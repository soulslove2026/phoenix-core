import { randomBytes, randomUUID } from "node:crypto";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { normalizeAndValidateEmail, EmailValidationError } from "./email.js";
import { passwordHasher, validatePassword, type PasswordHasher } from "./password.js";
import { PasswordBreachServiceUnavailableError, noOpPasswordBreachChecker, type PasswordBreachChecker } from "./password-breach.js";
import { PasskeyManager } from "./passkeys.js";
import type { PhaseBIdentityRepository } from "./phase-b-repository.js";
import type { PublicPasskey, SessionAssuranceMethod, SessionAssuranceRecord } from "./phase-b-types.js";
import { buildTotpUri, generateTotpSecret, verifyTotpCode } from "./totp.js";
import { createOpaqueToken, decryptMfaPayload, encryptMfaPayload, encryptNotificationPayload, hashOpaqueToken } from "./token-crypto.js";
import { IdentityRepositoryConflictError, type IdentityRepository, type SessionCreateInput } from "./repository.js";
import type { PublicSession, PublicUser, SecurityContext, SessionRecord, UserRecord } from "./types.js";

export class IdentityError extends Error {
  constructor(public readonly code: string, public readonly statusCode: number) { super(code); }
}

export type PasswordLoginResult =
  | Readonly<{ user: PublicUser; sessionToken: string; mfaRequired?: false }>
  | Readonly<{ mfaRequired: true; transactionToken: string; methods: ("totp" | "recovery_code")[] }>;

export type IdentityServiceOptions = Readonly<{
  sessionAbsoluteTtlSeconds: number;
  sessionIdleTtlSeconds: number;
  verificationTtlSeconds: number;
  passwordResetTtlSeconds: number;
  tokenPepper: string;
  notificationKey: string;
  passwords?: PasswordHasher;
  phaseB?: Readonly<{
    repository: PhaseBIdentityRepository;
    passkeys: PasskeyManager;
    passwordBreach?: PasswordBreachChecker;
    mfaKey: string;
    recentAuthenticationSeconds: number;
    mfaTransactionTtlSeconds: number;
    mfaMaxAttempts: number;
    totpEnrollmentTtlSeconds: number;
    totpIssuer: string;
    webauthnChallengeTtlSeconds: number;
  }>;
}>;

export class IdentityService {
  private readonly passwords: PasswordHasher;
  private readonly breach: PasswordBreachChecker;
  constructor(private readonly repository: IdentityRepository, private readonly options: IdentityServiceOptions) {
    this.passwords = options.passwords ?? passwordHasher;
    this.breach = options.phaseB?.passwordBreach ?? noOpPasswordBreachChecker;
    if (options.sessionIdleTtlSeconds > options.sessionAbsoluteTtlSeconds) throw new Error("idle TTL exceeds absolute TTL");
  }

  async register(input: { email: string; displayName: string; password: string }, context: SecurityContext): Promise<void> {
    let email: string;
    try { email = normalizeAndValidateEmail(input.email); }
    catch (error) { if (error instanceof EmailValidationError) throw new IdentityError("registration_invalid", 400); throw error; }
    const displayName = input.displayName.trim();
    if (displayName.length < 2 || displayName.length > 80) throw new IdentityError("registration_invalid", 400);
    const passwordHash = await this.securePasswordHash(input.password, { email, displayName }, "registration_invalid");
    let user = await this.repository.findUserByEmail(email);
    if (!user) {
      try { user = await this.repository.createUser({ id: randomUUID(), email, displayName, passwordHash }); }
      catch (error) { if (error instanceof IdentityRepositoryConflictError) user = await this.repository.findUserByEmail(email); else throw error; }
    }
    if (user && !user.emailVerifiedAt && user.status === "active") await this.issueAction(user, "verify_email", this.options.verificationTtlSeconds, "email_verification");
    await this.event("identity.registration_requested", "accepted", context, user?.id, email);
  }

  async requestEmailVerification(emailInput: string, context: SecurityContext): Promise<void> {
    const email = this.safeEmail(emailInput); const user = email ? await this.repository.findUserByEmail(email) : null;
    if (user && !user.emailVerifiedAt && user.status === "active") await this.issueAction(user, "verify_email", this.options.verificationTtlSeconds, "email_verification");
    await this.event("identity.email_verification_requested", "accepted", context, user?.id, email ?? emailInput);
  }

  async confirmEmailVerification(token: string, context: SecurityContext): Promise<{ user: PublicUser; sessionToken: string }> {
    const user = await this.repository.verifyEmailWithToken(hashOpaqueToken(token, this.options.tokenPepper));
    if (!user || user.status !== "active") throw new IdentityError("verification_token_invalid", 400);
    const session = await this.issueSession(user, context, "email_verification", 1);
    await this.event("identity.email_verified", "success", context, user.id);
    return { user: toPublicUser(user), sessionToken: session.token };
  }

  async login(input: { email: string; password: string }, context: SecurityContext): Promise<PasswordLoginResult> {
    const email = this.safeEmail(input.email); const user = email ? await this.repository.findUserByEmail(email) : null;
    const verification = user ? await this.passwords.verify(input.password, user.passwordHash) : await this.passwords.verify(input.password, DUMMY_HASH);
    if (!user || user.status !== "active" || !verification.valid) { await this.event("identity.login", "denied", context, user?.id, email ?? input.email); throw new IdentityError("credentials_invalid", 401); }
    if (!user.emailVerifiedAt) { await this.event("identity.login_unverified", "denied", context, user.id, user.email); throw new IdentityError("email_verification_required", 403); }
    if (verification.needsRehash) { const upgraded = await this.passwords.hash(input.password, { email: user.email, displayName: user.displayName }); await this.repository.upgradePasswordHash(user.id, upgraded); }

    if (this.options.phaseB && await this.options.phaseB.repository.hasActiveTotpFactor(user.id)) {
      const transactionToken = createOpaqueToken("phx_m");
      await this.options.phaseB.repository.createMfaTransaction({
        id: randomUUID(), userId: user.id, tokenHash: hashOpaqueToken(transactionToken, this.options.tokenPepper),
        expiresAt: new Date(Date.now() + this.options.phaseB.mfaTransactionTtlSeconds * 1000).toISOString(),
        maxAttempts: this.options.phaseB.mfaMaxAttempts, ipHash: context.ipHash, userAgentHash: context.userAgentHash
      });
      await this.event("identity.mfa_challenge_issued", "accepted", context, user.id);
      return { mfaRequired: true, transactionToken, methods: ["totp", "recovery_code"] };
    }

    const session = await this.issueSession(user, context, "password", 1);
    await this.event("identity.login", "success", context, user.id);
    return { user: toPublicUser(user), sessionToken: session.token };
  }

  async completeMfa(input: { transactionToken: string; method: "totp" | "recovery_code"; code: string }, context: SecurityContext): Promise<{ user: PublicUser; sessionToken: string }> {
    const phaseB = this.requirePhaseB();
    const transaction = await phaseB.repository.findMfaTransaction(hashOpaqueToken(input.transactionToken, this.options.tokenPepper));
    if (!transaction || transaction.ipHash !== context.ipHash || transaction.userAgentHash !== context.userAgentHash) throw new IdentityError("mfa_transaction_invalid", 401);
    const user = await this.repository.findUserById(transaction.userId);
    if (!user || user.status !== "active" || !user.emailVerifiedAt) throw new IdentityError("mfa_transaction_invalid", 401);

    let method: SessionAssuranceMethod;
    if (input.method === "totp") {
      const factor = await phaseB.repository.findTotpFactor(user.id);
      if (!factor) return this.rejectMfa(transaction.id, context, user.id);
      const { secret } = decryptMfaPayload<{ secret: string }>({ ciphertext: factor.secretCiphertext, iv: factor.secretIv, authTag: factor.secretAuthTag }, phaseB.mfaKey, "totp");
      const step = verifyTotpCode(secret, input.code);
      if (step === null || !(await phaseB.repository.advanceTotpCounter(factor.id, step))) return this.rejectMfa(transaction.id, context, user.id);
      method = "password_totp";
    } else {
      const normalized = normalizeRecoveryCode(input.code);
      const consumed = await phaseB.repository.consumeRecoveryCode(user.id, hashOpaqueToken(`recovery:${normalized}`, this.options.tokenPepper));
      if (!consumed) return this.rejectMfa(transaction.id, context, user.id);
      method = "recovery_code";
    }

    if (!(await phaseB.repository.consumeMfaTransaction(transaction.id))) throw new IdentityError("mfa_transaction_invalid", 401);
    const session = await this.issueSession(user, context, method, 2);
    if (method === "recovery_code") await this.queueSecurityNotice(user, "recovery_code_used");
    await this.event("identity.mfa_completed", "success", context, user.id, undefined, { method });
    return { user: toPublicUser(user), sessionToken: session.token };
  }

  async requestPasswordReset(emailInput: string, context: SecurityContext): Promise<void> {
    const email = this.safeEmail(emailInput); const user = email ? await this.repository.findUserByEmail(email) : null;
    if (user && user.status === "active" && user.emailVerifiedAt) await this.issueAction(user, "password_reset", this.options.passwordResetTtlSeconds, "password_reset");
    await this.event("identity.password_reset_requested", "accepted", context, user?.id, email ?? emailInput);
  }

  async confirmPasswordReset(input: { token: string; newPassword: string }, context: SecurityContext): Promise<void> {
    const passwordHash = await this.securePasswordHash(input.newPassword, {}, "password_invalid");
    const userId = await this.repository.resetPasswordWithToken(hashOpaqueToken(input.token, this.options.tokenPepper), passwordHash);
    if (!userId) throw new IdentityError("reset_token_invalid", 400);
    const user = await this.repository.findUserById(userId);
    if (user) await this.queueSecurityNotice(user, "password_reset_completed");
    await this.event("identity.password_reset_completed", "success", context, userId);
  }

  async authenticate(token: string): Promise<{ user: PublicUser; session: SessionRecord }> {
    const session = await this.repository.findActiveSessionByTokenHash(hashOpaqueToken(token, this.options.tokenPepper));
    if (!session) throw new IdentityError("session_invalid", 401);
    const user = await this.repository.findUserById(session.userId);
    if (!user || user.status !== "active" || !user.emailVerifiedAt || user.authVersion !== session.authVersion) throw new IdentityError("session_invalid", 401);
    const idleExpiry = new Date(Math.min(Date.now() + this.options.sessionIdleTtlSeconds * 1000, new Date(session.expiresAt).getTime())).toISOString();
    await this.repository.touchSession(session.id, idleExpiry);
    return { user: toPublicUser(user), session };
  }

  async rotateSession(token: string, context: SecurityContext): Promise<string> {
    const authenticated = await this.authenticate(token); const nextToken = createOpaqueToken("phx_s"); const now = Date.now();
    if (new Date(authenticated.session.expiresAt).getTime() <= now + 5_000) throw new IdentityError("session_invalid", 401);
    const base = this.sessionInput(authenticated.user.id, authenticated.session.authVersion, nextToken, context, now, authenticated.session.id);
    const input: SessionCreateInput = { ...base, expiresAt: authenticated.session.expiresAt, idleExpiresAt: new Date(Math.min(now + this.options.sessionIdleTtlSeconds * 1000, new Date(authenticated.session.expiresAt).getTime())).toISOString() };
    const rotated = await this.repository.rotateSession(hashOpaqueToken(token, this.options.tokenPepper), input);
    if (!rotated) throw new IdentityError("session_invalid", 401);
    if (this.options.phaseB) {
      const assurance = await this.options.phaseB.repository.getSessionAssurance(authenticated.session.id);
      await this.options.phaseB.repository.setSessionAssurance({ sessionId: rotated.id, userId: authenticated.user.id, method: assurance?.method ?? "password", level: assurance?.level ?? 1, authenticatedAt: assurance?.authenticatedAt ?? authenticated.session.createdAt, ...(assurance?.authenticatorId ? { authenticatorId: assurance.authenticatorId } : {}) });
    }
    await this.event("identity.session_rotated", "success", context, authenticated.user.id);
    return nextToken;
  }

  async listSessions(token: string): Promise<PublicSession[]> { const auth = await this.authenticate(token); const sessions = await this.repository.listActiveSessions(auth.user.id); return sessions.map(session => toPublicSession(session, session.id === auth.session.id)); }
  async revokeSessionById(token: string, sessionId: string, context: SecurityContext): Promise<void> { const auth = await this.authenticate(token); await this.repository.revokeSessionById(auth.user.id, sessionId); await this.event("identity.session_revoked", "success", context, auth.user.id); }
  async logout(token: string, context: SecurityContext): Promise<void> { const hash = hashOpaqueToken(token, this.options.tokenPepper); const session = await this.repository.findActiveSessionByTokenHash(hash); await this.repository.revokeSession(hash); if (session) await this.event("identity.logout", "success", context, session.userId); }
  async logoutAll(token: string, context: SecurityContext): Promise<void> { const auth = await this.authenticate(token); await this.repository.revokeAllSessions(auth.user.id); await this.event("identity.logout_all", "success", context, auth.user.id); }

  async mfaStatus(token: string): Promise<{ totpEnabled: boolean; recoveryCodesRemaining: number; passkeys: number }> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB();
    const [totpEnabled, recoveryCodesRemaining, passkeys] = await Promise.all([phaseB.repository.hasActiveTotpFactor(auth.user.id), phaseB.repository.countRecoveryCodes(auth.user.id), phaseB.repository.listPasskeys(auth.user.id)]);
    return { totpEnabled, recoveryCodesRemaining, passkeys: passkeys.length };
  }

  async startTotpEnrollment(token: string, context: SecurityContext): Promise<{ enrollmentId: string; secret: string; otpauthUri: string; expiresAt: string }> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB();
    await this.requireRecentSensitiveAuth(auth, false);
    const user = await this.repository.findUserById(auth.user.id); if (!user) throw new IdentityError("session_invalid", 401);
    const secret = generateTotpSecret(); const enrollmentId = randomUUID(); const expiresAt = new Date(Date.now() + phaseB.totpEnrollmentTtlSeconds * 1000).toISOString();
    await phaseB.repository.createTotpEnrollment({ id: enrollmentId, userId: user.id, encrypted: encryptMfaPayload({ secret }, phaseB.mfaKey, "totp"), expiresAt, maxAttempts: phaseB.mfaMaxAttempts, ipHash: context.ipHash, userAgentHash: context.userAgentHash });
    await this.event("identity.totp_enrollment_started", "accepted", context, user.id);
    return { enrollmentId, secret, otpauthUri: buildTotpUri({ secret, issuer: phaseB.totpIssuer, accountName: user.email }), expiresAt };
  }

  async confirmTotpEnrollment(token: string, input: { enrollmentId: string; code: string }, context: SecurityContext): Promise<{ recoveryCodes: string[] }> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB();
    const enrollment = await phaseB.repository.findTotpEnrollment(input.enrollmentId, auth.user.id);
    if (!enrollment || enrollment.ipHash !== context.ipHash || enrollment.userAgentHash !== context.userAgentHash) throw new IdentityError("totp_enrollment_invalid", 400);
    const { secret } = decryptMfaPayload<{ secret: string }>({ ciphertext: enrollment.secretCiphertext, iv: enrollment.secretIv, authTag: enrollment.secretAuthTag }, phaseB.mfaKey, "totp");
    const enrollmentStep = verifyTotpCode(secret, input.code);
    if (enrollmentStep === null) { await phaseB.repository.incrementTotpEnrollmentAttempt(enrollment.id); throw new IdentityError("totp_code_invalid", 400); }
    const recoveryCodes = generateRecoveryCodes(10);
    const completed = await phaseB.repository.completeTotpEnrollment({ enrollmentId: enrollment.id, userId: auth.user.id, currentSessionId: auth.session.id, initialStep: enrollmentStep, recoveryCodeHashes: recoveryCodes.map(code=>hashOpaqueToken(`recovery:${normalizeRecoveryCode(code)}`, this.options.tokenPepper)) });
    if (!completed) throw new IdentityError("totp_enrollment_invalid", 400);
    const user = await this.repository.findUserById(auth.user.id); if (user) await this.queueSecurityNotice(user, "totp_enabled");
    await this.event("identity.totp_enabled", "success", context, auth.user.id);
    return { recoveryCodes };
  }

  async regenerateRecoveryCodes(token: string, code: string, context: SecurityContext): Promise<{ recoveryCodes: string[] }> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB(); await this.requireRecentSensitiveAuth(auth, true);
    await this.verifyCurrentTotp(auth.user.id, code);
    const recoveryCodes = generateRecoveryCodes(10);
    await phaseB.repository.replaceRecoveryCodes(auth.user.id, recoveryCodes.map(value=>hashOpaqueToken(`recovery:${normalizeRecoveryCode(value)}`, this.options.tokenPepper)));
    const user = await this.repository.findUserById(auth.user.id); if (user) await this.queueSecurityNotice(user, "recovery_codes_regenerated");
    await this.event("identity.recovery_codes_regenerated", "success", context, auth.user.id);
    return { recoveryCodes };
  }

  async disableTotp(token: string, code: string, context: SecurityContext): Promise<void> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB(); await this.requireRecentSensitiveAuth(auth, true);
    await this.verifyCurrentTotp(auth.user.id, code);
    if (!(await phaseB.repository.disableTotpAndRevokeSessions(auth.user.id))) throw new IdentityError("totp_not_enabled", 409);
    const user = await this.repository.findUserById(auth.user.id); if (user) await this.queueSecurityNotice(user, "totp_disabled");
    await this.event("identity.totp_disabled", "success", context, auth.user.id);
  }

  async beginPasskeyRegistration(token: string, label: string, context: SecurityContext) {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB(); await this.requireRecentSensitiveAuth(auth, false);
    const normalizedLabel = label.trim(); if (normalizedLabel.length < 1 || normalizedLabel.length > 64) throw new IdentityError("passkey_label_invalid", 400);
    const user = await this.repository.findUserById(auth.user.id); if (!user) throw new IdentityError("session_invalid", 401);
    const existing = await phaseB.repository.listPasskeys(user.id); const options = await phaseB.passkeys.registrationOptions(user, existing);
    const challengeId = randomUUID(); const expiresAt = new Date(Date.now() + phaseB.webauthnChallengeTtlSeconds * 1000).toISOString();
    await phaseB.repository.createWebAuthnChallenge({ id: challengeId, userId: user.id, purpose: "register", encrypted: encryptMfaPayload({ challenge: options.challenge, label: normalizedLabel }, phaseB.mfaKey, "webauthn"), expiresAt, ipHash: context.ipHash, userAgentHash: context.userAgentHash });
    return { challengeId, options, expiresAt };
  }

  async finishPasskeyRegistration(token: string, input: { challengeId: string; response: RegistrationResponseJSON }, context: SecurityContext): Promise<{ passkey: PublicPasskey }> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB();
    const challenge = await phaseB.repository.consumeWebAuthnChallenge(input.challengeId, "register");
    if (!challenge || challenge.userId !== auth.user.id || challenge.ipHash !== context.ipHash || challenge.userAgentHash !== context.userAgentHash) throw new IdentityError("passkey_challenge_invalid", 400);
    const data = decryptMfaPayload<{ challenge: string; label: string }>({ ciphertext: challenge.challengeCiphertext, iv: challenge.challengeIv, authTag: challenge.challengeAuthTag }, phaseB.mfaKey, "webauthn");
    let verification;
    try { verification = await phaseB.passkeys.verifyRegistration(input.response, data.challenge); }
    catch { throw new IdentityError("passkey_registration_invalid", 400); }
    if (!verification.verified) throw new IdentityError("passkey_registration_invalid", 400);
    const info = verification.registrationInfo;
    const id = randomUUID();
    await phaseB.repository.createPasskey({ id, userId: auth.user.id, credentialId: info.credential.id, webauthnUserId: auth.user.id, publicKey: info.credential.publicKey, counter: info.credential.counter, deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp, transports: info.credential.transports ?? [], label: data.label });
    await phaseB.repository.setSessionAssurance({ sessionId: auth.session.id, userId: auth.user.id, method: "passkey_step_up", level: 2, authenticatedAt: new Date().toISOString(), authenticatorId: id });
    const user = await this.repository.findUserById(auth.user.id); if (user) await this.queueSecurityNotice(user, "passkey_added");
    await this.event("identity.passkey_added", "success", context, auth.user.id);
    const saved = await phaseB.repository.findPasskeyByCredentialId(info.credential.id); if (!saved) throw new Error("passkey_insert_missing");
    return { passkey: toPublicPasskey(saved) };
  }

  async beginPasskeyAuthentication(context: SecurityContext) {
    const phaseB = this.requirePhaseB(); const options = await phaseB.passkeys.authenticationOptions(); const challengeId = randomUUID(); const expiresAt = new Date(Date.now() + phaseB.webauthnChallengeTtlSeconds * 1000).toISOString();
    await phaseB.repository.createWebAuthnChallenge({ id: challengeId, purpose: "authenticate", encrypted: encryptMfaPayload({ challenge: options.challenge }, phaseB.mfaKey, "webauthn"), expiresAt, ipHash: context.ipHash, userAgentHash: context.userAgentHash });
    return { challengeId, options, expiresAt };
  }

  async finishPasskeyAuthentication(input: { challengeId: string; response: AuthenticationResponseJSON }, context: SecurityContext): Promise<{ user: PublicUser; sessionToken: string }> {
    const phaseB = this.requirePhaseB(); const challenge = await phaseB.repository.consumeWebAuthnChallenge(input.challengeId, "authenticate");
    if (!challenge || challenge.ipHash !== context.ipHash || challenge.userAgentHash !== context.userAgentHash) throw new IdentityError("passkey_challenge_invalid", 400);
    const passkey = await phaseB.repository.findPasskeyByCredentialId(input.response.id); if (!passkey) throw new IdentityError("passkey_authentication_invalid", 401);
    const data = decryptMfaPayload<{ challenge: string }>({ ciphertext: challenge.challengeCiphertext, iv: challenge.challengeIv, authTag: challenge.challengeAuthTag }, phaseB.mfaKey, "webauthn");
    let verification;
    try { verification = await phaseB.passkeys.verifyAuthentication(input.response, data.challenge, passkey); }
    catch { throw new IdentityError("passkey_authentication_invalid", 401); }
    if (!verification.verified) throw new IdentityError("passkey_authentication_invalid", 401);
    const user = await this.repository.findUserById(passkey.userId);
    if (!user || user.status !== "active" || !user.emailVerifiedAt) throw new IdentityError("passkey_authentication_invalid", 401);
    await phaseB.repository.updatePasskeyAfterAuthentication(passkey.id, verification.authenticationInfo.newCounter, verification.authenticationInfo.credentialBackedUp);
    const session = await this.issueSession(user, context, "passkey", 2, passkey.id);
    await this.event("identity.passkey_login", "success", context, user.id);
    return { user: toPublicUser(user), sessionToken: session.token };
  }

  async listPasskeys(token: string): Promise<{ passkeys: PublicPasskey[] }> {
    const auth = await this.authenticate(token); const records = await this.requirePhaseB().repository.listPasskeys(auth.user.id); return { passkeys: records.map(toPublicPasskey) };
  }

  async deletePasskey(token: string, passkeyId: string, context: SecurityContext): Promise<void> {
    const auth = await this.authenticate(token); const phaseB = this.requirePhaseB(); const assurance = await this.requireRecentSensitiveAuth(auth, true);
    if (assurance.authenticatorId === passkeyId) throw new IdentityError("current_passkey_cannot_be_deleted", 409);
    if (!(await phaseB.repository.deletePasskey(auth.user.id, passkeyId))) throw new IdentityError("passkey_not_found", 404);
    const user = await this.repository.findUserById(auth.user.id); if (user) await this.queueSecurityNotice(user, "passkey_removed");
    await this.event("identity.passkey_removed", "success", context, auth.user.id);
  }

  private safeEmail(value: string): string | null { try { return normalizeAndValidateEmail(value); } catch { return null; } }
  private requirePhaseB() { if (!this.options.phaseB) throw new IdentityError("identity_phase_b_unavailable", 503); return this.options.phaseB; }

  private async securePasswordHash(password: string, context: { email?: string; displayName?: string }, publicError: string): Promise<string> {
    let normalized: string;
    try { normalized = validatePassword(password, context); }
    catch { throw new IdentityError(publicError, 400); }
    try {
      const result = await this.breach.check(normalized);
      if (result.compromised) throw new IdentityError("password_compromised", 400);
    } catch (error) {
      if (error instanceof IdentityError) throw error;
      if (error instanceof PasswordBreachServiceUnavailableError) throw new IdentityError("password_screening_unavailable", 503);
      throw error;
    }
    try { return await this.passwords.hash(normalized, context); }
    catch { throw new IdentityError(publicError, 400); }
  }

  private async rejectMfa(transactionId: string, context: SecurityContext, userId: string): Promise<never> {
    await this.requirePhaseB().repository.incrementMfaAttempt(transactionId);
    await this.event("identity.mfa_completed", "denied", context, userId);
    throw new IdentityError("mfa_code_invalid", 401);
  }

  private async verifyCurrentTotp(userId: string, code: string): Promise<void> {
    const phaseB = this.requirePhaseB(); const factor = await phaseB.repository.findTotpFactor(userId);
    if (!factor) throw new IdentityError("totp_not_enabled", 409);
    const { secret } = decryptMfaPayload<{ secret: string }>({ ciphertext: factor.secretCiphertext, iv: factor.secretIv, authTag: factor.secretAuthTag }, phaseB.mfaKey, "totp");
    const step = verifyTotpCode(secret, code);
    if (step === null || !(await phaseB.repository.advanceTotpCounter(factor.id, step))) throw new IdentityError("totp_code_invalid", 400);
  }

  private async requireRecentSensitiveAuth(auth: { user: PublicUser; session: SessionRecord }, requireLevelTwo: boolean): Promise<SessionAssuranceRecord> {
    const phaseB = this.requirePhaseB(); const assurance = await phaseB.repository.getSessionAssurance(auth.session.id);
    if (!assurance) throw new IdentityError("reauthentication_required", 403);
    const age = Date.now() - new Date(assurance.authenticatedAt).getTime();
    if (age < 0 || age > phaseB.recentAuthenticationSeconds * 1000) throw new IdentityError("reauthentication_required", 403);
    if (assurance.method === "recovery_code") throw new IdentityError("strong_reauthentication_required", 403);
    if (requireLevelTwo && assurance.level < 2) throw new IdentityError("strong_reauthentication_required", 403);
    if (!requireLevelTwo && await phaseB.repository.hasActiveTotpFactor(auth.user.id) && assurance.level < 2) throw new IdentityError("strong_reauthentication_required", 403);
    return assurance;
  }

  private async issueAction(user: UserRecord, purpose: "verify_email" | "password_reset", ttlSeconds: number, kind: "email_verification" | "password_reset"): Promise<void> {
    const token = createOpaqueToken(purpose === "verify_email" ? "phx_v" : "phx_r"); const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const encrypted = encryptNotificationPayload({ kind, recipient: user.email, token, expiresAt }, this.options.notificationKey);
    await this.repository.issueActionToken({ id: randomUUID(), userId: user.id, purpose, tokenHash: hashOpaqueToken(token, this.options.tokenPepper), expiresAt, notification: { id: randomUUID(), kind, ...encrypted } });
  }

  private async queueSecurityNotice(user: UserRecord, event: string): Promise<void> {
    if (!this.options.phaseB) return;
    const encrypted = encryptNotificationPayload({ kind: "security_notice", recipient: user.email, event, occurredAt: new Date().toISOString() }, this.options.notificationKey);
    await this.options.phaseB.repository.queueNotification({ id: randomUUID(), userId: user.id, kind: "security_notice", encrypted });
  }

  private async issueSession(user: UserRecord, context: SecurityContext, method: SessionAssuranceMethod, level: 1 | 2, authenticatorId?: string): Promise<{ token: string; record: SessionRecord }> {
    const token = createOpaqueToken("phx_s"); const now = Date.now(); const record = await this.repository.createSession(this.sessionInput(user.id, user.authVersion, token, context, now));
    if (this.options.phaseB) await this.options.phaseB.repository.setSessionAssurance({ sessionId: record.id, userId: user.id, method, level, authenticatedAt: new Date(now).toISOString(), ...(authenticatorId ? { authenticatorId } : {}) });
    return { token, record };
  }

  private sessionInput(userId: string, authVersion: number, token: string, context: SecurityContext, now: number, rotatedFromSessionId?: string): SessionCreateInput {
    return { id: randomUUID(), userId, tokenHash: hashOpaqueToken(token, this.options.tokenPepper), authVersion, userAgentHash: context.userAgentHash, ipHash: context.ipHash, idleExpiresAt: new Date(now + this.options.sessionIdleTtlSeconds * 1000).toISOString(), expiresAt: new Date(now + this.options.sessionAbsoluteTtlSeconds * 1000).toISOString(), ...(rotatedFromSessionId ? { rotatedFromSessionId } : {}) };
  }

  private async event(eventType: string, outcome: "success" | "denied" | "accepted", context: SecurityContext, userId?: string, subject?: string, extraMetadata?: Record<string, unknown>) {
    const subjectHash = subject ? hashOpaqueToken(`subject:${subject.toLowerCase()}`, this.options.tokenPepper) : undefined;
    await this.repository.recordSecurityEvent({ id: randomUUID(), ...(userId ? { userId } : {}), eventType, outcome, ...(subjectHash ? { subjectHash } : {}), metadata: { ipHash: context.ipHash, userAgentHash: context.userAgentHash, ...(extraMetadata ?? {}) } });
  }
}

function generateRecoveryCodes(count: number): string[] {
  return Array.from({ length: count }, () => {
    const raw = randomBytes(16).toString("base64url").replace(/[-_]/gu, "A").toUpperCase().slice(0, 20);
    return raw.match(/.{1,5}/gu)!.join("-");
  });
}
function normalizeRecoveryCode(code: string): string { return code.toUpperCase().replace(/[^A-Z0-9]/gu, ""); }

const DUMMY_HASH = "scrypt$v2$131072$8$1$cGhvZW5peC1kdW1teS1zYWx0$mvGDHRcN-MxKy8iKcSTDJ3dxl5enp_Aof3FDnhrrTDuNiGySukWU4iMO78beo6g6aT1nKUSDvKHcDnEpSQhcvA";
function toPublicUser(user: UserRecord): PublicUser { return { id: user.id, email: user.email, displayName: user.displayName, status: user.status, emailVerified: Boolean(user.emailVerifiedAt), createdAt: user.createdAt }; }
function toPublicSession(session: SessionRecord, current: boolean): PublicSession { return { id: session.id, current, createdAt: session.createdAt, lastSeenAt: session.lastSeenAt, idleExpiresAt: session.idleExpiresAt, expiresAt: session.expiresAt }; }
function toPublicPasskey(passkey: { id: string; label: string; deviceType: "singleDevice" | "multiDevice"; backedUp: boolean; transports: PublicPasskey["transports"]; createdAt: string; lastUsedAt: string | null }): PublicPasskey { return { id: passkey.id, label: passkey.label, deviceType: passkey.deviceType, backedUp: passkey.backedUp, transports: passkey.transports, createdAt: passkey.createdAt, lastUsedAt: passkey.lastUsedAt }; }
