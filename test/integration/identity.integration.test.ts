import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { buildApp } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import { decryptNotificationPayload } from "../../src/identity/token-crypto.js";
import { totpCodeForStep } from "../../src/identity/totp.js";

const databaseUrl = process.env.PHOENIX_DATABASE_URL;
const notificationKey = process.env.PHOENIX_IDENTITY_NOTIFICATION_KEY;
const mfaKey = process.env.PHOENIX_IDENTITY_MFA_KEY;

function nextTotpCode(secret: string): string {
  return totpCodeForStep(secret, Math.floor(Date.now() / 1000 / 30) + 1);
}

test("Phase B verification, TOTP, recovery codes, sessions, and audit flow", { skip: !databaseUrl || !notificationKey || !mfaKey }, async () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  await pool.query(`truncate
    identity_session_assurance,
    identity_mfa_transactions,
    identity_recovery_codes,
    identity_totp_factors,
    identity_totp_enrollments,
    identity_passkeys,
    identity_webauthn_challenges,
    identity_rate_limits,
    identity_security_events,
    identity_notification_outbox,
    identity_action_tokens,
    identity_sessions,
    identity_users cascade`);

  const migrationCount = await pool.query<{ count: string }>("select count(*)::text count from phoenix_schema_migrations");
  assert.equal(Number(migrationCount.rows[0]?.count ?? 0), 4);

  const operationsToken = Buffer.alloc(32, 9).toString("base64url");
  const app = await buildApp(loadConfig({
    ...process.env,
    PHOENIX_ENV: "test",
    PHOENIX_LOG_LEVEL: "error",
    PHOENIX_DATABASE_REQUIRED: "true",
    PHOENIX_DATABASE_URL: databaseUrl,
    PHOENIX_DOCUMENTATION_ENABLED: "false",
    PHOENIX_REQUIRE_TLS: "false",
    PHOENIX_IDENTITY_PASSWORD_BREACH_MODE: "disabled",
    PHOENIX_IDENTITY_WEBAUTHN_RP_ID: "localhost",
    PHOENIX_IDENTITY_WEBAUTHN_ORIGINS: "http://localhost:3000",
    PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS: "20",
    PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS: "30",
    PHOENIX_IDENTITY_ACTION_REQUEST_MAX_ATTEMPTS: "20",
    PHOENIX_IDENTITY_ACTION_CONFIRM_MAX_ATTEMPTS: "30",
    PHOENIX_OPERATIONS_ENABLED: "true",
    PHOENIX_OPERATIONS_TOKEN: operationsToken,
  }));

  const password = "a unique secure password 2026";
  const nextPassword = "another unique secure phrase 2026";

  const registration = await app.inject({ method: "POST", url: "/v1/identity/register", payload: { email: "identity@example.com", displayName: "Identity User", password } });
  assert.equal(registration.statusCode, 202);
  assert.deepEqual(registration.json(), { accepted: true });

  const duplicate = await app.inject({ method: "POST", url: "/v1/identity/register", payload: { email: "IDENTITY@example.com", displayName: "Other", password } });
  assert.equal(duplicate.statusCode, 202);

  const beforeVerification = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  assert.equal(beforeVerification.statusCode, 403);

  const verificationRow = await pool.query<{ ciphertext: string; iv: string; auth_tag: string }>("select ciphertext,iv,auth_tag from identity_notification_outbox where kind='email_verification' order by created_at desc limit 1");
  const verificationPayload = decryptNotificationPayload<{ token: string }>({ ciphertext: verificationRow.rows[0]!.ciphertext, iv: verificationRow.rows[0]!.iv, authTag: verificationRow.rows[0]!.auth_tag }, notificationKey!);
  const verified = await app.inject({ method: "POST", url: "/v1/identity/email-verification/confirm", payload: { token: verificationPayload.token } });
  assert.equal(verified.statusCode, 200);
  const bootstrapToken = verified.json().sessionToken as string;

  const reusedVerification = await app.inject({ method: "POST", url: "/v1/identity/email-verification/confirm", payload: { token: verificationPayload.token } });
  assert.equal(reusedVerification.statusCode, 400);

  const enrollment = await app.inject({ method: "POST", url: "/v1/identity/mfa/totp/enrollment/start", headers: { authorization: `Bearer ${bootstrapToken}` } });
  assert.equal(enrollment.statusCode, 200);
  const enrollmentBody = enrollment.json() as { enrollmentId: string; secret: string; otpauthUri: string };
  assert.match(enrollmentBody.otpauthUri, /^otpauth:\/\/totp\//u);
  const enrollmentCode = totpCodeForStep(enrollmentBody.secret, Math.floor(Date.now() / 1000 / 30));

  const enabled = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/totp/enrollment/confirm",
    headers: { authorization: `Bearer ${bootstrapToken}` },
    payload: { enrollmentId: enrollmentBody.enrollmentId, code: enrollmentCode }
  });
  assert.equal(enabled.statusCode, 200);
  const recoveryCodes = enabled.json().recoveryCodes as string[];
  assert.equal(recoveryCodes.length, 10);
  assert.equal(new Set(recoveryCodes).size, 10);

  const status = await app.inject({ method: "GET", url: "/v1/identity/mfa/status", headers: { authorization: `Bearer ${bootstrapToken}` } });
  assert.equal(status.statusCode, 200);
  assert.deepEqual(status.json(), { totpEnabled: true, recoveryCodesRemaining: 10, passkeys: 0 });

  const registrationOptions = await app.inject({
    method: "POST",
    url: "/v1/identity/passkeys/registration/options",
    headers: { authorization: `Bearer ${bootstrapToken}` },
    payload: { label: "Primary passkey" }
  });
  assert.equal(registrationOptions.statusCode, 200);
  assert.equal(registrationOptions.json().options.authenticatorSelection.residentKey, "required");
  assert.equal(registrationOptions.json().options.authenticatorSelection.userVerification, "required");

  await app.inject({ method: "POST", url: "/v1/identity/logout", headers: { authorization: `Bearer ${bootstrapToken}` } });
  const passwordLogin = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  assert.equal(passwordLogin.statusCode, 200);
  assert.equal(passwordLogin.json().mfaRequired, true);
  const firstTransaction = passwordLogin.json().transactionToken as string;
  const freshTotp = nextTotpCode(enrollmentBody.secret);

  const totpLogin = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/complete",
    payload: { transactionToken: firstTransaction, method: "totp", code: freshTotp }
  });
  assert.equal(totpLogin.statusCode, 200);
  const totpSession = totpLogin.json().sessionToken as string;

  const replayLogin = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  const replay = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/complete",
    payload: { transactionToken: replayLogin.json().transactionToken, method: "totp", code: freshTotp }
  });
  assert.equal(replay.statusCode, 401);

  const recoveryLogin = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  const recovered = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/complete",
    payload: { transactionToken: recoveryLogin.json().transactionToken, method: "recovery_code", code: recoveryCodes[0] }
  });
  assert.equal(recovered.statusCode, 200);
  const recoverySession = recovered.json().sessionToken as string;

  const reusedRecoveryLogin = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  const reusedRecovery = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/complete",
    payload: { transactionToken: reusedRecoveryLogin.json().transactionToken, method: "recovery_code", code: recoveryCodes[0] }
  });
  assert.equal(reusedRecovery.statusCode, 401);

  const resetRequest = await app.inject({ method: "POST", url: "/v1/identity/password-reset/request", payload: { email: "identity@example.com" } });
  assert.equal(resetRequest.statusCode, 202);
  const resetRow = await pool.query<{ ciphertext: string; iv: string; auth_tag: string }>("select ciphertext,iv,auth_tag from identity_notification_outbox where kind='password_reset' order by created_at desc limit 1");
  const resetPayload = decryptNotificationPayload<{ token: string }>({ ciphertext: resetRow.rows[0]!.ciphertext, iv: resetRow.rows[0]!.iv, authTag: resetRow.rows[0]!.auth_tag }, notificationKey!);
  const reset = await app.inject({ method: "POST", url: "/v1/identity/password-reset/confirm", payload: { token: resetPayload.token, newPassword: nextPassword } });
  assert.equal(reset.statusCode, 204);

  for (const token of [totpSession, recoverySession]) {
    const invalidated = await app.inject({ method: "GET", url: "/v1/identity/me", headers: { authorization: `Bearer ${token}` } });
    assert.equal(invalidated.statusCode, 401);
  }

  const oldPassword = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password } });
  assert.equal(oldPassword.statusCode, 401);
  const newPasswordLogin = await app.inject({ method: "POST", url: "/v1/identity/login", payload: { email: "identity@example.com", password: nextPassword } });
  assert.equal(newPasswordLogin.json().mfaRequired, true);
  const postReset = await app.inject({
    method: "POST",
    url: "/v1/identity/mfa/complete",
    payload: { transactionToken: newPasswordLogin.json().transactionToken, method: "recovery_code", code: recoveryCodes[1] }
  });
  assert.equal(postReset.statusCode, 200);

  const remaining = await app.inject({ method: "GET", url: "/v1/identity/mfa/status", headers: { authorization: `Bearer ${postReset.json().sessionToken}` } });
  assert.equal(remaining.statusCode, 200);
  assert.equal(remaining.json().recoveryCodesRemaining, 8);

  const operationsUnauthorized = await app.inject({ method: "GET", url: "/v1/operations/identity/health" });
  assert.equal(operationsUnauthorized.statusCode, 401);

  const operationsHealth = await app.inject({
    method: "GET",
    url: "/v1/operations/identity/health",
    headers: { authorization: `Bearer ${operationsToken}` }
  });
  assert.equal(operationsHealth.statusCode, 200);
  assert.equal(operationsHealth.json().status, "healthy");
  assert.equal(operationsHealth.json().migrationCount, 4);

  const operationsMetrics = await app.inject({
    method: "GET",
    url: "/v1/operations/identity/metrics",
    headers: { authorization: `Bearer ${operationsToken}` }
  });
  assert.equal(operationsMetrics.statusCode, 200);
  assert.match(operationsMetrics.headers["content-type"] ?? "", /^text\/plain/u);
  assert.match(operationsMetrics.body, /phoenix_identity_operational_health 1/u);
  assert.ok(!operationsMetrics.body.includes("identity@example.com"));

  const passkeyHarness = await app.inject({ method: "GET", url: "/passkey-validation/" });
  assert.equal(passkeyHarness.statusCode, 200);
  assert.match(passkeyHarness.body, /Phoenix Passkey Validation/u);
  assert.match(passkeyHarness.headers["content-security-policy"] ?? "", /default-src 'none'/u);
  assert.equal(passkeyHarness.headers["cache-control"], "no-store");

  const events = await pool.query<{ count: string }>("select count(*)::text count from identity_security_events");
  assert.ok(Number(events.rows[0]?.count ?? 0) >= 14);
  assert.ok(!verificationRow.rows[0]!.ciphertext.includes(verificationPayload.token));

  const schema = app.swagger();
  for (const path of [
    "/v1/identity/mfa/complete",
    "/v1/identity/mfa/status",
    "/v1/identity/mfa/totp/enrollment/start",
    "/v1/identity/mfa/totp/enrollment/confirm",
    "/v1/identity/mfa/recovery-codes/regenerate",
    "/v1/identity/mfa/totp/disable",
    "/v1/identity/passkeys/registration/options",
    "/v1/identity/passkeys/registration/verify",
    "/v1/identity/passkeys/authentication/options",
    "/v1/identity/passkeys/authentication/verify",
    "/v1/identity/passkeys",
    "/v1/operations/identity/health",
    "/v1/operations/identity/metrics"
  ]) assert.ok(schema.paths?.[path], `missing OpenAPI path ${path}`);

  await app.close();
  await pool.end();
});
