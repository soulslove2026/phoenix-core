import type { AuthenticatorTransportFuture } from "@simplewebauthn/server";

export type SessionAssuranceMethod =
  | "email_verification"
  | "password"
  | "password_totp"
  | "recovery_code"
  | "passkey"
  | "passkey_step_up";

export type SessionAssuranceRecord = Readonly<{
  sessionId: string;
  userId: string;
  method: SessionAssuranceMethod;
  level: 1 | 2;
  authenticatedAt: string;
  authenticatorId: string | null;
}>;

export type TotpFactorRecord = Readonly<{
  id: string;
  userId: string;
  secretCiphertext: string;
  secretIv: string;
  secretAuthTag: string;
  algorithm: "SHA1";
  digits: 6;
  periodSeconds: 30;
  lastUsedStep: number;
  enabledAt: string;
  disabledAt: string | null;
}>;

export type TotpEnrollmentRecord = Readonly<{
  id: string;
  userId: string;
  secretCiphertext: string;
  secretIv: string;
  secretAuthTag: string;
  expiresAt: string;
  attempts: number;
  maxAttempts: number;
  ipHash: string;
  userAgentHash: string;
}>;

export type MfaTransactionRecord = Readonly<{
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: string;
  attempts: number;
  maxAttempts: number;
  ipHash: string;
  userAgentHash: string;
}>;

export type PasskeyRecord = Readonly<{
  id: string;
  userId: string;
  credentialId: string;
  webauthnUserId: string;
  publicKey: Uint8Array;
  counter: number;
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  transports: AuthenticatorTransportFuture[];
  label: string;
  createdAt: string;
  lastUsedAt: string | null;
}>;

export type WebAuthnChallengeRecord = Readonly<{
  id: string;
  userId: string | null;
  purpose: "register" | "authenticate";
  challengeCiphertext: string;
  challengeIv: string;
  challengeAuthTag: string;
  expiresAt: string;
  ipHash: string;
  userAgentHash: string;
}>;

export type NotificationOutboxRecord = Readonly<{
  id: string;
  userId: string;
  kind: "email_verification" | "password_reset" | "security_notice";
  ciphertext: string;
  iv: string;
  authTag: string;
  attempts: number;
  lockToken: string;
}>;

export type PublicPasskey = Readonly<{
  id: string;
  label: string;
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  transports: AuthenticatorTransportFuture[];
  createdAt: string;
  lastUsedAt: string | null;
}>;
