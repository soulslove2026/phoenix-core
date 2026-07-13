export type UserRecord = Readonly<{
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  status: "active" | "disabled";
  emailVerifiedAt: string | null;
  passwordChangedAt: string;
  authVersion: number;
  createdAt: string;
  updatedAt: string;
}>;

export type SessionRecord = Readonly<{
  id: string;
  userId: string;
  tokenHash: string;
  authVersion: number;
  userAgentHash: string | null;
  ipHash: string | null;
  rotatedFromSessionId: string | null;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  expiresAt: string;
  revokedAt: string | null;
}>;

export type PublicUser = Readonly<{
  id: string;
  email: string;
  displayName: string;
  status: "active" | "disabled";
  emailVerified: boolean;
  createdAt: string;
}>;

export type PublicSession = Readonly<{
  id: string;
  current: boolean;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  expiresAt: string;
}>;

export type IdentityActionPurpose = "verify_email" | "password_reset";
export type IdentityNotificationKind = "email_verification" | "password_reset" | "security_notice";

export type EncryptedNotification = Readonly<{
  id: string;
  kind: IdentityNotificationKind;
  ciphertext: string;
  iv: string;
  authTag: string;
}>;

export type SecurityContext = Readonly<{
  ipHash: string;
  userAgentHash: string;
}>;
