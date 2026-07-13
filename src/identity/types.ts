export type UserRecord = Readonly<{
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  status: "active" | "disabled";
  createdAt: string;
  updatedAt: string;
}>;

export type SessionRecord = Readonly<{
  id: string;
  userId: string;
  tokenHash: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
}>;

export type PublicUser = Readonly<{
  id: string;
  email: string;
  displayName: string;
  status: "active" | "disabled";
  createdAt: string;
}>;
