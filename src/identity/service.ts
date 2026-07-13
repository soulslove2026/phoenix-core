import { randomUUID } from "node:crypto";
import { normalizeAndValidateEmail, EmailValidationError } from "./email.js";
import { createSessionToken, hashSessionToken } from "./session-token.js";
import { hashPassword, verifyPassword } from "./password.js";
import {
  IdentityRepositoryConflictError,
  type IdentityRepository
} from "./repository.js";
import type { PublicUser, UserRecord } from "./types.js";

export class IdentityError extends Error {
  constructor(public readonly code: string, public readonly statusCode: number) {
    super(code);
  }
}

export class IdentityService {
  constructor(
    private readonly repository: IdentityRepository,
    private readonly options: Readonly<{ sessionTtlSeconds: number }> = { sessionTtlSeconds: 2_592_000 }
  ) {
    if (!Number.isInteger(options.sessionTtlSeconds) || options.sessionTtlSeconds <= 0) {
      throw new Error("sessionTtlSeconds must be a positive integer");
    }
  }

  async register(input: { email: string; displayName: string; password: string }): Promise<{ user: PublicUser; sessionToken: string }> {
    let email: string;
    try {
      email = normalizeAndValidateEmail(input.email);
    } catch (error) {
      if (error instanceof EmailValidationError) throw new IdentityError("email_invalid", 400);
      throw error;
    }

    const displayName = input.displayName.trim();
    if (displayName.length < 2 || displayName.length > 80) {
      throw new IdentityError("display_name_invalid", 400);
    }
    if (await this.repository.findUserByEmail(email)) {
      throw new IdentityError("registration_unavailable", 409);
    }

    let passwordHash: string;
    try {
      passwordHash = await hashPassword(input.password);
    } catch {
      throw new IdentityError("password_invalid", 400);
    }

    let user: UserRecord;
    try {
      user = await this.repository.createUser({
        id: randomUUID(),
        email,
        displayName,
        passwordHash
      });
    } catch (error) {
      if (error instanceof IdentityRepositoryConflictError && error.conflict === "email") {
        throw new IdentityError("registration_unavailable", 409);
      }
      throw error;
    }

    const { token, tokenHash } = createSessionToken();
    await this.repository.createSession({
      id: randomUUID(),
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + this.options.sessionTtlSeconds * 1_000).toISOString()
    });
    return { user: toPublicUser(user), sessionToken: token };
  }

  async login(input: { email: string; password: string }): Promise<{ user: PublicUser; sessionToken: string }> {
    let email: string;
    try {
      email = normalizeAndValidateEmail(input.email);
    } catch {
      throw new IdentityError("credentials_invalid", 401);
    }

    const user = await this.repository.findUserByEmail(email);
    if (!user || user.status !== "active" || !(await verifyPassword(input.password, user.passwordHash))) {
      throw new IdentityError("credentials_invalid", 401);
    }

    const { token, tokenHash } = createSessionToken();
    await this.repository.createSession({
      id: randomUUID(),
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + this.options.sessionTtlSeconds * 1_000).toISOString()
    });
    return { user: toPublicUser(user), sessionToken: token };
  }

  async authenticate(token: string): Promise<PublicUser> {
    const session = await this.repository.findActiveSessionByTokenHash(hashSessionToken(token));
    if (!session) throw new IdentityError("session_invalid", 401);
    const user = await this.repository.findUserById(session.userId);
    if (!user || user.status !== "active") throw new IdentityError("session_invalid", 401);
    return toPublicUser(user);
  }

  async logout(token: string): Promise<void> {
    await this.repository.revokeSession(hashSessionToken(token));
  }
}

function toPublicUser(user: { id: string; email: string; displayName: string; status: "active" | "disabled"; createdAt: string }): PublicUser {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    status: user.status,
    createdAt: user.createdAt
  };
}
