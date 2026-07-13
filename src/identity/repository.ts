import type { Pool } from "pg";
import type { SessionRecord, UserRecord } from "./types.js";

export class IdentityRepositoryConflictError extends Error {
  constructor(public readonly conflict: "email") {
    super(`identity_${conflict}_conflict`);
  }
}

export interface IdentityRepository {
  createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord>;
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  createSession(input: { id: string; userId: string; tokenHash: string; expiresAt: string }): Promise<SessionRecord>;
  findActiveSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  revokeSession(tokenHash: string): Promise<void>;
}

function rowToUser(row: Record<string, unknown>): UserRecord {
  return {
    id: String(row.id),
    email: String(row.email),
    displayName: String(row.display_name),
    passwordHash: String(row.password_hash),
    status: row.status === "disabled" ? "disabled" : "active",
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString()
  };
}

function rowToSession(row: Record<string, unknown>): SessionRecord {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    tokenHash: String(row.token_hash),
    createdAt: new Date(String(row.created_at)).toISOString(),
    expiresAt: new Date(String(row.expires_at)).toISOString(),
    revokedAt: row.revoked_at ? new Date(String(row.revoked_at)).toISOString() : null
  };
}

function postgresError(error: unknown): { code?: string; constraint?: string } {
  if (typeof error !== "object" || error === null) return {};
  const candidate = error as { code?: unknown; constraint?: unknown };
  return {
    ...(typeof candidate.code === "string" ? { code: candidate.code } : {}),
    ...(typeof candidate.constraint === "string" ? { constraint: candidate.constraint } : {})
  };
}

export class PostgresIdentityRepository implements IdentityRepository {
  constructor(private readonly pool: Pool) {}

  async createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord> {
    try {
      const result = await this.pool.query(
        `insert into identity_users (id, email, display_name, password_hash)
         values ($1, $2, $3, $4)
         returning *`,
        [input.id, input.email, input.displayName, input.passwordHash]
      );
      const row = result.rows[0] as Record<string, unknown> | undefined;
      if (!row) throw new Error("identity_user_insert_returned_no_row");
      return rowToUser(row);
    } catch (error) {
      const details = postgresError(error);
      if (details.code === "23505" && details.constraint === "identity_users_email_unique") {
        throw new IdentityRepositoryConflictError("email");
      }
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const result = await this.pool.query("select * from identity_users where email = $1", [email]);
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? rowToUser(row) : null;
  }

  async findUserById(id: string): Promise<UserRecord | null> {
    const result = await this.pool.query("select * from identity_users where id = $1", [id]);
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? rowToUser(row) : null;
  }

  async createSession(input: { id: string; userId: string; tokenHash: string; expiresAt: string }): Promise<SessionRecord> {
    const result = await this.pool.query(
      `insert into identity_sessions (id, user_id, token_hash, expires_at)
       values ($1, $2, $3, $4)
       returning *`,
      [input.id, input.userId, input.tokenHash, input.expiresAt]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) throw new Error("identity_session_insert_returned_no_row");
    return rowToSession(row);
  }

  async findActiveSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const result = await this.pool.query(
      `select * from identity_sessions
       where token_hash = $1 and revoked_at is null and expires_at > now()`,
      [tokenHash]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? rowToSession(row) : null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    await this.pool.query(
      "update identity_sessions set revoked_at = now() where token_hash = $1 and revoked_at is null",
      [tokenHash]
    );
  }
}
