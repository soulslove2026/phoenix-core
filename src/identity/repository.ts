import type { Pool } from "pg";
import type { SessionRecord, UserRecord } from "./types.js";

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

export class PostgresIdentityRepository implements IdentityRepository {
  constructor(private readonly pool: Pool) {}

  async createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord> {
    const result = await this.pool.query(
      `insert into identity_users (id, email, display_name, password_hash)
       values ($1, $2, $3, $4)
       returning *`,
      [input.id, input.email, input.displayName, input.passwordHash]
    );
    return rowToUser(result.rows[0]);
  }

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const result = await this.pool.query("select * from identity_users where email = $1", [email]);
    return result.rows[0] ? rowToUser(result.rows[0]) : null;
  }

  async findUserById(id: string): Promise<UserRecord | null> {
    const result = await this.pool.query("select * from identity_users where id = $1", [id]);
    return result.rows[0] ? rowToUser(result.rows[0]) : null;
  }

  async createSession(input: { id: string; userId: string; tokenHash: string; expiresAt: string }): Promise<SessionRecord> {
    const result = await this.pool.query(
      `insert into identity_sessions (id, user_id, token_hash, expires_at)
       values ($1, $2, $3, $4)
       returning *`,
      [input.id, input.userId, input.tokenHash, input.expiresAt]
    );
    return rowToSession(result.rows[0]);
  }

  async findActiveSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const result = await this.pool.query(
      `select * from identity_sessions
       where token_hash = $1 and revoked_at is null and expires_at > now()`,
      [tokenHash]
    );
    return result.rows[0] ? rowToSession(result.rows[0]) : null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    await this.pool.query(
      "update identity_sessions set revoked_at = now() where token_hash = $1 and revoked_at is null",
      [tokenHash]
    );
  }
}
