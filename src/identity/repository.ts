import type { Pool, PoolClient } from "pg";
import type { EncryptedNotification, IdentityActionPurpose, SessionRecord, UserRecord } from "./types.js";

export class IdentityRepositoryConflictError extends Error {
  constructor(public readonly conflict: "email") { super(`identity_${conflict}_conflict`); }
}

export type SessionCreateInput = Readonly<{
  id: string; userId: string; tokenHash: string; authVersion: number;
  userAgentHash: string; ipHash: string; idleExpiresAt: string; expiresAt: string;
  rotatedFromSessionId?: string;
}>;

export interface IdentityRepository {
  createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord>;
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  upgradePasswordHash(userId: string, passwordHash: string): Promise<void>;
  issueActionToken(input: { id: string; userId: string; purpose: IdentityActionPurpose; tokenHash: string; expiresAt: string; notification: EncryptedNotification }): Promise<void>;
  verifyEmailWithToken(tokenHash: string): Promise<UserRecord | null>;
  resetPasswordWithToken(tokenHash: string, passwordHash: string): Promise<string | null>;
  createSession(input: SessionCreateInput): Promise<SessionRecord>;
  findActiveSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  touchSession(id: string, idleExpiresAt: string): Promise<void>;
  rotateSession(oldTokenHash: string, input: SessionCreateInput): Promise<SessionRecord | null>;
  listActiveSessions(userId: string): Promise<SessionRecord[]>;
  revokeSession(tokenHash: string): Promise<void>;
  revokeSessionById(userId: string, sessionId: string): Promise<void>;
  revokeAllSessions(userId: string): Promise<void>;
  recordSecurityEvent(input: { id: string; userId?: string; eventType: string; outcome: "success" | "denied" | "accepted"; subjectHash?: string; metadata?: Record<string, unknown> }): Promise<void>;
}

function rowToUser(row: Record<string, unknown>): UserRecord {
  return {
    id: String(row.id), email: String(row.email), displayName: String(row.display_name), passwordHash: String(row.password_hash),
    status: row.status === "disabled" ? "disabled" : "active",
    emailVerifiedAt: row.email_verified_at ? new Date(String(row.email_verified_at)).toISOString() : null,
    passwordChangedAt: new Date(String(row.password_changed_at)).toISOString(), authVersion: Number(row.auth_version),
    createdAt: new Date(String(row.created_at)).toISOString(), updatedAt: new Date(String(row.updated_at)).toISOString()
  };
}

function rowToSession(row: Record<string, unknown>): SessionRecord {
  return {
    id: String(row.id), userId: String(row.user_id), tokenHash: String(row.token_hash), authVersion: Number(row.auth_version),
    userAgentHash: row.user_agent_hash ? String(row.user_agent_hash) : null, ipHash: row.ip_hash ? String(row.ip_hash) : null,
    rotatedFromSessionId: row.rotated_from_session_id ? String(row.rotated_from_session_id) : null,
    createdAt: new Date(String(row.created_at)).toISOString(), lastSeenAt: new Date(String(row.last_seen_at)).toISOString(),
    idleExpiresAt: new Date(String(row.idle_expires_at)).toISOString(), expiresAt: new Date(String(row.expires_at)).toISOString(),
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

async function transaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try { await client.query("begin"); const result = await operation(client); await client.query("commit"); return result; }
  catch (error) { await client.query("rollback"); throw error; }
  finally { client.release(); }
}

export class PostgresIdentityRepository implements IdentityRepository {
  constructor(private readonly pool: Pool) {}

  async createUser(input: { id: string; email: string; displayName: string; passwordHash: string }): Promise<UserRecord> {
    try {
      const result = await this.pool.query(`insert into identity_users (id,email,display_name,password_hash) values ($1,$2,$3,$4) returning *`, [input.id,input.email,input.displayName,input.passwordHash]);
      const row = result.rows[0] as Record<string, unknown> | undefined; if (!row) throw new Error("identity_user_insert_returned_no_row"); return rowToUser(row);
    } catch (error) {
      const details = postgresError(error);
      if (details.code === "23505" && details.constraint === "identity_users_email_unique") throw new IdentityRepositoryConflictError("email");
      throw error;
    }
  }
  async findUserByEmail(email: string) { const r=await this.pool.query("select * from identity_users where email=$1",[email]); const row=r.rows[0] as Record<string,unknown>|undefined; return row?rowToUser(row):null; }
  async findUserById(id: string) { const r=await this.pool.query("select * from identity_users where id=$1",[id]); const row=r.rows[0] as Record<string,unknown>|undefined; return row?rowToUser(row):null; }
  async upgradePasswordHash(userId: string, passwordHash: string) { await this.pool.query("update identity_users set password_hash=$2 where id=$1",[userId,passwordHash]); }

  async issueActionToken(input: { id: string; userId: string; purpose: IdentityActionPurpose; tokenHash: string; expiresAt: string; notification: EncryptedNotification }): Promise<void> {
    await transaction(this.pool, async (client) => {
      await client.query("select pg_advisory_xact_lock(hashtext($1))", [`identity_action:${input.userId}:${input.purpose}`]);
      await client.query("update identity_action_tokens set consumed_at=now() where user_id=$1 and purpose=$2 and consumed_at is null",[input.userId,input.purpose]);
      await client.query(`insert into identity_action_tokens (id,user_id,purpose,token_hash,expires_at) values ($1,$2,$3,$4,$5)`,[input.id,input.userId,input.purpose,input.tokenHash,input.expiresAt]);
      await client.query(`insert into identity_notification_outbox (id,user_id,kind,ciphertext,iv,auth_tag) values ($1,$2,$3,$4,$5,$6)`,[input.notification.id,input.userId,input.notification.kind,input.notification.ciphertext,input.notification.iv,input.notification.authTag]);
    });
  }

  async verifyEmailWithToken(tokenHash: string): Promise<UserRecord | null> {
    return transaction(this.pool, async (client) => {
      const token = await client.query<{id:string;user_id:string}>(`select id,user_id from identity_action_tokens where token_hash=$1 and purpose='verify_email' and consumed_at is null and expires_at>now() for update`,[tokenHash]);
      const row=token.rows[0]; if(!row) return null;
      await client.query("update identity_action_tokens set consumed_at=now() where id=$1",[row.id]);
      const updated=await client.query(`update identity_users set email_verified_at=coalesce(email_verified_at,now()) where id=$1 returning *`,[row.user_id]);
      const userRow=updated.rows[0] as Record<string,unknown>|undefined; return userRow?rowToUser(userRow):null;
    });
  }

  async resetPasswordWithToken(tokenHash: string, passwordHash: string): Promise<string | null> {
    return transaction(this.pool, async (client) => {
      const token=await client.query<{id:string;user_id:string}>(`select id,user_id from identity_action_tokens where token_hash=$1 and purpose='password_reset' and consumed_at is null and expires_at>now() for update`,[tokenHash]);
      const row=token.rows[0]; if(!row) return null;
      await client.query("update identity_action_tokens set consumed_at=now() where user_id=$1 and consumed_at is null",[row.user_id]);
      await client.query("update identity_users set password_hash=$2,password_changed_at=now(),auth_version=auth_version+1 where id=$1",[row.user_id,passwordHash]);
      await client.query("update identity_sessions set revoked_at=coalesce(revoked_at,now()) where user_id=$1",[row.user_id]);
      return row.user_id;
    });
  }

  async createSession(input: SessionCreateInput): Promise<SessionRecord> {
    const r=await this.pool.query(`insert into identity_sessions (id,user_id,token_hash,auth_version,user_agent_hash,ip_hash,idle_expires_at,expires_at,rotated_from_session_id) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,[input.id,input.userId,input.tokenHash,input.authVersion,input.userAgentHash,input.ipHash,input.idleExpiresAt,input.expiresAt,input.rotatedFromSessionId??null]);
    const row=r.rows[0] as Record<string,unknown>|undefined; if(!row) throw new Error("identity_session_insert_returned_no_row"); return rowToSession(row);
  }
  async findActiveSessionByTokenHash(tokenHash: string) { const r=await this.pool.query(`select * from identity_sessions where token_hash=$1 and revoked_at is null and idle_expires_at>now() and expires_at>now()`,[tokenHash]); const row=r.rows[0] as Record<string,unknown>|undefined; return row?rowToSession(row):null; }
  async touchSession(id: string,idleExpiresAt:string){ await this.pool.query("update identity_sessions set last_seen_at=now(),idle_expires_at=least($2,expires_at) where id=$1 and revoked_at is null",[id,idleExpiresAt]); }
  async rotateSession(oldTokenHash:string,input:SessionCreateInput):Promise<SessionRecord|null>{ return transaction(this.pool,async(client)=>{ const old=await client.query<{id:string}>(`select id from identity_sessions where token_hash=$1 and revoked_at is null and idle_expires_at>now() and expires_at>now() for update`,[oldTokenHash]); if(!old.rows[0])return null; await client.query("update identity_sessions set revoked_at=now() where id=$1",[old.rows[0].id]); const r=await client.query(`insert into identity_sessions (id,user_id,token_hash,auth_version,user_agent_hash,ip_hash,idle_expires_at,expires_at,rotated_from_session_id) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,[input.id,input.userId,input.tokenHash,input.authVersion,input.userAgentHash,input.ipHash,input.idleExpiresAt,input.expiresAt,old.rows[0].id]); return rowToSession(r.rows[0] as Record<string,unknown>); }); }
  async listActiveSessions(userId:string){ const r=await this.pool.query(`select * from identity_sessions where user_id=$1 and revoked_at is null and idle_expires_at>now() and expires_at>now() order by last_seen_at desc`,[userId]); return r.rows.map((row)=>rowToSession(row as Record<string,unknown>)); }
  async revokeSession(tokenHash:string){ await this.pool.query("update identity_sessions set revoked_at=now() where token_hash=$1 and revoked_at is null",[tokenHash]); }
  async revokeSessionById(userId:string,sessionId:string){ await this.pool.query("update identity_sessions set revoked_at=now() where id=$1 and user_id=$2 and revoked_at is null",[sessionId,userId]); }
  async revokeAllSessions(userId:string){ await this.pool.query("update identity_sessions set revoked_at=now() where user_id=$1 and revoked_at is null",[userId]); }

  async recordSecurityEvent(input:{id:string;userId?:string;eventType:string;outcome:"success"|"denied"|"accepted";subjectHash?:string;metadata?:Record<string,unknown>}):Promise<void>{
    await this.pool.query(`insert into identity_security_events (id,user_id,event_type,outcome,subject_hash,metadata) values ($1,$2,$3,$4,$5,$6::jsonb)`,[input.id,input.userId??null,input.eventType,input.outcome,input.subjectHash??null,JSON.stringify(input.metadata??{})]);
  }
}
