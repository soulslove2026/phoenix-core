import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  MfaTransactionRecord,
  NotificationOutboxRecord,
  PasskeyRecord,
  SessionAssuranceMethod,
  SessionAssuranceRecord,
  TotpEnrollmentRecord,
  TotpFactorRecord,
  WebAuthnChallengeRecord
} from "./phase-b-types.js";
import type { EncryptedPayload } from "./token-crypto.js";

async function transaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await operation(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

function sessionAssurance(row: Record<string, unknown>): SessionAssuranceRecord {
  return {
    sessionId: String(row.session_id),
    userId: String(row.user_id),
    method: String(row.method) as SessionAssuranceMethod,
    level: Number(row.assurance_level) === 2 ? 2 : 1,
    authenticatedAt: new Date(String(row.authenticated_at)).toISOString(),
    authenticatorId: row.authenticator_id ? String(row.authenticator_id) : null
  };
}

function totpFactor(row: Record<string, unknown>): TotpFactorRecord {
  return {
    id: String(row.id), userId: String(row.user_id),
    secretCiphertext: String(row.secret_ciphertext), secretIv: String(row.secret_iv), secretAuthTag: String(row.secret_auth_tag),
    algorithm: "SHA1", digits: 6, periodSeconds: 30, lastUsedStep: Number(row.last_used_step),
    enabledAt: new Date(String(row.enabled_at)).toISOString(), disabledAt: row.disabled_at ? new Date(String(row.disabled_at)).toISOString() : null
  };
}

function totpEnrollment(row: Record<string, unknown>): TotpEnrollmentRecord {
  return {
    id: String(row.id), userId: String(row.user_id),
    secretCiphertext: String(row.secret_ciphertext), secretIv: String(row.secret_iv), secretAuthTag: String(row.secret_auth_tag),
    expiresAt: new Date(String(row.expires_at)).toISOString(), attempts: Number(row.attempts), maxAttempts: Number(row.max_attempts),
    ipHash: String(row.ip_hash), userAgentHash: String(row.user_agent_hash)
  };
}

function mfaTransaction(row: Record<string, unknown>): MfaTransactionRecord {
  return {
    id: String(row.id), userId: String(row.user_id), tokenHash: String(row.token_hash),
    expiresAt: new Date(String(row.expires_at)).toISOString(), attempts: Number(row.attempts), maxAttempts: Number(row.max_attempts),
    ipHash: String(row.ip_hash), userAgentHash: String(row.user_agent_hash)
  };
}

function passkey(row: Record<string, unknown>): PasskeyRecord {
  return {
    id: String(row.id), userId: String(row.user_id), credentialId: String(row.credential_id), webauthnUserId: String(row.webauthn_user_id),
    publicKey: new Uint8Array(row.public_key as Buffer), counter: Number(row.counter),
    deviceType: row.device_type === "multiDevice" ? "multiDevice" : "singleDevice", backedUp: Boolean(row.backed_up),
    transports: Array.isArray(row.transports) ? row.transports.map(String) as PasskeyRecord["transports"] : [],
    label: String(row.label), createdAt: new Date(String(row.created_at)).toISOString(),
    lastUsedAt: row.last_used_at ? new Date(String(row.last_used_at)).toISOString() : null
  };
}

function challenge(row: Record<string, unknown>): WebAuthnChallengeRecord {
  return {
    id: String(row.id), userId: row.user_id ? String(row.user_id) : null,
    purpose: row.purpose === "register" ? "register" : "authenticate",
    challengeCiphertext: String(row.challenge_ciphertext), challengeIv: String(row.challenge_iv), challengeAuthTag: String(row.challenge_auth_tag),
    expiresAt: new Date(String(row.expires_at)).toISOString(), ipHash: String(row.ip_hash), userAgentHash: String(row.user_agent_hash)
  };
}

export interface PhaseBIdentityRepository {
  setSessionAssurance(input: { sessionId: string; userId: string; method: SessionAssuranceMethod; level: 1 | 2; authenticatedAt: string; authenticatorId?: string }): Promise<void>;
  getSessionAssurance(sessionId: string): Promise<SessionAssuranceRecord | null>;
  createMfaTransaction(input: { id: string; userId: string; tokenHash: string; expiresAt: string; maxAttempts: number; ipHash: string; userAgentHash: string }): Promise<void>;
  findMfaTransaction(tokenHash: string): Promise<MfaTransactionRecord | null>;
  incrementMfaAttempt(id: string): Promise<void>;
  consumeMfaTransaction(id: string): Promise<boolean>;
  hasActiveTotpFactor(userId: string): Promise<boolean>;
  findTotpFactor(userId: string): Promise<TotpFactorRecord | null>;
  advanceTotpCounter(factorId: string, step: number): Promise<boolean>;
  createTotpEnrollment(input: { id: string; userId: string; encrypted: EncryptedPayload; expiresAt: string; maxAttempts: number; ipHash: string; userAgentHash: string }): Promise<void>;
  findTotpEnrollment(id: string, userId: string): Promise<TotpEnrollmentRecord | null>;
  incrementTotpEnrollmentAttempt(id: string): Promise<void>;
  completeTotpEnrollment(input: { enrollmentId: string; userId: string; currentSessionId: string; initialStep: number; recoveryCodeHashes: string[] }): Promise<boolean>;
  replaceRecoveryCodes(userId: string, codeHashes: string[]): Promise<void>;
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>;
  countRecoveryCodes(userId: string): Promise<number>;
  disableTotpAndRevokeSessions(userId: string): Promise<boolean>;
  createWebAuthnChallenge(input: { id: string; userId?: string; purpose: "register" | "authenticate"; encrypted: EncryptedPayload; expiresAt: string; ipHash: string; userAgentHash: string }): Promise<void>;
  consumeWebAuthnChallenge(id: string, purpose: "register" | "authenticate"): Promise<WebAuthnChallengeRecord | null>;
  createPasskey(input: { id: string; userId: string; credentialId: string; webauthnUserId: string; publicKey: Uint8Array; counter: number; deviceType: "singleDevice" | "multiDevice"; backedUp: boolean; transports: string[]; label: string }): Promise<void>;
  findPasskeyByCredentialId(credentialId: string): Promise<PasskeyRecord | null>;
  listPasskeys(userId: string): Promise<PasskeyRecord[]>;
  updatePasskeyAfterAuthentication(id: string, newCounter: number, backedUp: boolean): Promise<void>;
  deletePasskey(userId: string, id: string): Promise<boolean>;
  queueNotification(input: { id: string; userId: string; kind: "security_notice"; encrypted: EncryptedPayload }): Promise<void>;
  claimNotifications(limit: number, lockToken: string): Promise<NotificationOutboxRecord[]>;
  markNotificationSent(id: string, lockToken: string): Promise<void>;
  markNotificationFailed(id: string, lockToken: string, errorCode: string, retryAt: string, deadLetter: boolean): Promise<void>;
}

export class PostgresPhaseBIdentityRepository implements PhaseBIdentityRepository {
  constructor(private readonly pool: Pool) {}

  async setSessionAssurance(input: { sessionId: string; userId: string; method: SessionAssuranceMethod; level: 1 | 2; authenticatedAt: string; authenticatorId?: string }): Promise<void> {
    await this.pool.query(`insert into identity_session_assurance(session_id,user_id,method,assurance_level,authenticated_at,authenticator_id)
      values($1,$2,$3,$4,$5,$6) on conflict(session_id) do update set method=excluded.method,assurance_level=excluded.assurance_level,authenticated_at=excluded.authenticated_at,authenticator_id=excluded.authenticator_id`,
      [input.sessionId,input.userId,input.method,input.level,input.authenticatedAt,input.authenticatorId??null]);
  }
  async getSessionAssurance(sessionId:string){const r=await this.pool.query("select * from identity_session_assurance where session_id=$1",[sessionId]);const row=r.rows[0] as Record<string,unknown>|undefined;return row?sessionAssurance(row):null;}

  async createMfaTransaction(input:{id:string;userId:string;tokenHash:string;expiresAt:string;maxAttempts:number;ipHash:string;userAgentHash:string}){await this.pool.query(`insert into identity_mfa_transactions(id,user_id,token_hash,expires_at,max_attempts,ip_hash,user_agent_hash) values($1,$2,$3,$4,$5,$6,$7)`,[input.id,input.userId,input.tokenHash,input.expiresAt,input.maxAttempts,input.ipHash,input.userAgentHash]);}
  async findMfaTransaction(tokenHash:string){const r=await this.pool.query(`select * from identity_mfa_transactions where token_hash=$1 and consumed_at is null and expires_at>now() and attempts<max_attempts`,[tokenHash]);const row=r.rows[0] as Record<string,unknown>|undefined;return row?mfaTransaction(row):null;}
  async incrementMfaAttempt(id:string){await this.pool.query(`update identity_mfa_transactions set attempts=attempts+1,consumed_at=case when attempts+1>=max_attempts then now() else consumed_at end where id=$1 and consumed_at is null`,[id]);}
  async consumeMfaTransaction(id:string){const r=await this.pool.query(`update identity_mfa_transactions set consumed_at=now() where id=$1 and consumed_at is null and expires_at>now() and attempts<max_attempts returning id`,[id]);return r.rowCount===1;}

  async hasActiveTotpFactor(userId:string){const r=await this.pool.query("select 1 from identity_totp_factors where user_id=$1 and disabled_at is null",[userId]);return r.rowCount===1;}
  async findTotpFactor(userId:string){const r=await this.pool.query("select * from identity_totp_factors where user_id=$1 and disabled_at is null",[userId]);const row=r.rows[0] as Record<string,unknown>|undefined;return row?totpFactor(row):null;}
  async advanceTotpCounter(factorId:string,step:number){const r=await this.pool.query("update identity_totp_factors set last_used_step=$2 where id=$1 and disabled_at is null and last_used_step<$2 returning id",[factorId,step]);return r.rowCount===1;}
  async createTotpEnrollment(input:{id:string;userId:string;encrypted:EncryptedPayload;expiresAt:string;maxAttempts:number;ipHash:string;userAgentHash:string}){
    await transaction(this.pool,async(client)=>{await client.query("update identity_totp_enrollments set consumed_at=now() where user_id=$1 and consumed_at is null",[input.userId]);await client.query(`insert into identity_totp_enrollments(id,user_id,secret_ciphertext,secret_iv,secret_auth_tag,expires_at,max_attempts,ip_hash,user_agent_hash) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[input.id,input.userId,input.encrypted.ciphertext,input.encrypted.iv,input.encrypted.authTag,input.expiresAt,input.maxAttempts,input.ipHash,input.userAgentHash]);});
  }
  async findTotpEnrollment(id:string,userId:string){const r=await this.pool.query(`select * from identity_totp_enrollments where id=$1 and user_id=$2 and consumed_at is null and expires_at>now() and attempts<max_attempts`,[id,userId]);const row=r.rows[0] as Record<string,unknown>|undefined;return row?totpEnrollment(row):null;}
  async incrementTotpEnrollmentAttempt(id:string){await this.pool.query(`update identity_totp_enrollments set attempts=attempts+1,consumed_at=case when attempts+1>=max_attempts then now() else consumed_at end where id=$1 and consumed_at is null`,[id]);}
  async completeTotpEnrollment(input:{enrollmentId:string;userId:string;currentSessionId:string;initialStep:number;recoveryCodeHashes:string[]}):Promise<boolean>{
    return transaction(this.pool,async(client)=>{
      const enrollment=await client.query<Record<string,unknown>>(`select * from identity_totp_enrollments where id=$1 and user_id=$2 and consumed_at is null and expires_at>now() for update`,[input.enrollmentId,input.userId]);
      const row=enrollment.rows[0];if(!row)return false;
      await client.query(`insert into identity_totp_factors(id,user_id,secret_ciphertext,secret_iv,secret_auth_tag,last_used_step) values($1,$2,$3,$4,$5,$6)
        on conflict(user_id) do update set secret_ciphertext=excluded.secret_ciphertext,secret_iv=excluded.secret_iv,secret_auth_tag=excluded.secret_auth_tag,last_used_step=excluded.last_used_step,enabled_at=now(),disabled_at=null`,[randomUUID(),input.userId,row.secret_ciphertext,row.secret_iv,row.secret_auth_tag,input.initialStep]);
      await client.query("delete from identity_recovery_codes where user_id=$1",[input.userId]);
      for(const hash of input.recoveryCodeHashes)await client.query("insert into identity_recovery_codes(id,user_id,code_hash) values($1,$2,$3)",[randomUUID(),input.userId,hash]);
      await client.query("update identity_totp_enrollments set consumed_at=now() where id=$1",[input.enrollmentId]);
      const user=await client.query<{auth_version:number}>("update identity_users set auth_version=auth_version+1 where id=$1 returning auth_version",[input.userId]);
      const authVersion=user.rows[0]?.auth_version;if(!authVersion)throw new Error("identity_user_missing");
      await client.query("update identity_sessions set revoked_at=now() where user_id=$1 and id<>$2 and revoked_at is null",[input.userId,input.currentSessionId]);
      await client.query("update identity_sessions set auth_version=$2 where id=$1 and revoked_at is null",[input.currentSessionId,authVersion]);
      await client.query(`insert into identity_session_assurance(session_id,user_id,method,assurance_level,authenticated_at) values($1,$2,'password_totp',2,now()) on conflict(session_id) do update set method='password_totp',assurance_level=2,authenticated_at=now(),authenticator_id=null`,[input.currentSessionId,input.userId]);
      return true;
    });
  }
  async replaceRecoveryCodes(userId:string,hashes:string[]){await transaction(this.pool,async(client)=>{await client.query("delete from identity_recovery_codes where user_id=$1",[userId]);for(const hash of hashes)await client.query("insert into identity_recovery_codes(id,user_id,code_hash) values($1,$2,$3)",[randomUUID(),userId,hash]);});}
  async consumeRecoveryCode(userId:string,codeHash:string){const r=await this.pool.query("update identity_recovery_codes set consumed_at=now() where user_id=$1 and code_hash=$2 and consumed_at is null returning id",[userId,codeHash]);return r.rowCount===1;}
  async countRecoveryCodes(userId:string){const r=await this.pool.query<{count:string}>("select count(*)::text count from identity_recovery_codes where user_id=$1 and consumed_at is null",[userId]);return Number(r.rows[0]?.count??0);}
  async disableTotpAndRevokeSessions(userId:string){return transaction(this.pool,async(client)=>{const r=await client.query("update identity_totp_factors set disabled_at=now() where user_id=$1 and disabled_at is null returning id",[userId]);if(r.rowCount!==1)return false;await client.query("delete from identity_recovery_codes where user_id=$1",[userId]);await client.query("update identity_users set auth_version=auth_version+1 where id=$1",[userId]);await client.query("update identity_sessions set revoked_at=now() where user_id=$1 and revoked_at is null",[userId]);return true;});}

  async createWebAuthnChallenge(input:{id:string;userId?:string;purpose:"register"|"authenticate";encrypted:EncryptedPayload;expiresAt:string;ipHash:string;userAgentHash:string}){await this.pool.query(`insert into identity_webauthn_challenges(id,user_id,purpose,challenge_ciphertext,challenge_iv,challenge_auth_tag,expires_at,ip_hash,user_agent_hash) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[input.id,input.userId??null,input.purpose,input.encrypted.ciphertext,input.encrypted.iv,input.encrypted.authTag,input.expiresAt,input.ipHash,input.userAgentHash]);}
  async consumeWebAuthnChallenge(id:string,purpose:"register"|"authenticate"){return transaction(this.pool,async(client)=>{const r=await client.query<Record<string,unknown>>(`select * from identity_webauthn_challenges where id=$1 and purpose=$2 and consumed_at is null and expires_at>now() for update`,[id,purpose]);const row=r.rows[0];if(!row)return null;await client.query("update identity_webauthn_challenges set consumed_at=now() where id=$1",[id]);return challenge(row);});}
  async createPasskey(input:{id:string;userId:string;credentialId:string;webauthnUserId:string;publicKey:Uint8Array;counter:number;deviceType:"singleDevice"|"multiDevice";backedUp:boolean;transports:string[];label:string}){await this.pool.query(`insert into identity_passkeys(id,user_id,credential_id,webauthn_user_id,public_key,counter,device_type,backed_up,transports,label) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[input.id,input.userId,input.credentialId,input.webauthnUserId,Buffer.from(input.publicKey),input.counter,input.deviceType,input.backedUp,input.transports,input.label]);}
  async findPasskeyByCredentialId(credentialId:string){const r=await this.pool.query("select * from identity_passkeys where credential_id=$1",[credentialId]);const row=r.rows[0] as Record<string,unknown>|undefined;return row?passkey(row):null;}
  async listPasskeys(userId:string){const r=await this.pool.query("select * from identity_passkeys where user_id=$1 order by created_at desc",[userId]);return r.rows.map(row=>passkey(row as Record<string,unknown>));}
  async updatePasskeyAfterAuthentication(id:string,newCounter:number,backedUp:boolean){await this.pool.query("update identity_passkeys set counter=$2,backed_up=$3,last_used_at=now() where id=$1",[id,newCounter,backedUp]);}
  async deletePasskey(userId:string,id:string){const r=await this.pool.query("delete from identity_passkeys where id=$1 and user_id=$2 returning id",[id,userId]);return r.rowCount===1;}

  async queueNotification(input:{id:string;userId:string;kind:"security_notice";encrypted:EncryptedPayload}){await this.pool.query(`insert into identity_notification_outbox(id,user_id,kind,ciphertext,iv,auth_tag) values($1,$2,$3,$4,$5,$6)`,[input.id,input.userId,input.kind,input.encrypted.ciphertext,input.encrypted.iv,input.encrypted.authTag]);}
  async claimNotifications(limit:number,lockToken:string):Promise<NotificationOutboxRecord[]>{const r=await this.pool.query<Record<string,unknown>>(`with candidates as (select id from identity_notification_outbox where sent_at is null and dead_lettered_at is null and available_at<=now() and (locked_at is null or locked_at<now()-interval '5 minutes') order by created_at limit $1 for update skip locked) update identity_notification_outbox o set locked_at=now(),lock_token=$2,attempts=attempts+1 from candidates c where o.id=c.id returning o.*`,[limit,lockToken]);return r.rows.map(row=>({id:String(row.id),userId:String(row.user_id),kind:String(row.kind) as NotificationOutboxRecord["kind"],ciphertext:String(row.ciphertext),iv:String(row.iv),authTag:String(row.auth_tag),attempts:Number(row.attempts),lockToken:String(row.lock_token)}));}
  async markNotificationSent(id:string,lockToken:string){await this.pool.query("update identity_notification_outbox set sent_at=now(),locked_at=null,lock_token=null,last_error_code=null where id=$1 and lock_token=$2",[id,lockToken]);}
  async markNotificationFailed(id:string,lockToken:string,errorCode:string,retryAt:string,deadLetter:boolean){await this.pool.query(`update identity_notification_outbox set locked_at=null,lock_token=null,last_error_code=$3,available_at=$4,dead_lettered_at=case when $5 then now() else dead_lettered_at end where id=$1 and lock_token=$2`,[id,lockToken,errorCode,retryAt,deadLetter]);}
}
