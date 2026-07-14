import pg from "pg";
import { loadConfig } from "../src/config.js";
import { rotateMfaPayload, rotateNotificationPayload, validateIdentityEncryptionRotation } from "../src/identity/key-rotation.js";

const config = loadConfig();
if (!config.databaseUrl || !config.identityNotificationKey || !config.identityMfaKey) throw new Error("current database and identity keys are required");
const rotationKeys = validateIdentityEncryptionRotation({
  currentNotificationKey: config.identityNotificationKey,
  currentMfaKey: config.identityMfaKey,
  nextNotificationKey: process.env.PHOENIX_IDENTITY_NOTIFICATION_KEY_NEW,
  nextMfaKey: process.env.PHOENIX_IDENTITY_MFA_KEY_NEW,
});
const apply = process.env.PHOENIX_KEY_ROTATION_APPLY === "true";
if (apply && process.env.PHOENIX_KEY_ROTATION_CONFIRM !== "ROTATE_IDENTITY_KEYS") throw new Error("PHOENIX_KEY_ROTATION_CONFIRM must equal ROTATE_IDENTITY_KEYS");

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 1, application_name: `${config.serviceName}-key-rotation` });
const client = await pool.connect();
const counts: Record<string, number> = {};

type Purpose = "notification" | "totp" | "webauthn";
async function rotateTable(table: string, columns: Readonly<{ ciphertext: string; iv: string; authTag: string }>, purpose: Purpose, oldKey: string, newKey: string): Promise<void> {
  const rows = await client.query<Record<string, string>>(`select id, ${columns.ciphertext} as ciphertext, ${columns.iv} as iv, ${columns.authTag} as auth_tag from ${table} order by id for update`);
  counts[table] = rows.rowCount ?? 0;
  for (const row of rows.rows) {
    const id = row.id;
    const ciphertext = row.ciphertext;
    const iv = row.iv;
    const authTag = row.auth_tag;
    if (!id || !ciphertext || !iv || !authTag) throw new Error(`identity_key_rotation_row_invalid:${table}`);
    const current = { ciphertext, iv, authTag };
    const rotated = purpose === "notification" ? rotateNotificationPayload(current, oldKey, newKey) : rotateMfaPayload(current, oldKey, newKey, purpose);
    if (apply) await client.query(`update ${table} set ${columns.ciphertext}=$2,${columns.iv}=$3,${columns.authTag}=$4 where id=$1`, [id, rotated.ciphertext, rotated.iv, rotated.authTag]);
  }
}

try {
  await client.query("begin");
  await client.query("select pg_advisory_xact_lock(hashtext('phoenix_identity_key_rotation'))");
  await rotateTable("identity_notification_outbox", { ciphertext: "ciphertext", iv: "iv", authTag: "auth_tag" }, "notification", rotationKeys.currentNotificationKey, rotationKeys.nextNotificationKey);
  await rotateTable("identity_totp_enrollments", { ciphertext: "secret_ciphertext", iv: "secret_iv", authTag: "secret_auth_tag" }, "totp", rotationKeys.currentMfaKey, rotationKeys.nextMfaKey);
  await rotateTable("identity_totp_factors", { ciphertext: "secret_ciphertext", iv: "secret_iv", authTag: "secret_auth_tag" }, "totp", rotationKeys.currentMfaKey, rotationKeys.nextMfaKey);
  await rotateTable("identity_webauthn_challenges", { ciphertext: "challenge_ciphertext", iv: "challenge_iv", authTag: "challenge_auth_tag" }, "webauthn", rotationKeys.currentMfaKey, rotationKeys.nextMfaKey);
  if (apply) await client.query("commit"); else await client.query("rollback");
  console.log(JSON.stringify({ event: "identity.key_rotation", mode: apply ? "applied" : "dry_run", counts }));
} catch (error) {
  await client.query("rollback");
  throw error;
} finally {
  client.release();
  await pool.end();
}
