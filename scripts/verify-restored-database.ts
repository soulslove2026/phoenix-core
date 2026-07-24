import pg from "pg";

const databaseUrl = process.env.PHOENIX_RECOVERY_DATABASE_URL?.trim();
if (!databaseUrl) throw new Error("PHOENIX_RECOVERY_DATABASE_URL is required");
const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, application_name: "phoenix-recovery-verifier" });
try {
  const migration = await pool.query<{ count: number }>("select count(*)::int count from phoenix_schema_migrations");
  const requiredTables = ["identity_users", "identity_sessions", "identity_security_events", "identity_passkeys", "identity_totp_factors", "identity_notification_outbox"];
  const tables = await pool.query<{ table_name: string }>("select table_name from information_schema.tables where table_schema='public' and table_name=any($1::text[])", [requiredTables]);
  const found = new Set(tables.rows.map(row => row.table_name));
  const missing = requiredTables.filter(table => !found.has(table));
  if (Number(migration.rows[0]?.count ?? 0) !== 5) throw new Error("recovery_migration_ledger_invalid");
  if (missing.length) throw new Error(`recovery_tables_missing:${missing.join(",")}`);
  const integrity = await pool.query<{ invalid_sessions: number; invalid_assurance: number }>(`select
    (select count(*)::int from identity_sessions s left join identity_users u on u.id=s.user_id where u.id is null) invalid_sessions,
    (select count(*)::int from identity_session_assurance a left join identity_sessions s on s.id=a.session_id where s.id is null) invalid_assurance`);
  if (Number(integrity.rows[0]?.invalid_sessions ?? 0) !== 0 || Number(integrity.rows[0]?.invalid_assurance ?? 0) !== 0) throw new Error("recovery_referential_integrity_invalid");
  console.log(JSON.stringify({ event: "database.recovery_verified", migrationCount: 5, requiredTables: requiredTables.length }));
} finally {
  await pool.end();
}
