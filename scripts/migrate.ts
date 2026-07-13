import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import pg from "pg";
import { loadConfig } from "../src/config.js";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required");

const migrationsDirectory = path.resolve(process.cwd(), "migrations");
const migrationFiles = (await fs.readdir(migrationsDirectory))
  .filter((name) => /^\d+_[a-z0-9_]+\.sql$/i.test(name))
  .sort((left, right) => left.localeCompare(right));
if (migrationFiles.length === 0) throw new Error("No migration files found");

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 1, application_name: `${config.serviceName}-migrator` });
const client = await pool.connect();
try {
  await client.query("select pg_advisory_lock(hashtext('phoenix_schema_migrations'))");
  await client.query(`
    create table if not exists phoenix_schema_migrations (
      migration_name text primary key,
      checksum_sha256 text not null,
      applied_at timestamptz not null default now()
    )
  `);

  for (const migrationName of migrationFiles) {
    const sql = await fs.readFile(path.join(migrationsDirectory, migrationName), "utf8");
    const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
    const existing = await client.query<{ checksum_sha256: string }>(
      "select checksum_sha256 from phoenix_schema_migrations where migration_name = $1",
      [migrationName]
    );

    if (existing.rows[0]) {
      if (existing.rows[0].checksum_sha256 !== checksum) {
        throw new Error(`Migration checksum mismatch: ${migrationName}`);
      }
      console.log(`Migration already applied: ${migrationName}`);
      continue;
    }

    await client.query("begin");
    try {
      await client.query(sql);
      await client.query(
        "insert into phoenix_schema_migrations (migration_name, checksum_sha256) values ($1, $2)",
        [migrationName, checksum]
      );
      await client.query("commit");
      console.log(`Migration applied: ${migrationName}`);
    } catch (error) {
      await client.query("rollback");
      throw error;
    }
  }
} finally {
  try {
    await client.query("select pg_advisory_unlock(hashtext('phoenix_schema_migrations'))");
  } finally {
    client.release();
    await pool.end();
  }
}
