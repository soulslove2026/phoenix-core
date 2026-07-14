import fs from "node:fs";
import pg from "pg";
import { loadConfig } from "../src/config.js";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required");
const hours = Number(process.env.PHOENIX_INCIDENT_SNAPSHOT_HOURS ?? "24");
if (!Number.isInteger(hours) || hours < 1 || hours > 720) throw new Error("PHOENIX_INCIDENT_SNAPSHOT_HOURS must be between 1 and 720");
const output = process.env.PHOENIX_INCIDENT_SNAPSHOT_PATH?.trim();
const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 1, application_name: `${config.serviceName}-incident-snapshot` });
try {
  const [events, sessions, notifications] = await Promise.all([
    pool.query<{ event_type: string; outcome: string; count: number }>(`select event_type,outcome,count(*)::int count from identity_security_events where created_at>=now()-($1::int*interval '1 hour') group by event_type,outcome order by event_type,outcome`, [hours]),
    pool.query<{ active: number; revoked: number }>(`select count(*) filter(where revoked_at is null and expires_at>now())::int active,count(*) filter(where revoked_at is not null)::int revoked from identity_sessions`),
    pool.query<{ pending: number; dead_lettered: number }>(`select count(*) filter(where sent_at is null and dead_lettered_at is null)::int pending,count(*) filter(where dead_lettered_at is not null)::int dead_lettered from identity_notification_outbox`),
  ]);
  const report = { schema: "phoenix.security-incident-snapshot.v1", generatedAt: new Date().toISOString(), windowHours: hours, aggregates: { events: events.rows, sessions: sessions.rows[0], notifications: notifications.rows[0] } };
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (output) fs.writeFileSync(output, serialized, { encoding: "utf8", mode: 0o600 }); else process.stdout.write(serialized);
} finally {
  await pool.end();
}
