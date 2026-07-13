import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { buildApp } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";

const databaseUrl = process.env.PHOENIX_DATABASE_URL;

test("identity API persists registration, rejects a duplicate race, and revokes sessions", { skip: !databaseUrl }, async () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  await pool.query("truncate identity_sessions, identity_users cascade");
  const migrationCount = await pool.query<{ count: string }>("select count(*)::text as count from phoenix_schema_migrations");
  assert.ok(Number(migrationCount.rows[0]?.count ?? 0) >= 2);

  const app = await buildApp(loadConfig({
    PHOENIX_ENV: "test",
    PHOENIX_LOG_LEVEL: "error",
    PHOENIX_DATABASE_REQUIRED: "true",
    PHOENIX_DATABASE_URL: databaseUrl,
    PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS: "20",
    PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS: "20"
  }));

  const register = await app.inject({
    method: "POST",
    url: "/v1/identity/register",
    payload: { email: "identity@example.com", displayName: "Identity User", password: "strong-password-123" }
  });
  assert.equal(register.statusCode, 201);
  const token = register.json().sessionToken as string;

  const duplicate = await app.inject({
    method: "POST",
    url: "/v1/identity/register",
    payload: { email: "IDENTITY@example.com", displayName: "Duplicate", password: "strong-password-123" }
  });
  assert.equal(duplicate.statusCode, 409);
  assert.equal(duplicate.json().error, "registration_unavailable");

  const me = await app.inject({
    method: "GET",
    url: "/v1/identity/me",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(me.statusCode, 200);
  assert.equal(me.json().user.email, "identity@example.com");

  const before = await pool.query<{ updated_at: Date }>("select updated_at from identity_users where email = $1", ["identity@example.com"]);
  await pool.query("select pg_sleep(0.01)");
  await pool.query("update identity_users set display_name = $1 where email = $2", ["Updated User", "identity@example.com"]);
  const after = await pool.query<{ updated_at: Date }>("select updated_at from identity_users where email = $1", ["identity@example.com"]);
  assert.ok(new Date(after.rows[0]!.updated_at).getTime() > new Date(before.rows[0]!.updated_at).getTime());

  const logout = await app.inject({
    method: "POST",
    url: "/v1/identity/logout",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(logout.statusCode, 204);

  const revoked = await app.inject({
    method: "GET",
    url: "/v1/identity/me",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(revoked.statusCode, 401);

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const denied = await app.inject({
      method: "POST",
      url: "/v1/identity/login",
      payload: { email: "missing@example.com", password: "wrong" }
    });
    assert.equal(denied.statusCode, 401);
  }
  const throttled = await app.inject({
    method: "POST",
    url: "/v1/identity/login",
    payload: { email: "missing@example.com", password: "wrong" }
  });
  assert.equal(throttled.statusCode, 429);
  assert.equal(throttled.json().error, "rate_limit_exceeded");
  assert.ok(Number(throttled.headers["retry-after"]) > 0);

  await app.close();
  await pool.end();
});
