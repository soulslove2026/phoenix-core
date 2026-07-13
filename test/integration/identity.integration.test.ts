import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { buildApp } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import fs from "node:fs/promises";

const databaseUrl = process.env.PHOENIX_DATABASE_URL;

test("identity API persists registration and session", { skip: !databaseUrl }, async () => {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  const sql = await fs.readFile(new URL("../../migrations/001_identity.sql", import.meta.url), "utf8");
  await pool.query(sql);
  await pool.query("truncate identity_sessions, identity_users cascade");
  await pool.end();

  const app = await buildApp(loadConfig({
    PHOENIX_ENV: "test",
    PHOENIX_LOG_LEVEL: "error",
    PHOENIX_DATABASE_REQUIRED: "true",
    PHOENIX_DATABASE_URL: databaseUrl
  }));

  const register = await app.inject({
    method: "POST",
    url: "/v1/identity/register",
    payload: { email: "identity@example.com", displayName: "Identity User", password: "strong-password-123" }
  });
  assert.equal(register.statusCode, 201);
  const token = register.json().sessionToken as string;

  const me = await app.inject({
    method: "GET",
    url: "/v1/identity/me",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(me.statusCode, 200);
  assert.equal(me.json().user.email, "identity@example.com");

  const logout = await app.inject({
    method: "POST",
    url: "/v1/identity/logout",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(logout.statusCode, 204);

  await app.close();
});
