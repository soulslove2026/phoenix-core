import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";

test("loads valid configuration and bounded identity defaults", () => {
  const config = loadConfig({ PHOENIX_ENV: "test", PHOENIX_PORT: "3100" });
  assert.equal(config.port, 3100);
  assert.equal(config.identitySessionTtlSeconds, 2_592_000);
  assert.equal(config.identityRegisterMaxAttempts, 5);
  assert.equal(config.identityLoginMaxAttempts, 10);
});

test("requires environment", () => {
  assert.throws(() => loadConfig({}), /PHOENIX_ENV/);
});

test("requires database URL when database is required", () => {
  assert.throws(
    () => loadConfig({ PHOENIX_ENV: "test", PHOENIX_DATABASE_REQUIRED: "true" }),
    /DATABASE_URL/
  );
});

test("rejects excessive session duration", () => {
  assert.throws(
    () => loadConfig({ PHOENIX_ENV: "test", PHOENIX_IDENTITY_SESSION_TTL_SECONDS: "7776001" }),
    /SESSION_TTL_SECONDS/
  );
});
