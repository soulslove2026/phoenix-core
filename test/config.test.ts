import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/config.js";

const secret = Buffer.alloc(32, 1).toString("base64url");

function stagingEnvironment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PHOENIX_ENV: "staging",
    PHOENIX_DEPLOYMENT_ID: "staging-20260715-001",
    PHOENIX_REGION: "eu-west-1",
    PHOENIX_BUILD_COMMIT: "0123456789abcdef0123456789abcdef01234567",
    PHOENIX_DATABASE_REQUIRED: "true",
    PHOENIX_DATABASE_URL: "postgres://staging-user:strong-password@postgres:5432/phoenix_staging",
    PHOENIX_IDENTITY_TOKEN_PEPPER: secret,
    PHOENIX_IDENTITY_NOTIFICATION_KEY: secret,
    PHOENIX_IDENTITY_PRIVACY_KEY: secret,
    PHOENIX_IDENTITY_MFA_KEY: secret,
    PHOENIX_OPERATIONS_ENABLED: "true",
    PHOENIX_OPERATIONS_TOKEN: secret,
    PHOENIX_IDENTITY_WEBAUTHN_RP_ID: "staging.example.test",
    PHOENIX_IDENTITY_WEBAUTHN_ORIGINS: "https://staging.example.test",
    PHOENIX_IDENTITY_PASSWORD_BREACH_MODE: "required",
    PHOENIX_REQUIRE_TLS: "true",
    PHOENIX_TRUST_PROXY_HOPS: "1",
    PHOENIX_DOCUMENTATION_ENABLED: "false",
    ...overrides
  };
}

test("database identity config requires separate strong secrets", () => {
  assert.throws(() => loadConfig({ PHOENIX_ENV: "test", PHOENIX_DATABASE_REQUIRED: "true", PHOENIX_DATABASE_URL: "postgres://x" }));
  const config = loadConfig({
    PHOENIX_ENV: "test",
    PHOENIX_DATABASE_REQUIRED: "true",
    PHOENIX_DATABASE_URL: "postgres://x",
    PHOENIX_IDENTITY_TOKEN_PEPPER: secret,
    PHOENIX_IDENTITY_NOTIFICATION_KEY: secret,
    PHOENIX_IDENTITY_PRIVACY_KEY: secret,
    PHOENIX_IDENTITY_MFA_KEY: secret
  });
  assert.equal(config.version, "4.0.0");
  assert.equal(config.identitySessionIdleTtlSeconds, 43_200);
  assert.equal(config.identityWebauthnRpId, "localhost");
});

test("production requires explicit WebAuthn relying-party and deployment configuration", () => {
  assert.throws(() => loadConfig({ PHOENIX_ENV: "production" }));
});

test("idle TTL cannot exceed absolute TTL", () => {
  assert.throws(() => loadConfig({ PHOENIX_ENV: "test", PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS: "1000", PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS: "900" }));
});

test("operations require a strong dedicated token", () => {
  assert.throws(() => loadConfig({ PHOENIX_ENV: "test", PHOENIX_OPERATIONS_ENABLED: "true" }));
  const config = loadConfig({ PHOENIX_ENV: "test", PHOENIX_OPERATIONS_ENABLED: "true", PHOENIX_OPERATIONS_TOKEN: secret });
  assert.equal(config.operationsEnabled, true);
});

test("passkey validation harness is forbidden outside governed local or staging environments", () => {
  assert.throws(() => loadConfig({ PHOENIX_ENV: "production", PHOENIX_PASSKEY_VALIDATION_ENABLED: "true" }));
  assert.throws(() => loadConfig({ PHOENIX_ENV: "integration", PHOENIX_PASSKEY_VALIDATION_ENABLED: "true" }));
});

test("staging requires production-like TLS, observability, deployment identity, and non-local WebAuthn", () => {
  const config = loadConfig(stagingEnvironment({ PHOENIX_PASSKEY_VALIDATION_ENABLED: "true" }));
  assert.equal(config.environment, "staging");
  assert.equal(config.requireTls, true);
  assert.equal(config.operationsEnabled, true);
  assert.equal(config.documentationEnabled, false);
  assert.equal(config.identityWebauthnRpId, "staging.example.test");
  assert.deepEqual(config.identityWebauthnOrigins, ["https://staging.example.test"]);
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_REQUIRE_TLS: "false" })));
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_OPERATIONS_ENABLED: "false" })));
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_IDENTITY_WEBAUTHN_RP_ID: "localhost" })));
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_IDENTITY_WEBAUTHN_ORIGINS: "http://staging.example.test" })));
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_IDENTITY_PASSWORD_BREACH_MODE: "disabled" })));
});

test("secret file inputs are supported and mutually exclusive with direct values", () => {
  const directory = mkdtempSync(join(tmpdir(), "phoenix-config-"));
  try {
    const secretFile = join(directory, "token-pepper");
    writeFileSync(secretFile, `${secret}\n`, { mode: 0o600 });
    const config = loadConfig({
      PHOENIX_ENV: "test",
      PHOENIX_DATABASE_REQUIRED: "true",
      PHOENIX_DATABASE_URL: "postgres://x",
      PHOENIX_IDENTITY_TOKEN_PEPPER_FILE: secretFile,
      PHOENIX_IDENTITY_NOTIFICATION_KEY: secret,
      PHOENIX_IDENTITY_PRIVACY_KEY: secret,
      PHOENIX_IDENTITY_MFA_KEY: secret
    });
    assert.equal(config.identityTokenPepper, secret);
    assert.throws(() => loadConfig({
      PHOENIX_ENV: "test",
      PHOENIX_IDENTITY_TOKEN_PEPPER: secret,
      PHOENIX_IDENTITY_TOKEN_PEPPER_FILE: secretFile
    }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("default local database credentials are rejected in staging", () => {
  assert.throws(() => loadConfig(stagingEnvironment({ PHOENIX_DATABASE_URL: "postgres://phoenix:phoenix@postgres:5432/phoenix" })));
});
