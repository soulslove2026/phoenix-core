import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";
import { assessStagingConfig, smokeStaging } from "../src/deployment/staging-assurance.js";

const secret = Buffer.alloc(32, 2).toString("base64url");
const config = loadConfig({
  PHOENIX_ENV: "staging",
  PHOENIX_DEPLOYMENT_ID: "staging-release-001",
  PHOENIX_REGION: "eu-west-1",
  PHOENIX_BUILD_COMMIT: "abcdef0123456789abcdef0123456789abcdef01",
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
  PHOENIX_PASSKEY_VALIDATION_ENABLED: "true"
});

const headers = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
  "strict-transport-security": "max-age=86400"
};

test("staging preflight emits only sanitized deployment posture", () => {
  const report = assessStagingConfig(config);
  assert.equal(report.status, "passed");
  assert.equal(report.environment, "staging");
  assert.equal(report.checks.webauthnOriginsUseHttps, true);
  assert.doesNotMatch(JSON.stringify(report), new RegExp(secret, "u"));
});

test("staging smoke proves deployment identity, readiness, security headers, harness, and operations route", async () => {
  const fakeFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith("/v1/system/health")) return new Response(JSON.stringify({
      status: "healthy",
      service: "phoenix-core",
      version: "3.8.0",
      environment: "staging",
      deploymentId: "staging-release-001",
      region: "eu-west-1",
      buildCommit: "abcdef0123456789abcdef0123456789abcdef01",
      requestId: "request-1"
    }), { status: 200, headers: { ...headers, "content-type": "application/json" } });
    if (url.endsWith("/v1/system/ready")) return new Response(JSON.stringify({
      status: "ready",
      service: "phoenix-core",
      version: "3.8.0",
      environment: "staging",
      deploymentId: "staging-release-001",
      region: "eu-west-1",
      buildCommit: "abcdef0123456789abcdef0123456789abcdef01",
      requestId: "request-2",
      database: "available"
    }), { status: 200, headers: { ...headers, "content-type": "application/json" } });
    if (url.endsWith("/passkey-validation/")) return new Response("<h1>Phoenix Passkey Validation</h1>", { status: 200, headers: { ...headers, "x-robots-tag": "noindex, nofollow" } });
    if (url.endsWith("/v1/operations/identity/health")) {
      assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${secret}`);
      return new Response("{}", { status: 200, headers });
    }
    return new Response("not found", { status: 404 });
  };

  const report = await smokeStaging("https://staging.example.test", { expectPasskeyHarness: true, operationsToken: secret }, fakeFetch);
  assert.equal(report.status, "passed");
  assert.equal(report.deployment.environment, "staging");
  assert.equal(report.checks.passkeyHarness, true);
  assert.equal(report.checks.operationsHealth, true);
});

test("staging smoke rejects insecure base URLs", async () => {
  await assert.rejects(() => smokeStaging("http://staging.example.test", { expectPasskeyHarness: false }, fetch));
});
