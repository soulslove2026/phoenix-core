import type { AppConfig } from "../config.js";

export type StagingPreflightReport = Readonly<{
  schema: "phoenix.staging-preflight.v1";
  status: "passed";
  version: string;
  environment: "staging";
  deploymentId: string;
  region: string;
  buildCommit: string;
  checks: Readonly<Record<string, boolean>>;
}>;

export type StagingSmokeReport = Readonly<{
  schema: "phoenix.staging-smoke.v1";
  status: "passed";
  observedAt: string;
  baseUrl: string;
  deployment: Readonly<{
    version: string;
    environment: string;
    deploymentId: string;
    region: string;
    buildCommit: string;
  }>;
  checks: Readonly<Record<string, boolean>>;
}>;

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${label} is missing`);
  return value;
}

export function assessStagingConfig(config: AppConfig): StagingPreflightReport {
  if (config.environment !== "staging") throw new Error("staging preflight requires PHOENIX_ENV=staging");
  const deploymentId = requiredString(config.deploymentId, "deploymentId");
  const region = requiredString(config.region, "region");
  const buildCommit = requiredString(config.buildCommit, "buildCommit");
  const checks = Object.freeze({
    databaseRequired: config.databaseRequired,
    tlsRequired: config.requireTls,
    trustedProxyConfigured: config.trustProxyHops >= 1,
    documentationDisabled: !config.documentationEnabled,
    operationsEnabled: config.operationsEnabled,
    passwordBreachScreeningEnabled: config.identityPasswordBreachMode !== "disabled",
    webauthnRpIsNonLocal: config.identityWebauthnRpId !== "localhost",
    webauthnOriginsUseHttps: config.identityWebauthnOrigins.every(origin => origin.startsWith("https://")),
    deploymentIdentityPresent: Boolean(deploymentId && region && buildCommit)
  });
  if (Object.values(checks).some(value => !value)) throw new Error("staging preflight checks failed");
  return Object.freeze({
    schema: "phoenix.staging-preflight.v1",
    status: "passed",
    version: config.version,
    environment: "staging",
    deploymentId,
    region,
    buildCommit,
    checks
  });
}

function normalizedBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:") throw new Error("PHOENIX_STAGING_BASE_URL must use https");
  if (url.username || url.password || url.hash || url.search) throw new Error("PHOENIX_STAGING_BASE_URL must not contain credentials, fragments, or query parameters");
  return url.toString().replace(/\/$/u, "");
}

async function fetchWithTimeout(fetchImpl: typeof fetch, url: string, init: RequestInit = {}, timeoutMs = 10_000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, redirect: "error", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function assertSecurityHeaders(response: Response, label: string): void {
  if (response.headers.get("x-content-type-options") !== "nosniff") throw new Error(`${label} missing nosniff`);
  if (response.headers.get("x-frame-options") !== "DENY") throw new Error(`${label} missing frame denial`);
  if (response.headers.get("cache-control") !== "no-store") throw new Error(`${label} missing no-store`);
  if (!response.headers.get("strict-transport-security")) throw new Error(`${label} missing HSTS`);
}

export async function smokeStaging(
  baseUrlValue: string,
  options: Readonly<{ expectPasskeyHarness: boolean; operationsToken?: string; timeoutMs?: number }>,
  fetchImpl: typeof fetch = fetch
): Promise<StagingSmokeReport> {
  const baseUrl = normalizedBaseUrl(baseUrlValue);
  const timeoutMs = options.timeoutMs ?? 10_000;

  const health = await fetchWithTimeout(fetchImpl, `${baseUrl}/v1/system/health`, {}, timeoutMs);
  if (health.status !== 200) throw new Error(`staging health returned ${health.status}`);
  assertSecurityHeaders(health, "health");
  const healthBody = await health.json() as Record<string, unknown>;
  const environment = requiredString(healthBody.environment, "health.environment");
  if (environment !== "staging") throw new Error("staging health reported a non-staging environment");
  const deploymentId = requiredString(healthBody.deploymentId, "health.deploymentId");
  const region = requiredString(healthBody.region, "health.region");
  const buildCommit = requiredString(healthBody.buildCommit, "health.buildCommit");
  const version = requiredString(healthBody.version, "health.version");

  const ready = await fetchWithTimeout(fetchImpl, `${baseUrl}/v1/system/ready`, {}, timeoutMs);
  if (ready.status !== 200) throw new Error(`staging readiness returned ${ready.status}`);
  assertSecurityHeaders(ready, "readiness");
  const readyBody = await ready.json() as Record<string, unknown>;
  if (readyBody.status !== "ready" || readyBody.database !== "available") throw new Error("staging readiness did not prove database availability");
  if (readyBody.deploymentId !== deploymentId || readyBody.buildCommit !== buildCommit) throw new Error("staging health and readiness deployment identity differ");

  if (options.expectPasskeyHarness) {
    const harness = await fetchWithTimeout(fetchImpl, `${baseUrl}/passkey-validation/`, {}, timeoutMs);
    if (harness.status !== 200) throw new Error(`Passkey harness returned ${harness.status}`);
    assertSecurityHeaders(harness, "Passkey harness");
    if (!harness.headers.get("x-robots-tag")?.includes("noindex")) throw new Error("Passkey harness missing noindex");
    const body = await harness.text();
    if (!body.includes("Phoenix Passkey Validation")) throw new Error("Passkey harness content is unexpected");
  }

  if (options.operationsToken) {
    const operations = await fetchWithTimeout(fetchImpl, `${baseUrl}/v1/operations/identity/health`, {
      headers: { authorization: `Bearer ${options.operationsToken}` }
    }, timeoutMs);
    if (![200, 503].includes(operations.status)) throw new Error(`operations health returned ${operations.status}`);
    assertSecurityHeaders(operations, "operations health");
  }

  return Object.freeze({
    schema: "phoenix.staging-smoke.v1",
    status: "passed",
    observedAt: new Date().toISOString(),
    baseUrl,
    deployment: Object.freeze({ version, environment, deploymentId, region, buildCommit }),
    checks: Object.freeze({
      https: true,
      health: true,
      readiness: true,
      databaseAvailable: true,
      securityHeaders: true,
      deploymentIdentityConsistent: true,
      passkeyHarness: options.expectPasskeyHarness,
      operationsHealth: Boolean(options.operationsToken)
    })
  });
}
