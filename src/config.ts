export type AppConfig = Readonly<{
  serviceName: string;
  version: string;
  environment: string;
  host: string;
  port: number;
  logLevel: "debug" | "info" | "warn" | "error";
  databaseRequired: boolean;
  databaseUrl?: string;
  documentationEnabled: boolean;
  requireTls: boolean;
  trustProxyHops: number;
  identitySessionAbsoluteTtlSeconds: number;
  identitySessionIdleTtlSeconds: number;
  identityVerificationTtlSeconds: number;
  identityPasswordResetTtlSeconds: number;
  identityRateLimitWindowSeconds: number;
  identityRegisterMaxAttempts: number;
  identityLoginMaxAttempts: number;
  identityActionRequestMaxAttempts: number;
  identityActionConfirmMaxAttempts: number;
  identityTokenPepper?: string;
  identityNotificationKey?: string;
  identityPrivacyKey?: string;
}>;

function boundedInt(name: string, value: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = value === undefined || value.trim() === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function booleanValue(name: string, value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === "") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function validateBase64UrlSecret(name: string, value: string | undefined, required: boolean): string | undefined {
  const secret = value?.trim();
  if (!secret) {
    if (required) throw new Error(`${name} is required when the database is required`);
    return undefined;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(secret)) throw new Error(`${name} must use base64url encoding`);
  const decoded = Buffer.from(secret, "base64url");
  if (decoded.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return secret;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const environment = env.PHOENIX_ENV?.trim();
  if (!environment) throw new Error("PHOENIX_ENV is required");

  const port = boundedInt("PHOENIX_PORT", env.PHOENIX_PORT, 3000, 1, 65_535);
  const logLevel = (env.PHOENIX_LOG_LEVEL ?? "info") as AppConfig["logLevel"];
  if (!["debug", "info", "warn", "error"].includes(logLevel)) throw new Error("invalid PHOENIX_LOG_LEVEL");

  const databaseRequired = booleanValue("PHOENIX_DATABASE_REQUIRED", env.PHOENIX_DATABASE_REQUIRED, false);
  const databaseUrl = env.PHOENIX_DATABASE_URL?.trim();
  if (databaseRequired && !databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required when database is required");

  const absoluteTtl = boundedInt("PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS", env.PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS, 2_592_000, 900, 7_776_000);
  const idleTtl = boundedInt("PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS", env.PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS, 43_200, 300, 604_800);
  if (idleTtl > absoluteTtl) throw new Error("session idle TTL must not exceed absolute TTL");

  const documentationEnabled = booleanValue("PHOENIX_DOCUMENTATION_ENABLED", env.PHOENIX_DOCUMENTATION_ENABLED, environment !== "production");
  const requireTls = booleanValue("PHOENIX_REQUIRE_TLS", env.PHOENIX_REQUIRE_TLS, environment === "production");
  const trustProxyHops = boundedInt("PHOENIX_TRUST_PROXY_HOPS", env.PHOENIX_TRUST_PROXY_HOPS, 0, 0, 2);

  return Object.freeze({
    serviceName: "phoenix-core",
    version: "3.4.0",
    environment,
    host: env.PHOENIX_HOST?.trim() || "127.0.0.1",
    port,
    logLevel,
    databaseRequired,
    ...(databaseUrl ? { databaseUrl } : {}),
    documentationEnabled,
    requireTls,
    trustProxyHops,
    identitySessionAbsoluteTtlSeconds: absoluteTtl,
    identitySessionIdleTtlSeconds: idleTtl,
    identityVerificationTtlSeconds: boundedInt("PHOENIX_IDENTITY_VERIFICATION_TTL_SECONDS", env.PHOENIX_IDENTITY_VERIFICATION_TTL_SECONDS, 86_400, 300, 172_800),
    identityPasswordResetTtlSeconds: boundedInt("PHOENIX_IDENTITY_PASSWORD_RESET_TTL_SECONDS", env.PHOENIX_IDENTITY_PASSWORD_RESET_TTL_SECONDS, 900, 300, 3_600),
    identityRateLimitWindowSeconds: boundedInt("PHOENIX_IDENTITY_RATE_LIMIT_WINDOW_SECONDS", env.PHOENIX_IDENTITY_RATE_LIMIT_WINDOW_SECONDS, 900, 60, 3_600),
    identityRegisterMaxAttempts: boundedInt("PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS", env.PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS, 5, 1, 100),
    identityLoginMaxAttempts: boundedInt("PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS", env.PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS, 10, 1, 1_000),
    identityActionRequestMaxAttempts: boundedInt("PHOENIX_IDENTITY_ACTION_REQUEST_MAX_ATTEMPTS", env.PHOENIX_IDENTITY_ACTION_REQUEST_MAX_ATTEMPTS, 5, 1, 100),
    identityActionConfirmMaxAttempts: boundedInt("PHOENIX_IDENTITY_ACTION_CONFIRM_MAX_ATTEMPTS", env.PHOENIX_IDENTITY_ACTION_CONFIRM_MAX_ATTEMPTS, 10, 1, 100),
    ...(validateBase64UrlSecret("PHOENIX_IDENTITY_TOKEN_PEPPER", env.PHOENIX_IDENTITY_TOKEN_PEPPER, databaseRequired) ? { identityTokenPepper: env.PHOENIX_IDENTITY_TOKEN_PEPPER!.trim() } : {}),
    ...(validateBase64UrlSecret("PHOENIX_IDENTITY_NOTIFICATION_KEY", env.PHOENIX_IDENTITY_NOTIFICATION_KEY, databaseRequired) ? { identityNotificationKey: env.PHOENIX_IDENTITY_NOTIFICATION_KEY!.trim() } : {}),
    ...(validateBase64UrlSecret("PHOENIX_IDENTITY_PRIVACY_KEY", env.PHOENIX_IDENTITY_PRIVACY_KEY, databaseRequired) ? { identityPrivacyKey: env.PHOENIX_IDENTITY_PRIVACY_KEY!.trim() } : {})
  });
}
