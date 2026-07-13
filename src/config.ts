export type AppConfig = Readonly<{
  serviceName: string;
  version: string;
  environment: string;
  host: string;
  port: number;
  logLevel: "debug" | "info" | "warn" | "error";
  databaseRequired: boolean;
  databaseUrl?: string;
  identitySessionTtlSeconds: number;
  identityRateLimitWindowSeconds: number;
  identityRegisterMaxAttempts: number;
  identityLoginMaxAttempts: number;
}>;

function boundedPositiveInt(
  name: string,
  value: string | undefined,
  fallback: number,
  maximum: number
): number {
  const parsed = value === undefined || value.trim() === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${name} must be a positive integer not greater than ${maximum}`);
  }
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const environment = env.PHOENIX_ENV?.trim();
  if (!environment) throw new Error("PHOENIX_ENV is required");

  const port = boundedPositiveInt("PHOENIX_PORT", env.PHOENIX_PORT, 3000, 65_535);
  const logLevel = (env.PHOENIX_LOG_LEVEL ?? "info") as AppConfig["logLevel"];
  if (!["debug", "info", "warn", "error"].includes(logLevel)) {
    throw new Error("invalid PHOENIX_LOG_LEVEL");
  }

  const databaseRequired = env.PHOENIX_DATABASE_REQUIRED === "true";
  const databaseUrl = env.PHOENIX_DATABASE_URL?.trim();
  if (databaseRequired && !databaseUrl) {
    throw new Error("PHOENIX_DATABASE_URL is required when database is required");
  }

  const identitySessionTtlSeconds = boundedPositiveInt(
    "PHOENIX_IDENTITY_SESSION_TTL_SECONDS",
    env.PHOENIX_IDENTITY_SESSION_TTL_SECONDS,
    2_592_000,
    7_776_000
  );
  const identityRateLimitWindowSeconds = boundedPositiveInt(
    "PHOENIX_IDENTITY_RATE_LIMIT_WINDOW_SECONDS",
    env.PHOENIX_IDENTITY_RATE_LIMIT_WINDOW_SECONDS,
    900,
    3_600
  );
  const identityRegisterMaxAttempts = boundedPositiveInt(
    "PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS",
    env.PHOENIX_IDENTITY_REGISTER_MAX_ATTEMPTS,
    5,
    100
  );
  const identityLoginMaxAttempts = boundedPositiveInt(
    "PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS",
    env.PHOENIX_IDENTITY_LOGIN_MAX_ATTEMPTS,
    10,
    1_000
  );

  return Object.freeze({
    serviceName: "phoenix-core",
    version: "3.3.2",
    environment,
    host: env.PHOENIX_HOST?.trim() || "127.0.0.1",
    port,
    logLevel,
    databaseRequired,
    ...(databaseUrl ? { databaseUrl } : {}),
    identitySessionTtlSeconds,
    identityRateLimitWindowSeconds,
    identityRegisterMaxAttempts,
    identityLoginMaxAttempts
  });
}
