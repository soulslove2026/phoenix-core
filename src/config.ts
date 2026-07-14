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
  identityMfaKey?: string;
  identityRecentAuthenticationSeconds: number;
  identityMfaTransactionTtlSeconds: number;
  identityMfaMaxAttempts: number;
  identityTotpEnrollmentTtlSeconds: number;
  identityTotpIssuer: string;
  identityWebauthnRpName: string;
  identityWebauthnRpId: string;
  identityWebauthnOrigins: string[];
  identityWebauthnChallengeTtlSeconds: number;
  identityWebauthnTimeoutMs: number;
  identityPasswordBreachMode: "required" | "best_effort" | "disabled";
  identityPwnedPasswordsBaseUrl: string;
  identityPwnedPasswordsTimeoutMs: number;
  notificationProviderUrl?: string;
  notificationProviderToken?: string;
  notificationFromEmail?: string;
  notificationProviderTimeoutMs: number;
  notificationWorkerBatchSize: number;
  notificationWorkerMaxAttempts: number;
  notificationWorkerPollMs: number;
  notificationWorkerOnce: boolean;
  operationsEnabled: boolean;
  operationsToken?: string;
  operationsObservationWindowMinutes: number;
  operationsStaleLockSeconds: number;
  operationsMaxDeadLetters: number;
  operationsMaxStaleLocks: number;
  operationsMaxDeniedEvents: number;
  passkeyValidationEnabled: boolean;
}>;

function boundedInt(name: string, value: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = value === undefined || value.trim() === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
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
  if (!secret) { if (required) throw new Error(`${name} is required when the database is required`); return undefined; }
  if (!/^[A-Za-z0-9_-]+$/u.test(secret)) throw new Error(`${name} must use base64url encoding`);
  if (Buffer.from(secret, "base64url").length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return secret;
}

function normalizedUrl(name: string, value: string, requireHttps: boolean): string {
  const url = new URL(value);
  if (requireHttps && url.protocol !== "https:") throw new Error(`${name} must use https`);
  if (url.username || url.password || url.hash) throw new Error(`${name} must not contain credentials or fragments`);
  return url.toString().replace(/\/$/u, "");
}

function optionalValue(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const environment = env.PHOENIX_ENV?.trim();
  if (!environment) throw new Error("PHOENIX_ENV is required");
  const production = environment === "production";
  const port = boundedInt("PHOENIX_PORT", env.PHOENIX_PORT, 3000, 1, 65_535);
  const logLevel = (env.PHOENIX_LOG_LEVEL ?? "info") as AppConfig["logLevel"];
  if (!["debug","info","warn","error"].includes(logLevel)) throw new Error("invalid PHOENIX_LOG_LEVEL");
  const databaseRequired = booleanValue("PHOENIX_DATABASE_REQUIRED", env.PHOENIX_DATABASE_REQUIRED, false);
  const databaseUrl = optionalValue(env.PHOENIX_DATABASE_URL);
  if (databaseRequired && !databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required when database is required");

  const absoluteTtl = boundedInt("PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS", env.PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS, 2_592_000, 900, 7_776_000);
  const idleTtl = boundedInt("PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS", env.PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS, 43_200, 300, 604_800);
  if (idleTtl > absoluteTtl) throw new Error("session idle TTL must not exceed absolute TTL");

  const webauthnRpId = optionalValue(env.PHOENIX_IDENTITY_WEBAUTHN_RP_ID) ?? (production ? "" : "localhost");
  if (!webauthnRpId) throw new Error("PHOENIX_IDENTITY_WEBAUTHN_RP_ID is required in production");
  if (!/^(localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/iu.test(webauthnRpId)) throw new Error("invalid WebAuthn RP ID");
  const originSource = optionalValue(env.PHOENIX_IDENTITY_WEBAUTHN_ORIGINS) ?? (production ? "" : "http://localhost:3000");
  if (!originSource) throw new Error("PHOENIX_IDENTITY_WEBAUTHN_ORIGINS is required in production");
  const webauthnOrigins = [...new Set(originSource.split(",").map(value=>normalizedUrl("PHOENIX_IDENTITY_WEBAUTHN_ORIGINS",value.trim(),production)))];
  if (webauthnOrigins.length === 0 || webauthnOrigins.length > 5) throw new Error("WebAuthn origins must contain between 1 and 5 values");

  const breachMode = (optionalValue(env.PHOENIX_IDENTITY_PASSWORD_BREACH_MODE) ?? (production ? "required" : "disabled")) as AppConfig["identityPasswordBreachMode"];
  if (!["required","best_effort","disabled"].includes(breachMode)) throw new Error("invalid password breach mode");

  const providerUrlRaw = optionalValue(env.PHOENIX_NOTIFICATION_PROVIDER_URL);
  const providerUrl = providerUrlRaw ? normalizedUrl("PHOENIX_NOTIFICATION_PROVIDER_URL", providerUrlRaw, production) : undefined;
  const operationsEnabled = booleanValue("PHOENIX_OPERATIONS_ENABLED", env.PHOENIX_OPERATIONS_ENABLED, false);
  const operationsToken = validateBase64UrlSecret("PHOENIX_OPERATIONS_TOKEN", env.PHOENIX_OPERATIONS_TOKEN, operationsEnabled);
  const passkeyValidationEnabled = booleanValue("PHOENIX_PASSKEY_VALIDATION_ENABLED", env.PHOENIX_PASSKEY_VALIDATION_ENABLED, false);
  if (production && passkeyValidationEnabled) throw new Error("Passkey validation harness is forbidden in production");

  return Object.freeze({
    serviceName: "phoenix-core",
    version: "3.6.0",
    environment,
    host: optionalValue(env.PHOENIX_HOST) ?? "127.0.0.1",
    port,
    logLevel,
    databaseRequired,
    ...(databaseUrl ? { databaseUrl } : {}),
    documentationEnabled: booleanValue("PHOENIX_DOCUMENTATION_ENABLED", env.PHOENIX_DOCUMENTATION_ENABLED, !production),
    requireTls: booleanValue("PHOENIX_REQUIRE_TLS", env.PHOENIX_REQUIRE_TLS, production),
    trustProxyHops: boundedInt("PHOENIX_TRUST_PROXY_HOPS", env.PHOENIX_TRUST_PROXY_HOPS, 0, 0, 2),
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
    ...(validateBase64UrlSecret("PHOENIX_IDENTITY_PRIVACY_KEY", env.PHOENIX_IDENTITY_PRIVACY_KEY, databaseRequired) ? { identityPrivacyKey: env.PHOENIX_IDENTITY_PRIVACY_KEY!.trim() } : {}),
    ...(validateBase64UrlSecret("PHOENIX_IDENTITY_MFA_KEY", env.PHOENIX_IDENTITY_MFA_KEY, databaseRequired) ? { identityMfaKey: env.PHOENIX_IDENTITY_MFA_KEY!.trim() } : {}),
    identityRecentAuthenticationSeconds: boundedInt("PHOENIX_IDENTITY_RECENT_AUTH_SECONDS", env.PHOENIX_IDENTITY_RECENT_AUTH_SECONDS, 600, 60, 3_600),
    identityMfaTransactionTtlSeconds: boundedInt("PHOENIX_IDENTITY_MFA_TRANSACTION_TTL_SECONDS", env.PHOENIX_IDENTITY_MFA_TRANSACTION_TTL_SECONDS, 300, 60, 900),
    identityMfaMaxAttempts: boundedInt("PHOENIX_IDENTITY_MFA_MAX_ATTEMPTS", env.PHOENIX_IDENTITY_MFA_MAX_ATTEMPTS, 5, 1, 10),
    identityTotpEnrollmentTtlSeconds: boundedInt("PHOENIX_IDENTITY_TOTP_ENROLLMENT_TTL_SECONDS", env.PHOENIX_IDENTITY_TOTP_ENROLLMENT_TTL_SECONDS, 600, 120, 1_800),
    identityTotpIssuer: optionalValue(env.PHOENIX_IDENTITY_TOTP_ISSUER) ?? "Phoenix",
    identityWebauthnRpName: optionalValue(env.PHOENIX_IDENTITY_WEBAUTHN_RP_NAME) ?? "Phoenix",
    identityWebauthnRpId: webauthnRpId,
    identityWebauthnOrigins: webauthnOrigins,
    identityWebauthnChallengeTtlSeconds: boundedInt("PHOENIX_IDENTITY_WEBAUTHN_CHALLENGE_TTL_SECONDS", env.PHOENIX_IDENTITY_WEBAUTHN_CHALLENGE_TTL_SECONDS, 300, 60, 600),
    identityWebauthnTimeoutMs: boundedInt("PHOENIX_IDENTITY_WEBAUTHN_TIMEOUT_MS", env.PHOENIX_IDENTITY_WEBAUTHN_TIMEOUT_MS, 60_000, 15_000, 120_000),
    identityPasswordBreachMode: breachMode,
    identityPwnedPasswordsBaseUrl: normalizedUrl("PHOENIX_IDENTITY_PWNED_PASSWORDS_BASE_URL", optionalValue(env.PHOENIX_IDENTITY_PWNED_PASSWORDS_BASE_URL) ?? "https://api.pwnedpasswords.com", true),
    identityPwnedPasswordsTimeoutMs: boundedInt("PHOENIX_IDENTITY_PWNED_PASSWORDS_TIMEOUT_MS", env.PHOENIX_IDENTITY_PWNED_PASSWORDS_TIMEOUT_MS, 3_000, 500, 10_000),
    ...(providerUrl ? { notificationProviderUrl: providerUrl } : {}),
    ...(optionalValue(env.PHOENIX_NOTIFICATION_PROVIDER_TOKEN) ? { notificationProviderToken: env.PHOENIX_NOTIFICATION_PROVIDER_TOKEN!.trim() } : {}),
    ...(optionalValue(env.PHOENIX_NOTIFICATION_FROM_EMAIL) ? { notificationFromEmail: env.PHOENIX_NOTIFICATION_FROM_EMAIL!.trim() } : {}),
    notificationProviderTimeoutMs: boundedInt("PHOENIX_NOTIFICATION_PROVIDER_TIMEOUT_MS", env.PHOENIX_NOTIFICATION_PROVIDER_TIMEOUT_MS, 5_000, 500, 30_000),
    notificationWorkerBatchSize: boundedInt("PHOENIX_NOTIFICATION_WORKER_BATCH_SIZE", env.PHOENIX_NOTIFICATION_WORKER_BATCH_SIZE, 25, 1, 100),
    notificationWorkerMaxAttempts: boundedInt("PHOENIX_NOTIFICATION_WORKER_MAX_ATTEMPTS", env.PHOENIX_NOTIFICATION_WORKER_MAX_ATTEMPTS, 8, 1, 20),
    notificationWorkerPollMs: boundedInt("PHOENIX_NOTIFICATION_WORKER_POLL_MS", env.PHOENIX_NOTIFICATION_WORKER_POLL_MS, 5_000, 250, 60_000),
    notificationWorkerOnce: booleanValue("PHOENIX_NOTIFICATION_WORKER_ONCE", env.PHOENIX_NOTIFICATION_WORKER_ONCE, false),
    operationsEnabled,
    ...(operationsToken ? { operationsToken } : {}),
    operationsObservationWindowMinutes: boundedInt("PHOENIX_OPERATIONS_OBSERVATION_WINDOW_MINUTES", env.PHOENIX_OPERATIONS_OBSERVATION_WINDOW_MINUTES, 15, 1, 1440),
    operationsStaleLockSeconds: boundedInt("PHOENIX_OPERATIONS_STALE_LOCK_SECONDS", env.PHOENIX_OPERATIONS_STALE_LOCK_SECONDS, 300, 30, 3600),
    operationsMaxDeadLetters: boundedInt("PHOENIX_OPERATIONS_MAX_DEAD_LETTERS", env.PHOENIX_OPERATIONS_MAX_DEAD_LETTERS, 0, 0, 1000000),
    operationsMaxStaleLocks: boundedInt("PHOENIX_OPERATIONS_MAX_STALE_LOCKS", env.PHOENIX_OPERATIONS_MAX_STALE_LOCKS, 0, 0, 1000000),
    operationsMaxDeniedEvents: boundedInt("PHOENIX_OPERATIONS_MAX_DENIED_EVENTS", env.PHOENIX_OPERATIONS_MAX_DENIED_EVENTS, 100, 0, 1000000),
    passkeyValidationEnabled
  });
}
