export type AppConfig = Readonly<{
  serviceName: string;
  version: string;
  environment: string;
  host: string;
  port: number;
  logLevel: "debug" | "info" | "warn" | "error";
  databaseRequired: boolean;
  databaseUrl?: string;
}>;

function positiveInt(name: string, value: string | undefined, fallback: number): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const environment = env.PHOENIX_ENV?.trim();
  if (!environment) throw new Error("PHOENIX_ENV is required");
  const port = positiveInt("PHOENIX_PORT", env.PHOENIX_PORT, 3000);
  if (port > 65535) throw new Error("PHOENIX_PORT must be between 1 and 65535");
  const logLevel = (env.PHOENIX_LOG_LEVEL ?? "info") as AppConfig["logLevel"];
  if (!["debug","info","warn","error"].includes(logLevel)) throw new Error("invalid PHOENIX_LOG_LEVEL");
  const databaseRequired = env.PHOENIX_DATABASE_REQUIRED === "true";
  const databaseUrl = env.PHOENIX_DATABASE_URL?.trim();
  if (databaseRequired && !databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required when database is required");
  return Object.freeze({serviceName:"phoenix-core",version:"3.2.0",environment,host:env.PHOENIX_HOST?.trim()||"127.0.0.1",port,logLevel,databaseRequired,...(databaseUrl?{databaseUrl}:{})});
}
