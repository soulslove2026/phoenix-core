import fp from "fastify-plugin";
import pg from "pg";
import type { AppConfig } from "../config.js";

declare module "fastify" {
  interface FastifyInstance {
    database: { available: boolean; query: pg.Pool["query"] | null; pool: pg.Pool | null };
  }
}

export const databasePlugin = fp<{ config: AppConfig }>(async (app, options) => {
  const { config } = options;
  if (!config.databaseUrl) {
    app.decorate("database", { available: false, query: null, pool: null });
    return;
  }
  const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 5, application_name: config.serviceName });
  try {
    await pool.query("select 1");
    app.decorate("database", { available: true, query: pool.query.bind(pool), pool });
  } catch (error) {
    await pool.end();
    if (config.databaseRequired) throw error;
    app.log.warn({ err: error }, "database unavailable; continuing in optional mode");
    app.decorate("database", { available: false, query: null, pool: null });
    return;
  }
  app.addHook("onClose", async () => { await pool.end(); });
});
