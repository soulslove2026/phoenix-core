import fs from "node:fs/promises";
import pg from "pg";
import { loadConfig } from "../src/config.js";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required");

const sql = await fs.readFile(new URL("../migrations/001_identity.sql", import.meta.url), "utf8");
const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 1 });
try {
  await pool.query("begin");
  await pool.query(sql);
  await pool.query("commit");
  console.log("Identity migration applied.");
} catch (error) {
  await pool.query("rollback");
  throw error;
} finally {
  await pool.end();
}
