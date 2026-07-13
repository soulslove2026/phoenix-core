import test from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";

const config = loadConfig({ PHOENIX_ENV: "test", PHOENIX_LOG_LEVEL: "error" });

test("health is schema-valid", async () => {
  const app = await buildApp(config);
  const response = await app.inject({ method: "GET", url: "/v1/system/health" });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().status, "healthy");
  assert.equal(response.json().version, config.version);
  await app.close();
});

test("ready succeeds in optional database mode", async () => {
  const app = await buildApp(config);
  const response = await app.inject({ method: "GET", url: "/v1/system/ready" });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().database, "unavailable");
  assert.equal(response.json().version, config.version);
  await app.close();
});

test("OpenAPI document uses the repository version and declares bearer authentication", async () => {
  const app = await buildApp(config);
  await app.ready();
  const document = app.swagger() as unknown as {
    info: { version: string };
    components?: { securitySchemes?: Record<string, { type?: string }> };
  };
  assert.equal(document.info.version, config.version);
  assert.equal(document.components?.securitySchemes?.bearerAuth?.type, "http");
  await app.close();
});
