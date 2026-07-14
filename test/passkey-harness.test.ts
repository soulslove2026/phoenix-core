import test from "node:test";
import assert from "node:assert/strict";
import Fastify from "fastify";
import { passkeyValidationHarness } from "../src/validation/passkey-harness.js";

test("passkey validation harness serves same-origin assets without embedded secrets", async () => {
  const app = Fastify();
  await app.register(passkeyValidationHarness, { prefix: "/passkey-validation" });
  const page = await app.inject({ method: "GET", url: "/passkey-validation/" });
  assert.equal(page.statusCode, 200);
  assert.match(page.body, /Phoenix Passkey Validation/u);
  assert.match(page.headers["x-robots-tag"] ?? "", /noindex/u);
  const script = await app.inject({ method: "GET", url: "/passkey-validation/app.js" });
  assert.equal(script.statusCode, 200);
  assert.match(script.body, /navigator\.credentials\.create/u);
  assert.match(script.body, /navigator\.credentials\.get/u);
  assert.doesNotMatch(script.body, /localStorage|sessionStorage/u);
  await app.close();
});
