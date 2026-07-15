import { smokeStaging } from "../src/deployment/staging-assurance.js";

const baseUrl = process.env.PHOENIX_STAGING_BASE_URL?.trim();
if (!baseUrl) throw new Error("PHOENIX_STAGING_BASE_URL is required");
const expectPasskeyHarness = process.env.PHOENIX_STAGING_EXPECT_PASSKEY_HARNESS === "true";
const operationsToken = process.env.PHOENIX_OPERATIONS_TOKEN?.trim();
const report = await smokeStaging(baseUrl, {
  expectPasskeyHarness,
  ...(operationsToken ? { operationsToken } : {})
});
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
