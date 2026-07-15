import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";
const secret=Buffer.alloc(32,1).toString("base64url");

test("database identity config requires separate strong secrets",()=>{
  assert.throws(()=>loadConfig({PHOENIX_ENV:"test",PHOENIX_DATABASE_REQUIRED:"true",PHOENIX_DATABASE_URL:"postgres://x"}));
  const config=loadConfig({PHOENIX_ENV:"test",PHOENIX_DATABASE_REQUIRED:"true",PHOENIX_DATABASE_URL:"postgres://x",PHOENIX_IDENTITY_TOKEN_PEPPER:secret,PHOENIX_IDENTITY_NOTIFICATION_KEY:secret,PHOENIX_IDENTITY_PRIVACY_KEY:secret,PHOENIX_IDENTITY_MFA_KEY:secret});
  assert.equal(config.version,"3.7.1");
  assert.equal(config.identitySessionIdleTtlSeconds,43200);
  assert.equal(config.identityWebauthnRpId,"localhost");
});

test("production requires explicit WebAuthn relying-party configuration",()=>assert.throws(()=>loadConfig({PHOENIX_ENV:"production"})));
test("idle TTL cannot exceed absolute TTL",()=>assert.throws(()=>loadConfig({PHOENIX_ENV:"test",PHOENIX_IDENTITY_SESSION_IDLE_TTL_SECONDS:"1000",PHOENIX_IDENTITY_SESSION_ABSOLUTE_TTL_SECONDS:"900"})));

test("operations require a strong dedicated token",()=>{
  assert.throws(()=>loadConfig({PHOENIX_ENV:"test",PHOENIX_OPERATIONS_ENABLED:"true"}));
  const config=loadConfig({PHOENIX_ENV:"test",PHOENIX_OPERATIONS_ENABLED:"true",PHOENIX_OPERATIONS_TOKEN:secret});
  assert.equal(config.operationsEnabled,true);
});

test("passkey validation harness is forbidden in production",()=>assert.throws(()=>loadConfig({PHOENIX_ENV:"production",PHOENIX_IDENTITY_WEBAUTHN_RP_ID:"example.com",PHOENIX_IDENTITY_WEBAUTHN_ORIGINS:"https://example.com",PHOENIX_PASSKEY_VALIDATION_ENABLED:"true"})));
