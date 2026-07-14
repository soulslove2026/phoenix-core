import test from "node:test";
import assert from "node:assert/strict";
import { PasskeyManager } from "../src/identity/passkeys.js";
import type { UserRecord } from "../src/identity/types.js";

const user:UserRecord={id:"00000000-0000-4000-8000-000000000001",email:"u@example.com",displayName:"User",passwordHash:"x",status:"active",emailVerifiedAt:new Date().toISOString(),passwordChangedAt:new Date().toISOString(),authVersion:1,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};

test("passkey options require discoverable credentials and user verification",async()=>{
  const manager=new PasskeyManager({rpName:"Phoenix",rpId:"localhost",origins:["http://localhost:3000"],timeoutMs:60000});
  const registration=await manager.registrationOptions(user,[]);
  assert.equal(registration.rp.id,"localhost");
  assert.equal(registration.authenticatorSelection?.residentKey,"required");
  assert.equal(registration.authenticatorSelection?.userVerification,"required");
  const authentication=await manager.authenticationOptions();
  assert.equal(authentication.rpId,"localhost");
  assert.equal(authentication.userVerification,"required");
});
