import test from "node:test";
import assert from "node:assert/strict";
import { buildTotpUri, generateTotpSecret, totpCodeForStep, verifyTotpCode } from "../src/identity/totp.js";

test("RFC 6238 SHA-1 vector is reproduced",()=>{
  const secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(totpCodeForStep(secret,1,8),"94287082");
});

test("TOTP verification accepts limited clock skew and rejects malformed codes",()=>{
  const secret=generateTotpSecret();
  const now=1_800_000_000_000;
  const step=Math.floor(now/1000/30);
  const code=totpCodeForStep(secret,step);
  assert.equal(verifyTotpCode(secret,code,{now}),step);
  assert.equal(verifyTotpCode(secret,"12345x",{now}),null);
  assert.match(buildTotpUri({secret,issuer:"Phoenix",accountName:"u@example.com"}),/^otpauth:\/\/totp\//u);
});
