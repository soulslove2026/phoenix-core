import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { HibpPasswordBreachChecker, PasswordBreachServiceUnavailableError } from "../src/identity/password-breach.js";

test("Pwned Passwords range check uses k-anonymity and padding",async()=>{
  const password="correct horse battery staple";
  const hash=createHash("sha1").update(password).digest("hex").toUpperCase();
  let requested="";let padding="";let agent="";
  const checker=new HibpPasswordBreachChecker({mode:"required",baseUrl:"https://api.pwnedpasswords.com",timeoutMs:1000,userAgent:"Phoenix-Test",fetchImpl:async(input,init)=>{requested=String(input);padding=new Headers(init?.headers).get("add-padding")??"";agent=new Headers(init?.headers).get("user-agent")??"";return new Response(`${hash.slice(5)}:42\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0`,{status:200});}});
  const result=await checker.check(password);
  assert.equal(requested.endsWith(`/range/${hash.slice(0,5)}`),true);
  assert.equal(padding,"true");assert.equal(agent,"Phoenix-Test");assert.deepEqual(result,{compromised:true,occurrenceCount:42,available:true});
});

test("required breach screening fails closed",async()=>{
  const checker=new HibpPasswordBreachChecker({mode:"required",baseUrl:"https://api.pwnedpasswords.com",timeoutMs:1000,userAgent:"Phoenix-Test",fetchImpl:async()=>{throw new Error("offline");}});
  await assert.rejects(()=>checker.check("a sufficiently long password"),PasswordBreachServiceUnavailableError);
});
