import test from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
const config=loadConfig({PHOENIX_ENV:"test",PHOENIX_LOG_LEVEL:"error"});
test("health is schema-valid",async()=>{const app=await buildApp(config);const r=await app.inject({method:"GET",url:"/v1/system/health"});assert.equal(r.statusCode,200);assert.equal(r.json().status,"healthy");await app.close();});
test("ready succeeds in optional database mode",async()=>{const app=await buildApp(config);const r=await app.inject({method:"GET",url:"/v1/system/ready"});assert.equal(r.statusCode,200);assert.equal(r.json().database,"unavailable");await app.close();});
test("openapi document is generated",async()=>{const app=await buildApp(config);await app.ready();const doc=app.swagger();assert.equal(doc.info.version,"3.2.0");await app.close();});
