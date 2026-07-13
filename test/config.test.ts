import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";
test("loads valid config",()=>{const c=loadConfig({PHOENIX_ENV:"test",PHOENIX_PORT:"3100"});assert.equal(c.port,3100);});
test("requires environment",()=>assert.throws(()=>loadConfig({}),/PHOENIX_ENV/));
test("requires database URL when database is required",()=>assert.throws(()=>loadConfig({PHOENIX_ENV:"test",PHOENIX_DATABASE_REQUIRED:"true"}),/DATABASE_URL/));
