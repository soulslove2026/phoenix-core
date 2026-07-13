import test from "node:test";
import assert from "node:assert/strict";
import { FixedWindowRateLimiter } from "../src/identity/rate-limit.js";

test("blocks requests after the configured limit and resets after the window", () => {
  const limiter = new FixedWindowRateLimiter(1_000);
  assert.equal(limiter.consume("login:ip", 2, 0).allowed, true);
  assert.equal(limiter.consume("login:ip", 2, 100).allowed, true);
  const blocked = limiter.consume("login:ip", 2, 200);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 1);
  assert.equal(limiter.consume("login:ip", 2, 1_001).allowed, true);
});
