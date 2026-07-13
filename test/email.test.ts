import test from "node:test";
import assert from "node:assert/strict";
import { normalizeAndValidateEmail } from "../src/identity/email.js";

test("normalizes a valid Internet email address", () => {
  assert.equal(normalizeAndValidateEmail(" User.Name+tag@Example.COM "), "user.name+tag@example.com");
});

for (const invalid of [
  "plain-address",
  "a@@example.com",
  ".a@example.com",
  "a..b@example.com",
  "a@example",
  "a@-example.com",
  "a@example-.com",
  "a @example.com"
]) {
  test(`rejects invalid email: ${invalid}`, () => {
    assert.throws(() => normalizeAndValidateEmail(invalid), /email_invalid/);
  });
}
