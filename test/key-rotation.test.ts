import test from "node:test";
import assert from "node:assert/strict";
import { decryptMfaPayload, decryptNotificationPayload, encryptMfaPayload, encryptNotificationPayload } from "../src/identity/token-crypto.js";
import { rotateMfaPayload, rotateNotificationPayload, validateIdentityEncryptionRotation } from "../src/identity/key-rotation.js";

const oldKey = Buffer.alloc(32, 1).toString("base64url");
const newKey = Buffer.alloc(32, 2).toString("base64url");

test("identity payloads rotate without exposing plaintext", () => {
  const notification = encryptNotificationPayload({ kind: "security_notice", recipient: "redacted@example.com" }, oldKey);
  const rotatedNotification = rotateNotificationPayload(notification, oldKey, newKey);
  assert.deepEqual(decryptNotificationPayload(rotatedNotification, newKey), { kind: "security_notice", recipient: "redacted@example.com" });
  assert.throws(() => decryptNotificationPayload(rotatedNotification, oldKey));

  const totp = encryptMfaPayload({ secret: "ABCDEF" }, oldKey, "totp");
  const rotatedTotp = rotateMfaPayload(totp, oldKey, newKey, "totp");
  assert.deepEqual(decryptMfaPayload(rotatedTotp, newKey, "totp"), { secret: "ABCDEF" });
  assert.throws(() => decryptMfaPayload(rotatedTotp, oldKey, "totp"));
});


test("identity rotation keys must change and remain independent", () => {
  const thirdKey = Buffer.alloc(32, 3).toString("base64url");
  const fourthKey = Buffer.alloc(32, 4).toString("base64url");
  assert.deepEqual(validateIdentityEncryptionRotation({
    currentNotificationKey: oldKey,
    currentMfaKey: newKey,
    nextNotificationKey: thirdKey,
    nextMfaKey: fourthKey,
  }), {
    currentNotificationKey: oldKey,
    currentMfaKey: newKey,
    nextNotificationKey: thirdKey,
    nextMfaKey: fourthKey,
  });
  assert.throws(() => validateIdentityEncryptionRotation({
    currentNotificationKey: oldKey,
    currentMfaKey: newKey,
    nextNotificationKey: oldKey,
    nextMfaKey: fourthKey,
  }), /notification rotation key must change/u);
  assert.throws(() => validateIdentityEncryptionRotation({
    currentNotificationKey: oldKey,
    currentMfaKey: newKey,
    nextNotificationKey: thirdKey,
    nextMfaKey: thirdKey,
  }), /remain independent/u);
});
