import { timingSafeEqual } from "node:crypto";
import { decryptMfaPayload, decryptNotificationPayload, encryptMfaPayload, encryptNotificationPayload, type EncryptedPayload } from "./token-crypto.js";

export function rotateNotificationPayload(payload: EncryptedPayload, oldKey: string, newKey: string): EncryptedPayload {
  return encryptNotificationPayload(decryptNotificationPayload<unknown>(payload, oldKey), newKey);
}

export function rotateMfaPayload(payload: EncryptedPayload, oldKey: string, newKey: string, purpose: "totp" | "webauthn"): EncryptedPayload {
  return encryptMfaPayload(decryptMfaPayload<unknown>(payload, oldKey, purpose), newKey, purpose);
}

function validatedKey(name: string, value: string | undefined): Readonly<{ encoded: string; bytes: Buffer }> {
  const candidate = value?.trim();
  if (!candidate) throw new Error(`${name} is required`);
  if (!/^[A-Za-z0-9_-]+$/u.test(candidate)) throw new Error(`${name} must use base64url encoding`);
  const decoded = Buffer.from(candidate, "base64url");
  if (decoded.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
  return { encoded: candidate, bytes: decoded.subarray(0, 32) };
}

function sameEffectiveKey(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export function validateIdentityEncryptionRotation(input: Readonly<{
  currentNotificationKey: string | undefined;
  currentMfaKey: string | undefined;
  nextNotificationKey: string | undefined;
  nextMfaKey: string | undefined;
}>): Readonly<{
  currentNotificationKey: string;
  currentMfaKey: string;
  nextNotificationKey: string;
  nextMfaKey: string;
}> {
  const currentNotification = validatedKey("PHOENIX_IDENTITY_NOTIFICATION_KEY", input.currentNotificationKey);
  const currentMfa = validatedKey("PHOENIX_IDENTITY_MFA_KEY", input.currentMfaKey);
  const nextNotification = validatedKey("PHOENIX_IDENTITY_NOTIFICATION_KEY_NEW", input.nextNotificationKey);
  const nextMfa = validatedKey("PHOENIX_IDENTITY_MFA_KEY_NEW", input.nextMfaKey);
  if (sameEffectiveKey(currentNotification.bytes, nextNotification.bytes)) throw new Error("notification rotation key must change");
  if (sameEffectiveKey(currentMfa.bytes, nextMfa.bytes)) throw new Error("MFA rotation key must change");
  if (sameEffectiveKey(nextNotification.bytes, nextMfa.bytes)) throw new Error("notification and MFA rotation keys must remain independent");
  return {
    currentNotificationKey: currentNotification.encoded,
    currentMfaKey: currentMfa.encoded,
    nextNotificationKey: nextNotification.encoded,
    nextMfaKey: nextMfa.encoded,
  };
}
