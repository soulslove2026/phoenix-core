import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

function secretBytes(secret: string): Buffer {
  const decoded = Buffer.from(secret, "base64url");
  if (decoded.length < 32) throw new Error("secret must decode to at least 32 bytes");
  return decoded;
}

export type EncryptedPayload = Readonly<{ ciphertext: string; iv: string; authTag: string }>;

function encryptPayload(payload: unknown, key: string, purpose: string): EncryptedPayload {
  const encryptionKey = secretBytes(key).subarray(0, 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  cipher.setAAD(Buffer.from(`phoenix-identity-${purpose}-v1`, "utf8"));
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext: ciphertext.toString("base64url"), iv: iv.toString("base64url"), authTag: cipher.getAuthTag().toString("base64url") };
}

function decryptPayload<T>(payload: EncryptedPayload, key: string, purpose: string): T {
  const encryptionKey = secretBytes(key).subarray(0, 32);
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(payload.iv, "base64url"));
  decipher.setAAD(Buffer.from(`phoenix-identity-${purpose}-v1`, "utf8"));
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64url"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, "base64url")), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8")) as T;
}

export function createOpaqueToken(prefix: "phx_s" | "phx_v" | "phx_r" | "phx_m"): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

export function hashOpaqueToken(token: string, pepper: string): string {
  return createHmac("sha256", secretBytes(pepper)).update(token, "utf8").digest("hex");
}

export function privacyHash(value: string, privacyKey: string): string {
  return createHmac("sha256", secretBytes(privacyKey)).update(value, "utf8").digest("hex");
}

export function encryptNotificationPayload(payload: unknown, key: string): EncryptedPayload { return encryptPayload(payload, key, "notification"); }
export function decryptNotificationPayload<T>(payload: EncryptedPayload, key: string): T { return decryptPayload<T>(payload, key, "notification"); }
export function encryptMfaPayload(payload: unknown, key: string, purpose: "totp" | "webauthn"): EncryptedPayload { return encryptPayload(payload, key, purpose); }
export function decryptMfaPayload<T>(payload: EncryptedPayload, key: string, purpose: "totp" | "webauthn"): T { return decryptPayload<T>(payload, key, purpose); }
