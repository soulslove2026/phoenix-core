import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

const NOTIFICATION_AAD = Buffer.from("phoenix-identity-notification-v1", "utf8");

function secretBytes(secret: string): Buffer {
  const decoded = Buffer.from(secret, "base64url");
  if (decoded.length < 32) throw new Error("secret must decode to at least 32 bytes");
  return decoded;
}

export function createOpaqueToken(prefix: "phx_s" | "phx_v" | "phx_r"): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

export function hashOpaqueToken(token: string, pepper: string): string {
  return createHmac("sha256", secretBytes(pepper)).update(token, "utf8").digest("hex");
}

export function privacyHash(value: string, privacyKey: string): string {
  return createHmac("sha256", secretBytes(privacyKey)).update(value, "utf8").digest("hex");
}

export type EncryptedPayload = Readonly<{ ciphertext: string; iv: string; authTag: string }>;

export function encryptNotificationPayload(payload: unknown, key: string): EncryptedPayload {
  const encryptionKey = secretBytes(key).subarray(0, 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  cipher.setAAD(NOTIFICATION_AAD);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64url"),
    iv: iv.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url")
  };
}

export function decryptNotificationPayload<T>(payload: EncryptedPayload, key: string): T {
  const encryptionKey = secretBytes(key).subarray(0, 32);
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(payload.iv, "base64url"));
  decipher.setAAD(NOTIFICATION_AAD);
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64url")),
    decipher.final()
  ]);
  return JSON.parse(plaintext.toString("utf8")) as T;
}
