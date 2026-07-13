import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
function derive(password: string, salt: Buffer, keyLength: number, options?: { N: number; r: number; p: number; maxmem: number }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const callback = (error: Error | null, derivedKey: Buffer) => error ? reject(error) : resolve(derivedKey);
    if (options) scryptCallback(password, salt, keyLength, options, callback);
    else scryptCallback(password, salt, keyLength, callback);
  });
}
const KEY_LENGTH = 64;
const N = 131_072;
const R = 8;
const P = 1;
const MAXMEM = 256 * 1024 * 1024;
const COMMON_PASSWORDS = new Set([
  "password", "password123", "123456789", "1234567890", "qwerty123", "letmein", "welcome",
  "admin", "administrator", "iloveyou", "phoenix", "phoenix123", "changeme"
]);

export type PasswordContext = Readonly<{ email?: string; displayName?: string }>;
export type PasswordVerification = Readonly<{ valid: boolean; needsRehash: boolean }>;
export type PasswordHasher = Readonly<{
  hash(password: string, context?: PasswordContext): Promise<string>;
  verify(password: string, encoded: string): Promise<PasswordVerification>;
}>;

export const passwordHasher: PasswordHasher = {
  hash: hashPassword,
  verify: verifyPassword
};

export function normalizePassword(password: string): string {
  return password.normalize("NFC");
}

export function validatePassword(password: string, context: PasswordContext = {}): string {
  const normalized = normalizePassword(password);
  const length = Array.from(normalized).length;
  if (length < 15 || length > 128) throw new Error("password_length_invalid");
  if(/[\u0000-\u001F\u007F]/u.test(normalized)) throw new Error("password_control_character_invalid");

  const lower = normalized.toLocaleLowerCase("en-US");
  const contextWords = new Set<string>();
  const localPart = context.email?.split("@")[0]?.toLocaleLowerCase("en-US").replace(/[^a-z0-9]/g, "");
  const display = context.displayName?.toLocaleLowerCase("en-US").replace(/[^a-z0-9]/g, "");
  if (localPart && localPart.length >= 4) contextWords.add(localPart);
  if (display && display.length >= 4) contextWords.add(display);
  const compact = lower.replace(/[^a-z0-9]/g, "");
  const contextDerived = [...contextWords].some((word) => compact === word || (compact.startsWith(word) && /^\d+$/.test(compact.slice(word.length))));
  if (COMMON_PASSWORDS.has(lower) || contextDerived) throw new Error("password_blocked");
  return normalized;
}

export async function hashPassword(password: string, context: PasswordContext = {}): Promise<string> {
  const normalized = validatePassword(password, context);
  const salt = randomBytes(16);
  const derived = await derive(normalized, salt, KEY_LENGTH, { N, r: R, p: P, maxmem: MAXMEM });
  return `scrypt$v2$${N}$${R}$${P}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

export async function verifyPassword(password: string, encoded: string): Promise<PasswordVerification> {
  try {
    const normalized = normalizePassword(password);
    const parts = encoded.split("$");
    if (parts[0] !== "scrypt") return { valid: false, needsRehash: false };

    if (parts[1] === "v2" && parts.length === 7) {
      const n = Number(parts[2]); const r = Number(parts[3]); const p = Number(parts[4]);
      const salt = Buffer.from(parts[5]!, "base64url");
      const expected = Buffer.from(parts[6]!, "base64url");
      if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p) || expected.length !== KEY_LENGTH) return { valid: false, needsRehash: false };
      const actual = await derive(normalized, salt, expected.length, { N: n, r, p, maxmem: MAXMEM });
      const valid = actual.length === expected.length && timingSafeEqual(expected, actual);
      return { valid, needsRehash: valid && (n !== N || r !== R || p !== P) };
    }

    // Legacy v3.3.x format: scrypt$salt$hash.
    if (parts.length === 3 && parts[1] && parts[2]) {
      const salt = Buffer.from(parts[1], "base64url");
      const expected = Buffer.from(parts[2], "base64url");
      const actual = await derive(normalized, salt, expected.length);
      const valid = actual.length === expected.length && timingSafeEqual(expected, actual);
      return { valid, needsRehash: valid };
    }
  } catch {
    return { valid: false, needsRehash: false };
  }
  return { valid: false, needsRehash: false };
}
