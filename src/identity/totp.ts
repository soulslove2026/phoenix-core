import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(input: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function base32Decode(value: string): Buffer {
  const normalized = value.toUpperCase().replace(/=+$/u, "").replace(/\s+/gu, "");
  let bits = 0;
  let accumulator = 0;
  const bytes: number[] = [];
  for (const character of normalized) {
    const index = ALPHABET.indexOf(character);
    if (index < 0) throw new Error("totp_secret_invalid");
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((accumulator >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(32));
}

export function totpCodeForStep(secret: string, step: number, digits = 6): string {
  if (!Number.isSafeInteger(step) || step < 0) throw new Error("totp_step_invalid");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24)
    | ((digest[offset + 1]! & 0xff) << 16)
    | ((digest[offset + 2]! & 0xff) << 8)
    | (digest[offset + 3]! & 0xff);
  return String(binary % (10 ** digits)).padStart(digits, "0");
}

export function verifyTotpCode(
  secret: string,
  code: string,
  options: Readonly<{ now?: number; periodSeconds?: number; window?: number; digits?: number }> = {}
): number | null {
  const periodSeconds = options.periodSeconds ?? 30;
  const digits = options.digits ?? 6;
  const window = options.window ?? 1;
  if (!new RegExp(`^\\d{${digits}}$`, "u").test(code)) return null;
  const currentStep = Math.floor((options.now ?? Date.now()) / 1000 / periodSeconds);
  const submitted = Buffer.from(code, "utf8");
  for (let delta = -window; delta <= window; delta += 1) {
    const step = currentStep + delta;
    if (step < 0) continue;
    const expected = Buffer.from(totpCodeForStep(secret, step, digits), "utf8");
    if (expected.length === submitted.length && timingSafeEqual(expected, submitted)) return step;
  }
  return null;
}

export function buildTotpUri(input: Readonly<{ secret: string; issuer: string; accountName: string }>): string {
  const label = `${input.issuer}:${input.accountName}`;
  const query = new URLSearchParams({
    secret: input.secret,
    issuer: input.issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30"
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${query.toString()}`;
}
