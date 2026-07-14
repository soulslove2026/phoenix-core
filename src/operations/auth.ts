import { createHash, timingSafeEqual } from "node:crypto";

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function verifyOperationsBearer(authorization: string | undefined, expectedToken: string): boolean {
  if (!authorization?.startsWith("Bearer ")) return false;
  const candidate = authorization.slice(7).trim();
  if (!candidate) return false;
  return timingSafeEqual(digest(candidate), digest(expectedToken));
}
