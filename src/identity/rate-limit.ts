export type RateLimitDecision = Readonly<{
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}>;

type Bucket = { count: number; resetAtMs: number };

export class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly windowMs: number) {
    if (!Number.isInteger(windowMs) || windowMs <= 0) {
      throw new Error("windowMs must be a positive integer");
    }
  }

  consume(key: string, maximum: number, nowMs = Date.now()): RateLimitDecision {
    if (!Number.isInteger(maximum) || maximum <= 0) {
      throw new Error("maximum must be a positive integer");
    }

    if (this.buckets.size >= 10_000) {
      this.prune(nowMs);
      while (this.buckets.size >= 10_000) {
        const oldestKey = this.buckets.keys().next().value as string | undefined;
        if (!oldestKey) break;
        this.buckets.delete(oldestKey);
      }
    }
    const existing = this.buckets.get(key);
    const bucket = !existing || existing.resetAtMs <= nowMs
      ? { count: 0, resetAtMs: nowMs + this.windowMs }
      : existing;

    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAtMs - nowMs) / 1_000));
    if (bucket.count >= maximum) {
      this.buckets.set(key, bucket);
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }

    bucket.count += 1;
    this.buckets.set(key, bucket);
    return {
      allowed: true,
      remaining: Math.max(0, maximum - bucket.count),
      retryAfterSeconds
    };
  }

  private prune(nowMs: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAtMs <= nowMs) this.buckets.delete(key);
    }
  }
}
