import type { Pool } from "pg";

export type RateLimitDecision = Readonly<{ allowed: boolean; remaining: number; retryAfterSeconds: number }>;
export interface IdentityRateLimiter { consume(key: string, maximum: number, windowSeconds: number): Promise<RateLimitDecision> }

export class PostgresIdentityRateLimiter implements IdentityRateLimiter {
  private calls = 0;
  constructor(private readonly pool: Pool) {}

  async consume(key: string, maximum: number, windowSeconds: number): Promise<RateLimitDecision> {
    if (!Number.isInteger(maximum) || maximum <= 0) throw new Error("maximum must be positive");
    if (!Number.isInteger(windowSeconds) || windowSeconds <= 0) throw new Error("windowSeconds must be positive");

    const result = await this.pool.query<{ count: number; reset_at: Date }>(
      `insert into identity_rate_limits (bucket_key, count, reset_at)
       values ($1, 1, now() + make_interval(secs => $2))
       on conflict (bucket_key) do update set
         count = case when identity_rate_limits.reset_at <= now() then 1 else least(identity_rate_limits.count + 1, $3 + 1) end,
         reset_at = case when identity_rate_limits.reset_at <= now() then now() + make_interval(secs => $2) else identity_rate_limits.reset_at end
       returning count, reset_at`,
      [key, windowSeconds, maximum]
    );
    const row = result.rows[0];
    if (!row) throw new Error("rate_limit_update_returned_no_row");
    this.calls += 1;
    if (this.calls % 500 === 0) void this.pool.query("delete from identity_rate_limits where reset_at < now() - interval '1 day'").catch(() => undefined);
    const retryAfterSeconds = Math.max(1, Math.ceil((new Date(row.reset_at).getTime() - Date.now()) / 1_000));
    return { allowed: row.count <= maximum, remaining: Math.max(0, maximum - row.count), retryAfterSeconds };
  }
}
