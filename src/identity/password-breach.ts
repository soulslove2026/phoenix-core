import { createHash } from "node:crypto";

export type PasswordBreachResult = Readonly<{ compromised: boolean; occurrenceCount: number; available: boolean }>;
export interface PasswordBreachChecker { check(password: string): Promise<PasswordBreachResult>; }
export class PasswordBreachServiceUnavailableError extends Error { constructor(){super("password_breach_service_unavailable");} }

export class HibpPasswordBreachChecker implements PasswordBreachChecker {
  constructor(private readonly options: Readonly<{
    mode: "required" | "best_effort" | "disabled";
    baseUrl: string;
    timeoutMs: number;
    userAgent: string;
    fetchImpl?: typeof fetch;
  }>) {}

  async check(password: string): Promise<PasswordBreachResult> {
    if (this.options.mode === "disabled") return { compromised: false, occurrenceCount: 0, available: false };
    const hash = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const fetchImpl = this.options.fetchImpl ?? fetch;
    try {
      const response = await fetchImpl(`${this.options.baseUrl.replace(/\/$/u, "")}/range/${prefix}`, {
        method: "GET",
        headers: { "user-agent": this.options.userAgent, "add-padding": "true", accept: "text/plain" },
        signal: AbortSignal.timeout(this.options.timeoutMs),
        redirect: "error"
      });
      if (!response.ok) throw new Error(`pwned_passwords_http_${response.status}`);
      const body = await response.text();
      let count = 0;
      for (const line of body.split(/\r?\n/u)) {
        const [candidate, rawCount] = line.trim().split(":");
        if (candidate === suffix) { count = Number(rawCount ?? "0"); break; }
      }
      return { compromised: count > 0, occurrenceCount: Number.isFinite(count) ? count : 0, available: true };
    } catch (error) {
      if (this.options.mode === "required") throw new PasswordBreachServiceUnavailableError();
      return { compromised: false, occurrenceCount: 0, available: false };
    }
  }
}

export const noOpPasswordBreachChecker: PasswordBreachChecker = {
  async check(){ return { compromised: false, occurrenceCount: 0, available: false }; }
};
