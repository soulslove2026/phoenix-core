import { randomUUID } from "node:crypto";
import type { PhaseBIdentityRepository } from "./phase-b-repository.js";
import { decryptNotificationPayload } from "./token-crypto.js";

export type NotificationPayload = Readonly<{
  kind: "email_verification" | "password_reset" | "security_notice";
  recipient: string;
  token?: string;
  expiresAt?: string;
  event?: string;
  occurredAt?: string;
}>;

export interface NotificationProvider {
  deliver(input: Readonly<{ idempotencyKey: string; from: string; to: string; template: string; variables: Record<string, unknown> }>): Promise<void>;
}

export class HttpNotificationProvider implements NotificationProvider {
  constructor(private readonly options: Readonly<{ endpoint: string; bearerToken: string; timeoutMs: number; fetchImpl?: typeof fetch }>) {
    const url = new URL(options.endpoint);
    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") throw new Error("notification_provider_https_required");
  }
  async deliver(input: Readonly<{ idempotencyKey: string; from: string; to: string; template: string; variables: Record<string, unknown> }>): Promise<void> {
    const response = await (this.options.fetchImpl ?? fetch)(this.options.endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${this.options.bearerToken}`, "content-type": "application/json", "idempotency-key": input.idempotencyKey },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(this.options.timeoutMs),
      redirect: "error"
    });
    if (!response.ok) throw new Error(`notification_provider_http_${response.status}`);
  }
}

function errorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : "unknown";
  return /^[a-z0-9_:-]{1,80}$/iu.test(message) ? message.slice(0,80) : "delivery_failed";
}

export class NotificationDeliveryService {
  constructor(private readonly options: Readonly<{
    repository: PhaseBIdentityRepository;
    provider: NotificationProvider;
    notificationKey: string;
    from: string;
    batchSize: number;
    maxAttempts: number;
  }>) {}

  async runBatch(): Promise<{ claimed: number; sent: number; failed: number }> {
    const lockToken = randomUUID();
    const rows = await this.options.repository.claimNotifications(this.options.batchSize, lockToken);
    let sent = 0;
    let failed = 0;
    for (const row of rows) {
      try {
        const payload = decryptNotificationPayload<NotificationPayload>({ ciphertext: row.ciphertext, iv: row.iv, authTag: row.authTag }, this.options.notificationKey);
        if (payload.kind !== row.kind || !payload.recipient) throw new Error("notification_payload_invalid");
        const { recipient, kind, ...variables } = payload;
        await this.options.provider.deliver({ idempotencyKey: row.id, from: this.options.from, to: recipient, template: `phoenix.identity.${kind}`, variables });
        await this.options.repository.markNotificationSent(row.id, row.lockToken);
        sent += 1;
      } catch (error) {
        const deadLetter = row.attempts >= this.options.maxAttempts;
        const retrySeconds = Math.min(3600, 2 ** Math.min(row.attempts, 10) * 15);
        await this.options.repository.markNotificationFailed(row.id, row.lockToken, errorCode(error), new Date(Date.now()+retrySeconds*1000).toISOString(), deadLetter);
        failed += 1;
      }
    }
    return { claimed: rows.length, sent, failed };
  }
}
