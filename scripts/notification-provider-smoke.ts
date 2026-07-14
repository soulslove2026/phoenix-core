import { randomUUID } from "node:crypto";
import { loadConfig } from "../src/config.js";
import { HttpNotificationProvider } from "../src/identity/notification-delivery.js";

const config = loadConfig();
if (!config.notificationProviderUrl || !config.notificationProviderToken || !config.notificationFromEmail) throw new Error("notification provider configuration is required");
const recipient = process.env.PHOENIX_NOTIFICATION_SMOKE_TO?.trim();
if (!recipient) throw new Error("PHOENIX_NOTIFICATION_SMOKE_TO is required");
if (process.env.PHOENIX_NOTIFICATION_SMOKE_CONFIRM !== "SEND_TEST_NOTIFICATION") throw new Error("PHOENIX_NOTIFICATION_SMOKE_CONFIRM must equal SEND_TEST_NOTIFICATION");
const provider = new HttpNotificationProvider({ endpoint: config.notificationProviderUrl, bearerToken: config.notificationProviderToken, timeoutMs: config.notificationProviderTimeoutMs });
const idempotencyKey = randomUUID();
await provider.deliver({ idempotencyKey, from: config.notificationFromEmail, to: recipient, template: "phoenix.identity.security_notice", variables: { event: "notification_provider_smoke_test", occurredAt: new Date().toISOString() } });
console.log(JSON.stringify({ event: "notification.provider_smoke", outcome: "success", idempotencyKey }));
