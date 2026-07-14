import pg from "pg";
import { loadConfig } from "../src/config.js";
import { HttpNotificationProvider, NotificationDeliveryService } from "../src/identity/notification-delivery.js";
import { PostgresPhaseBIdentityRepository } from "../src/identity/phase-b-repository.js";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("PHOENIX_DATABASE_URL is required");
if (!config.identityNotificationKey) throw new Error("PHOENIX_IDENTITY_NOTIFICATION_KEY is required");
if (!config.notificationProviderUrl || !config.notificationProviderToken || !config.notificationFromEmail) throw new Error("notification provider configuration is required");

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 3, application_name: `${config.serviceName}-notification-worker` });
const service = new NotificationDeliveryService({
  repository: new PostgresPhaseBIdentityRepository(pool),
  provider: new HttpNotificationProvider({ endpoint: config.notificationProviderUrl, bearerToken: config.notificationProviderToken, timeoutMs: config.notificationProviderTimeoutMs }),
  notificationKey: config.identityNotificationKey,
  from: config.notificationFromEmail,
  batchSize: config.notificationWorkerBatchSize,
  maxAttempts: config.notificationWorkerMaxAttempts
});

let stopping = false;
process.once("SIGTERM",()=>{stopping=true;});
process.once("SIGINT",()=>{stopping=true;});
try {
  do {
    const result = await service.runBatch();
    console.log(JSON.stringify({ event:"notification.batch", ...result }));
    if (config.notificationWorkerOnce) break;
    await new Promise(resolve=>setTimeout(resolve, result.claimed === 0 ? config.notificationWorkerPollMs : 50));
  } while (!stopping);
} finally {
  await pool.end();
}
