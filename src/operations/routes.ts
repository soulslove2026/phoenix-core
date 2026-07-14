import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityObservabilityRepository } from "./identity-observability.js";
import { prometheusMetrics, snapshotStatus } from "./identity-observability.js";
import { verifyOperationsBearer } from "./auth.js";

const unauthorized = { type: "object", additionalProperties: false, required: ["error", "requestId"], properties: { error: { type: "string" }, requestId: { type: "string" } } } as const;
const health = {
  type: "object", additionalProperties: false,
  required: ["status", "observedAt", "migrationCount", "users", "activeSessions", "passkeys", "activeTotpFactors", "pendingNotifications", "deadLetterNotifications", "staleNotificationLocks", "expiredWebAuthnChallenges", "deniedSecurityEvents", "requestId"],
  properties: {
    status: { type: "string", enum: ["healthy", "degraded"] }, observedAt: { type: "string", format: "date-time" }, migrationCount: { type: "integer" }, users: { type: "integer" }, activeSessions: { type: "integer" }, passkeys: { type: "integer" }, activeTotpFactors: { type: "integer" }, pendingNotifications: { type: "integer" }, deadLetterNotifications: { type: "integer" }, staleNotificationLocks: { type: "integer" }, expiredWebAuthnChallenges: { type: "integer" }, deniedSecurityEvents: { type: "integer" }, requestId: { type: "string" }
  }
} as const;

export const operationsRoutes: FastifyPluginAsync<Readonly<{
  repository: IdentityObservabilityRepository;
  token: string;
  observationWindowMinutes: number;
  staleLockSeconds: number;
  maxDeadLetters: number;
  maxStaleLocks: number;
  maxDeniedEvents: number;
}>> = async (app, options) => {
  const authorize = async (request: FastifyRequest, reply: FastifyReply) => {
    if (!verifyOperationsBearer(request.headers.authorization, options.token)) return reply.code(401).send({ error: "operations_unauthorized", requestId: request.id });
  };
  const collect = async () => {
    const snapshot = await options.repository.snapshot(options.observationWindowMinutes, options.staleLockSeconds);
    const status = snapshotStatus(snapshot, { maxDeadLetters: options.maxDeadLetters, maxStaleLocks: options.maxStaleLocks, maxDeniedEvents: options.maxDeniedEvents });
    return { snapshot, status } as const;
  };

  app.get("/identity/health", { preHandler: authorize, schema: { security: [{ bearerAuth: [] }], response: { 200: health, 401: unauthorized, 503: health } } }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { snapshot, status } = await collect();
    if (status === "degraded") reply.code(503);
    return { status, ...snapshot, requestId: request.id };
  });

  app.get("/identity/metrics", { preHandler: authorize, schema: { security: [{ bearerAuth: [] }], response: { 401: unauthorized } } }, async (_request: FastifyRequest, reply: FastifyReply) => {
    const { snapshot, status } = await collect();
    return reply.type("text/plain; version=0.0.4; charset=utf-8").send(prometheusMetrics(snapshot, status, app.config.version));
  });
};
