import type { FastifyPluginAsync } from "fastify";

const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["status", "service", "version", "environment", "requestId"],
  properties: {
    status: { type: "string" },
    service: { type: "string" },
    version: { type: "string" },
    environment: { type: "string" },
    deploymentId: { type: "string" },
    region: { type: "string" },
    buildCommit: { type: "string" },
    requestId: { type: "string" },
    database: { type: "string" }
  }
} as const;

function deploymentIdentity(config: {
  environment: string;
  deploymentId?: string;
  region?: string;
  buildCommit?: string;
}) {
  return {
    environment: config.environment,
    ...(config.deploymentId ? { deploymentId: config.deploymentId } : {}),
    ...(config.region ? { region: config.region } : {}),
    ...(config.buildCommit ? { buildCommit: config.buildCommit } : {})
  };
}

export const systemRoutes: FastifyPluginAsync = async (app) => {
  app.get("/health", { schema: { response: { 200: responseSchema } } }, async (request) => ({
    status: "healthy",
    service: app.config.serviceName,
    version: app.config.version,
    ...deploymentIdentity(app.config),
    requestId: request.id
  }));

  app.get("/ready", { schema: { response: { 200: responseSchema, 503: responseSchema } } }, async (request, reply) => {
    const required = app.config.databaseRequired;
    const available = app.database.available;
    const ready = !required || available;
    if (!ready) reply.code(503);
    return {
      status: ready ? "ready" : "not_ready",
      service: app.config.serviceName,
      version: app.config.version,
      ...deploymentIdentity(app.config),
      requestId: request.id,
      database: available ? "available" : "unavailable"
    };
  });
};
