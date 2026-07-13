import type { FastifyPluginAsync } from "fastify";

const responseSchema = {
  type: "object", additionalProperties: false,
  required: ["status","service","version","requestId"],
  properties: { status:{type:"string"}, service:{type:"string"}, version:{type:"string"}, requestId:{type:"string"}, database:{type:"string"} }
} as const;

export const systemRoutes: FastifyPluginAsync = async app => {
  app.get("/health", { schema: { response: { 200: responseSchema } } }, async request => ({
    status:"healthy", service:"phoenix-core", version:"3.2.0", requestId:request.id
  }));
  app.get("/ready", { schema: { response: { 200: responseSchema, 503: responseSchema } } }, async (request, reply) => {
    const required = app.config.databaseRequired;
    const available = app.database.available;
    const ready = !required || available;
    if (!ready) reply.code(503);
    return {status:ready?"ready":"not_ready",service:"phoenix-core",version:"3.2.0",requestId:request.id,database:available?"available":"unavailable"};
  });
};
