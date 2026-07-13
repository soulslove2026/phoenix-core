import Fastify, { type FastifyInstance } from "fastify";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { loadConfig, type AppConfig } from "./config.js";
import { databasePlugin } from "./plugins/database.js";
import { systemRoutes } from "./routes/system.js";

declare module "fastify" { interface FastifyInstance { config: AppConfig } }

export async function buildApp(config: AppConfig = loadConfig()): Promise<FastifyInstance> {
  const app = Fastify({
    logger: { level: config.logLevel, base: { service: config.serviceName, version: config.version, environment: config.environment } },
    requestIdHeader: "x-request-id", genReqId: request => {
      const value=request.headers["x-request-id"];
      return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value) ? value : crypto.randomUUID();
    },
    bodyLimit: 1_048_576, disableRequestLogging: true
  });
  app.decorate("config", config);
  app.addHook("onRequest", async (_request, reply) => {
    reply.header("x-content-type-options","nosniff").header("x-frame-options","DENY").header("referrer-policy","no-referrer").header("cache-control","no-store");
  });
  app.addHook("onResponse", async (request, reply) => app.log.info({requestId:request.id,method:request.method,path:request.url,statusCode:reply.statusCode},"request.completed"));
  await app.register(swagger,{openapi:{info:{title:"Phoenix Core API",version:"3.2.0"}}});
  await app.register(swaggerUi,{routePrefix:"/documentation"});
  await app.register(databasePlugin,{config});
  await app.register(systemRoutes,{prefix:"/v1/system"});
  app.setNotFoundHandler(async (request, reply) => reply.code(404).send({error:"not_found",requestId:request.id}));
  app.setErrorHandler(async (error, request, reply) => {
    request.log.error({err:error,requestId:request.id},"request.failed");
    const candidate = typeof error === "object" && error !== null && "statusCode" in error ? Number((error as { statusCode?: unknown }).statusCode) : 500;
    const statusCode = Number.isInteger(candidate) && candidate >= 400 && candidate < 500 ? candidate : 500;
    await reply.code(statusCode).send({error:statusCode<500?"request_invalid":"internal_error",requestId:request.id});
  });
  return app;
}
