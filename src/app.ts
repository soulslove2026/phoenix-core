import { randomUUID } from "node:crypto";
import Fastify, { LogController, type FastifyInstance } from "fastify";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { loadConfig, type AppConfig } from "./config.js";
import { databasePlugin } from "./plugins/database.js";
import { systemRoutes } from "./routes/system.js";
import { IdentityService } from "./identity/service.js";
import { PostgresIdentityRepository } from "./identity/repository.js";
import { PostgresIdentityRateLimiter } from "./identity/distributed-rate-limit.js";
import { identityRoutes } from "./identity/routes.js";
import { PostgresPhaseBIdentityRepository } from "./identity/phase-b-repository.js";
import { PasskeyManager } from "./identity/passkeys.js";
import { HibpPasswordBreachChecker } from "./identity/password-breach.js";

declare module "fastify" { interface FastifyInstance { config: AppConfig } }

export async function buildApp(config: AppConfig = loadConfig()): Promise<FastifyInstance> {
  const app = Fastify({
    logger: { level: config.logLevel, base: { service: config.serviceName, version: config.version, environment: config.environment } },
    trustProxy: config.trustProxyHops === 0 ? false : config.trustProxyHops,
    requestIdHeader: "x-request-id",
    genReqId: request => { const value=request.headers["x-request-id"]; return typeof value==="string"&&/^[A-Za-z0-9._-]{1,128}$/u.test(value)?value:randomUUID(); },
    bodyLimit: 262_144,
    logController: new LogController({ disableRequestLogging: true })
  });
  app.decorate("config", config);
  app.addHook("onRequest", async(request,reply)=>{
    if(config.requireTls&&request.protocol!=="https")return reply.code(400).send({error:"https_required",requestId:request.id});
    reply.header("x-content-type-options","nosniff").header("x-frame-options","DENY").header("referrer-policy","no-referrer").header("cache-control","no-store").header("permissions-policy","camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self)").header("cross-origin-resource-policy","same-origin").header("cross-origin-opener-policy","same-origin");
    if(!request.url.startsWith("/documentation"))reply.header("content-security-policy","default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    if(config.environment==="production")reply.header("strict-transport-security","max-age=31536000; includeSubDomains; preload");
  });
  app.addHook("onResponse",async(request,reply)=>{app.log.info({requestId:request.id,method:request.method,path:request.routeOptions.url??"unknown",statusCode:reply.statusCode},"request.completed");});

  await app.register(swagger,{openapi:{info:{title:"Phoenix Core API",version:config.version},components:{securitySchemes:{bearerAuth:{type:"http",scheme:"bearer",bearerFormat:"opaque"}}}}});
  if(config.documentationEnabled)await app.register(swaggerUi,{routePrefix:"/documentation"});
  await app.register(databasePlugin,{config});
  await app.register(systemRoutes,{prefix:"/v1/system"});

  if(app.database.pool){
    if(!config.identityTokenPepper||!config.identityNotificationKey||!config.identityPrivacyKey||!config.identityMfaKey)throw new Error("identity secrets are required");
    const phaseBRepository = new PostgresPhaseBIdentityRepository(app.database.pool);
    const service = new IdentityService(new PostgresIdentityRepository(app.database.pool),{
      sessionAbsoluteTtlSeconds:config.identitySessionAbsoluteTtlSeconds,
      sessionIdleTtlSeconds:config.identitySessionIdleTtlSeconds,
      verificationTtlSeconds:config.identityVerificationTtlSeconds,
      passwordResetTtlSeconds:config.identityPasswordResetTtlSeconds,
      tokenPepper:config.identityTokenPepper,
      notificationKey:config.identityNotificationKey,
      phaseB:{
        repository:phaseBRepository,
        passkeys:new PasskeyManager({rpName:config.identityWebauthnRpName,rpId:config.identityWebauthnRpId,origins:config.identityWebauthnOrigins,timeoutMs:config.identityWebauthnTimeoutMs}),
        passwordBreach:new HibpPasswordBreachChecker({mode:config.identityPasswordBreachMode,baseUrl:config.identityPwnedPasswordsBaseUrl,timeoutMs:config.identityPwnedPasswordsTimeoutMs,userAgent:`Phoenix-Core/${config.version}`}),
        mfaKey:config.identityMfaKey,
        recentAuthenticationSeconds:config.identityRecentAuthenticationSeconds,
        mfaTransactionTtlSeconds:config.identityMfaTransactionTtlSeconds,
        mfaMaxAttempts:config.identityMfaMaxAttempts,
        totpEnrollmentTtlSeconds:config.identityTotpEnrollmentTtlSeconds,
        totpIssuer:config.identityTotpIssuer,
        webauthnChallengeTtlSeconds:config.identityWebauthnChallengeTtlSeconds
      }
    });
    await app.register(identityRoutes,{prefix:"/v1/identity",service,limiter:new PostgresIdentityRateLimiter(app.database.pool),privacyKey:config.identityPrivacyKey,rateLimit:{windowSeconds:config.identityRateLimitWindowSeconds,registerMaximum:config.identityRegisterMaxAttempts,loginMaximum:config.identityLoginMaxAttempts,actionRequestMaximum:config.identityActionRequestMaxAttempts,actionConfirmMaximum:config.identityActionConfirmMaxAttempts}});
  }
  app.setNotFoundHandler(async(request,reply)=>reply.code(404).send({error:"not_found",requestId:request.id}));
  app.setErrorHandler(async(error,request,reply)=>{request.log.error({err:error,requestId:request.id},"request.failed");const candidate=typeof error==="object"&&error!==null&&"statusCode" in error?Number((error as {statusCode?:unknown}).statusCode):500;const statusCode=Number.isInteger(candidate)&&candidate>=400&&candidate<500?candidate:500;return reply.code(statusCode).send({error:statusCode<500?"request_invalid":"internal_error",requestId:request.id});});
  return app;
}
