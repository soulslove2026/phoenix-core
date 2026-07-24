import { randomUUID } from "node:crypto";
import Fastify, { LogController, type FastifyInstance } from "fastify";
import rateLimit from "@fastify/rate-limit";
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
import { IdentityObservabilityRepository } from "./operations/identity-observability.js";
import { operationsRoutes } from "./operations/routes.js";
import { passkeyValidationHarness } from "./validation/passkey-harness.js";
import { PostgresPlatformRepository } from "./platform/repository.js";
import { PlatformService } from "./platform/service.js";
import { platformRoutes } from "./platform/routes.js";

declare module "fastify" { interface FastifyInstance { config: AppConfig } }

export async function buildApp(config: AppConfig = loadConfig()): Promise<FastifyInstance> {
  const app = Fastify({
    logger: { level: config.logLevel, base: { service: config.serviceName, version: config.version, environment: config.environment, ...(config.deploymentId ? { deploymentId: config.deploymentId } : {}), ...(config.region ? { region: config.region } : {}), ...(config.buildCommit ? { buildCommit: config.buildCommit } : {}) } },
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
    if(request.url.startsWith("/passkey-validation")) reply.header("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    else if(!request.url.startsWith("/documentation"))reply.header("content-security-policy","default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    if(config.environment==="production") reply.header("strict-transport-security","max-age=31536000; includeSubDomains; preload");
    else if(config.environment==="staging") reply.header("strict-transport-security","max-age=86400");
  });
  app.addHook("onResponse",async(request,reply)=>{app.log.info({requestId:request.id,method:request.method,path:request.routeOptions.url??"unknown",statusCode:reply.statusCode},"request.completed");});

  await app.register(swagger,{openapi:{info:{title:"Phoenix Core API",version:config.version},components:{securitySchemes:{bearerAuth:{type:"http",scheme:"bearer",bearerFormat:"opaque"}}}}});
  if(config.documentationEnabled)await app.register(swaggerUi,{routePrefix:"/documentation"});
  await app.register(databasePlugin,{config});
  await app.register(systemRoutes,{prefix:"/v1/system"});
  if(config.passkeyValidationEnabled) await app.register(passkeyValidationHarness,{prefix:"/passkey-validation"});

  if(app.database.pool){
    if(!config.identityTokenPepper||!config.identityNotificationKey||!config.identityPrivacyKey||!config.identityMfaKey)throw new Error("identity secrets are required");
    const phaseBRepository = new PostgresPhaseBIdentityRepository(app.database.pool);
    const identityRepository = new PostgresIdentityRepository(app.database.pool);
    const service = new IdentityService(identityRepository,{
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
    await app.register(rateLimit,{
      global:false,
      skipOnError:false,
      errorResponseBuilder:(request)=>({
        error:"rate_limit_exceeded",
        requestId:request.id
      })
    });
    const limiter = new PostgresIdentityRateLimiter(app.database.pool);
    await app.register(identityRoutes,{prefix:"/v1/identity",service,limiter:limiter,privacyKey:config.identityPrivacyKey,rateLimit:{windowSeconds:config.identityRateLimitWindowSeconds,registerMaximum:config.identityRegisterMaxAttempts,loginMaximum:config.identityLoginMaxAttempts,actionRequestMaximum:config.identityActionRequestMaxAttempts,actionConfirmMaximum:config.identityActionConfirmMaxAttempts}});
    await app.register(platformRoutes,{prefix:"/v1/platform",identityService:service,platformService:new PlatformService(new PostgresPlatformRepository(app.database.pool)),limiter,privacyKey:config.identityPrivacyKey,rateLimit:{windowSeconds:config.identityRateLimitWindowSeconds,readMaximum:config.identityActionRequestMaxAttempts,writeMaximum:config.identityActionConfirmMaxAttempts}});
    if(config.operationsEnabled&&config.operationsToken) await app.register(operationsRoutes,{prefix:"/v1/operations",repository:new IdentityObservabilityRepository(app.database.pool),token:config.operationsToken,observationWindowMinutes:config.operationsObservationWindowMinutes,staleLockSeconds:config.operationsStaleLockSeconds,maxDeadLetters:config.operationsMaxDeadLetters,maxStaleLocks:config.operationsMaxStaleLocks,maxDeniedEvents:config.operationsMaxDeniedEvents});
  }
  app.setNotFoundHandler(async(request,reply)=>reply.code(404).send({error:"not_found",requestId:request.id}));
  app.setErrorHandler(async(error,request,reply)=>{request.log.error({err:error,requestId:request.id},"request.failed");const candidate=typeof error==="object"&&error!==null&&"statusCode" in error?Number((error as {statusCode?:unknown}).statusCode):500;const statusCode=Number.isInteger(candidate)&&candidate>=400&&candidate<500?candidate:500;return reply.code(statusCode).send({error:statusCode<500?"request_invalid":"internal_error",requestId:request.id});});
  return app;
}
