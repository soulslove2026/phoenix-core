import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { FixedWindowRateLimiter } from "./rate-limit.js";
import { IdentityError, IdentityService } from "./service.js";

const userSchema = {
  type: "object",
  additionalProperties: false,
  required: ["id", "email", "displayName", "status", "createdAt"],
  properties: {
    id: { type: "string", format: "uuid" },
    email: { type: "string" },
    displayName: { type: "string" },
    status: { type: "string", enum: ["active", "disabled"] },
    createdAt: { type: "string", format: "date-time" }
  }
} as const;

const identityResponseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["user", "sessionToken"],
  properties: { user: userSchema, sessionToken: { type: "string" } }
} as const;

const errorSchema = {
  type: "object",
  additionalProperties: false,
  required: ["error", "requestId"],
  properties: { error: { type: "string" }, requestId: { type: "string" } }
} as const;

export type IdentityRouteOptions = Readonly<{
  service: IdentityService;
  rateLimit: Readonly<{
    windowSeconds: number;
    registerMaximum: number;
    loginMaximum: number;
  }>;
}>;

export const identityRoutes: FastifyPluginAsync<IdentityRouteOptions> = async (app, options) => {
  const { service } = options;
  const limiter = new FixedWindowRateLimiter(options.rateLimit.windowSeconds * 1_000);

  function limited(scope: "register" | "login", maximum: number) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const decision = limiter.consume(`${scope}:${request.ip}`, maximum);
      reply.header("x-ratelimit-limit", maximum);
      reply.header("x-ratelimit-remaining", decision.remaining);
      if (!decision.allowed) {
        request.log.warn({ event: "identity.rate_limited", scope }, "identity request rate limited");
        reply.header("retry-after", decision.retryAfterSeconds);
        await reply.code(429).send({ error: "rate_limit_exceeded", requestId: request.id });
      }
    };
  }

  app.post("/register", {
    preHandler: limited("register", options.rateLimit.registerMaximum),
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["email", "displayName", "password"],
        properties: {
          email: { type: "string", minLength: 3, maxLength: 320 },
          displayName: { type: "string", minLength: 2, maxLength: 80 },
          password: { type: "string", minLength: 12, maxLength: 200 }
        }
      },
      response: { 201: identityResponseSchema, 400: errorSchema, 409: errorSchema, 429: errorSchema }
    }
  }, async (request, reply) => {
    const result = await service.register(request.body as { email: string; displayName: string; password: string });
    request.log.info({ userId: result.user.id, event: "identity.user_registered" }, "user registered");
    return reply.code(201).send(result);
  });

  app.post("/login", {
    preHandler: limited("login", options.rateLimit.loginMaximum),
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["email", "password"],
        properties: {
          email: { type: "string", minLength: 3, maxLength: 320 },
          password: { type: "string", minLength: 1, maxLength: 200 }
        }
      },
      response: { 200: identityResponseSchema, 401: errorSchema, 429: errorSchema }
    }
  }, async (request) => {
    const result = await service.login(request.body as { email: string; password: string });
    request.log.info({ userId: result.user.id, event: "identity.user_logged_in" }, "user logged in");
    return result;
  });

  app.get("/me", {
    schema: {
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          type: "object",
          additionalProperties: false,
          required: ["user"],
          properties: { user: userSchema }
        },
        401: errorSchema
      }
    }
  }, async (request) => {
    const token = extractBearerToken(request.headers.authorization);
    return { user: await service.authenticate(token) };
  });

  app.post("/logout", {
    schema: { security: [{ bearerAuth: [] }] }
  }, async (request, reply) => {
    const token = extractBearerToken(request.headers.authorization);
    await service.logout(token);
    return reply.code(204).send();
  });

  app.setErrorHandler(async (error, request, reply) => {
    if (error instanceof IdentityError) {
      return reply.code(error.statusCode).send({ error: error.code, requestId: request.id });
    }
    throw error;
  });
};

function extractBearerToken(value: string | undefined): string {
  if (!value?.startsWith("Bearer ")) throw new IdentityError("session_missing", 401);
  const token = value.slice(7).trim();
  if (!token) throw new IdentityError("session_missing", 401);
  return token;
}
