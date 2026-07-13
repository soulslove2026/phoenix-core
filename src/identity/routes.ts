import { createHash } from "node:crypto";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityRateLimiter } from "./distributed-rate-limit.js";
import { IdentityError, IdentityService } from "./service.js";
import { privacyHash } from "./token-crypto.js";
import type { SecurityContext } from "./types.js";

const errorSchema = {
  type: "object",
  additionalProperties: false,
  required: ["error", "requestId"],
  properties: { error: { type: "string" }, requestId: { type: "string" } }
} as const;

const acceptedSchema = {
  type: "object",
  additionalProperties: false,
  required: ["accepted"],
  properties: { accepted: { type: "boolean", const: true } }
} as const;

const userSchema = {
  type: "object",
  additionalProperties: false,
  required: ["id", "email", "displayName", "status", "emailVerified", "createdAt"],
  properties: {
    id: { type: "string", format: "uuid" },
    email: { type: "string" },
    displayName: { type: "string" },
    status: { type: "string", enum: ["active", "disabled"] },
    emailVerified: { type: "boolean" },
    createdAt: { type: "string", format: "date-time" }
  }
} as const;

const identitySchema = {
  type: "object",
  additionalProperties: false,
  required: ["user", "sessionToken"],
  properties: { user: userSchema, sessionToken: { type: "string", minLength: 40 } }
} as const;

const sessionSchema = {
  type: "object",
  additionalProperties: false,
  required: ["id", "current", "createdAt", "lastSeenAt", "idleExpiresAt", "expiresAt"],
  properties: {
    id: { type: "string", format: "uuid" },
    current: { type: "boolean" },
    createdAt: { type: "string", format: "date-time" },
    lastSeenAt: { type: "string", format: "date-time" },
    idleExpiresAt: { type: "string", format: "date-time" },
    expiresAt: { type: "string", format: "date-time" }
  }
} as const;

type Options = Readonly<{
  service: IdentityService;
  limiter: IdentityRateLimiter;
  privacyKey: string;
  rateLimit: Readonly<{
    windowSeconds: number;
    registerMaximum: number;
    loginMaximum: number;
    actionRequestMaximum: number;
    actionConfirmMaximum: number;
  }>;
}>;

export const identityRoutes: FastifyPluginAsync<Options> = async (app, options) => {
  const context = (request: FastifyRequest): SecurityContext => ({
    ipHash: privacyHash(request.ip, options.privacyKey),
    userAgentHash: privacyHash(String(request.headers["user-agent"] ?? "unknown"), options.privacyKey)
  });

  const subject = (request: FastifyRequest): string => {
    const body = request.body as Record<string, unknown> | undefined;
    const raw = typeof body?.email === "string"
      ? body.email
      : typeof body?.token === "string"
        ? body.token
        : "none";
    return createHash("sha256").update(raw.toLowerCase()).digest("hex");
  };

  const limited = (scope: string, maximum: number) => async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | void> => {
    const subjectDigest = subject(request);
    const keys = [
      { key: privacyHash(`${scope}:pair:${request.ip}:${subjectDigest}`, options.privacyKey), maximum },
      { key: privacyHash(`${scope}:ip:${request.ip}`, options.privacyKey), maximum: maximum * 10 },
      { key: privacyHash(`${scope}:subject:${subjectDigest}`, options.privacyKey), maximum: maximum * 5 }
    ];
    const decisions = await Promise.all(keys.map((item) => options.limiter.consume(item.key, item.maximum, options.rateLimit.windowSeconds)));
    const denied = decisions.find((decision) => !decision.allowed);
    const remaining = Math.min(...decisions.map((decision) => decision.remaining));
    reply.header("x-ratelimit-limit", maximum).header("x-ratelimit-remaining", Math.max(0, remaining));
    if (denied) {
      reply.header("retry-after", Math.max(...decisions.map((decision) => decision.retryAfterSeconds)));
      return reply.code(429).send({ error: "rate_limit_exceeded", requestId: request.id });
    }
  };

  app.post("/register", {
    preHandler: limited("register", options.rateLimit.registerMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["email", "displayName", "password"],
        properties: {
          email: { type: "string", minLength: 3, maxLength: 320 },
          displayName: { type: "string", minLength: 2, maxLength: 80 },
          password: { type: "string", minLength: 15, maxLength: 256 }
        }
      },
      response: { 202: acceptedSchema, 400: errorSchema, 429: errorSchema }
    }
  }, async (request, reply) => {
    await options.service.register(request.body as { email: string; displayName: string; password: string }, context(request));
    return reply.code(202).send({ accepted: true });
  });

  app.post("/email-verification/request", {
    preHandler: limited("verify_request", options.rateLimit.actionRequestMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["email"],
        properties: { email: { type: "string", minLength: 3, maxLength: 320 } }
      },
      response: { 202: acceptedSchema, 429: errorSchema }
    }
  }, async (request, reply) => {
    await options.service.requestEmailVerification((request.body as { email: string }).email, context(request));
    return reply.code(202).send({ accepted: true });
  });

  app.post("/email-verification/confirm", {
    preHandler: limited("verify_confirm", options.rateLimit.actionConfirmMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["token"],
        properties: { token: { type: "string", minLength: 40, maxLength: 200 } }
      },
      response: { 200: identitySchema, 400: errorSchema, 429: errorSchema }
    }
  }, async (request) => options.service.confirmEmailVerification((request.body as { token: string }).token, context(request)));

  app.post("/login", {
    preHandler: limited("login", options.rateLimit.loginMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["email", "password"],
        properties: {
          email: { type: "string", minLength: 3, maxLength: 320 },
          password: { type: "string", minLength: 1, maxLength: 256 }
        }
      },
      response: { 200: identitySchema, 401: errorSchema, 403: errorSchema, 429: errorSchema }
    }
  }, async (request) => options.service.login(request.body as { email: string; password: string }, context(request)));

  app.post("/password-reset/request", {
    preHandler: limited("reset_request", options.rateLimit.actionRequestMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["email"],
        properties: { email: { type: "string", minLength: 3, maxLength: 320 } }
      },
      response: { 202: acceptedSchema, 429: errorSchema }
    }
  }, async (request, reply) => {
    await options.service.requestPasswordReset((request.body as { email: string }).email, context(request));
    return reply.code(202).send({ accepted: true });
  });

  app.post("/password-reset/confirm", {
    preHandler: limited("reset_confirm", options.rateLimit.actionConfirmMaximum),
    schema: {
      body: {
        type: "object", additionalProperties: false, required: ["token", "newPassword"],
        properties: {
          token: { type: "string", minLength: 40, maxLength: 200 },
          newPassword: { type: "string", minLength: 15, maxLength: 256 }
        }
      },
      response: { 204: { type: "null" }, 400: errorSchema, 429: errorSchema }
    }
  }, async (request, reply) => {
    await options.service.confirmPasswordReset(request.body as { token: string; newPassword: string }, context(request));
    return reply.code(204).send();
  });

  app.get("/me", {
    schema: {
      security: [{ bearerAuth: [] }],
      response: {
        200: { type: "object", additionalProperties: false, required: ["user"], properties: { user: userSchema } },
        401: errorSchema
      }
    }
  }, async (request) => ({ user: (await options.service.authenticate(extract(request.headers.authorization))).user }));

  app.post("/sessions/rotate", {
    schema: {
      security: [{ bearerAuth: [] }],
      response: {
        200: { type: "object", additionalProperties: false, required: ["sessionToken"], properties: { sessionToken: { type: "string" } } },
        401: errorSchema
      }
    }
  }, async (request) => ({ sessionToken: await options.service.rotateSession(extract(request.headers.authorization), context(request)) }));

  app.get("/sessions", {
    schema: {
      security: [{ bearerAuth: [] }],
      response: {
        200: { type: "object", additionalProperties: false, required: ["sessions"], properties: { sessions: { type: "array", items: sessionSchema } } },
        401: errorSchema
      }
    }
  }, async (request) => ({ sessions: await options.service.listSessions(extract(request.headers.authorization)) }));

  app.delete("/sessions/:sessionId", {
    schema: {
      security: [{ bearerAuth: [] }],
      params: { type: "object", required: ["sessionId"], properties: { sessionId: { type: "string", format: "uuid" } } },
      response: { 204: { type: "null" }, 401: errorSchema }
    }
  }, async (request, reply) => {
    await options.service.revokeSessionById(extract(request.headers.authorization), (request.params as { sessionId: string }).sessionId, context(request));
    return reply.code(204).send();
  });

  app.post("/logout", { schema: { security: [{ bearerAuth: [] }] } }, async (request, reply) => {
    await options.service.logout(extract(request.headers.authorization), context(request));
    return reply.code(204).send();
  });

  app.post("/logout-all", { schema: { security: [{ bearerAuth: [] }] } }, async (request, reply) => {
    await options.service.logoutAll(extract(request.headers.authorization), context(request));
    return reply.code(204).send();
  });

  app.setErrorHandler(async (error, request, reply) => {
    if (error instanceof IdentityError) return reply.code(error.statusCode).send({ error: error.code, requestId: request.id });
    throw error;
  });
};

function extract(value: string | undefined): string {
  if (!value?.startsWith("Bearer ")) throw new IdentityError("session_missing", 401);
  const token = value.slice(7).trim();
  if (!token) throw new IdentityError("session_missing", 401);
  return token;
}
