import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { IdentityError, type IdentityService } from "../identity/service.js";
import { PlatformError, type PlatformService } from "./service.js";
import type { AuthenticatedActor } from "./types.js";
import type { IdentityRateLimiter } from "../identity/distributed-rate-limit.js";
import { privacyHash } from "../identity/token-crypto.js";

const errorSchema = {
  type: "object",
  additionalProperties: false,
  required: ["error", "requestId"],
  properties: {
    error: { type: "string" },
    requestId: { type: "string" },
  },
} as const;


const organizationSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "slug",
    "name",
    "status",
    "createdByUserId",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: { type: "string", format: "uuid" },
    slug: { type: "string" },
    name: { type: "string" },
    status: { type: "string", enum: ["active", "suspended"] },
    createdByUserId: { type: "string", format: "uuid" },
    createdAt: { type: "string", format: "date-time" },
    updatedAt: { type: "string", format: "date-time" },
  },
} as const;

const membershipSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "organizationId",
    "userId",
    "role",
    "status",
    "createdByUserId",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    organizationId: { type: "string", format: "uuid" },
    userId: { type: "string", format: "uuid" },
    role: { type: "string", enum: ["owner", "admin", "member"] },
    status: { type: "string", enum: ["active", "suspended"] },
    createdByUserId: { type: "string", format: "uuid" },
    createdAt: { type: "string", format: "date-time" },
    updatedAt: { type: "string", format: "date-time" },
  },
} as const;

const bearerSecurity = [{ bearerAuth: [] }] as const;

type Options = Readonly<{
  identityService: IdentityService;
  platformService: PlatformService;
  limiter: IdentityRateLimiter;
  privacyKey: string;
  rateLimit: Readonly<{
    windowSeconds: number;
    readMaximum: number;
    writeMaximum: number;
  }>;
}>;

function bearer(value: string | undefined): string {
  if (!value?.startsWith("Bearer ")) {
    throw new IdentityError("session_missing", 401);
  }
  const token = value.slice(7).trim();
  if (!token) throw new IdentityError("session_missing", 401);
  return token;
}

async function actor(
  request: FastifyRequest,
  identityService: IdentityService,
): Promise<AuthenticatedActor> {
  const authenticated = await identityService.authenticate(
    bearer(request.headers.authorization),
  );
  return {
    userId: authenticated.user.id,
    sessionId: authenticated.session.id,
    requestId: request.id,
  };
}

export const platformRoutes: FastifyPluginAsync<Options> = async (app, options) => {
  const limited = (
    scope: string,
    maximum: number,
  ) => async (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<FastifyReply | void> => {
    const authorization = String(request.headers.authorization ?? "none");
    const subject = privacyHash(authorization, options.privacyKey);
    const keys = [
      {
        key: privacyHash(
          `platform:${scope}:pair:${request.ip}:${subject}`,
          options.privacyKey,
        ),
        maximum,
      },
      {
        key: privacyHash(
          `platform:${scope}:ip:${request.ip}`,
          options.privacyKey,
        ),
        maximum: maximum * 10,
      },
      {
        key: privacyHash(
          `platform:${scope}:subject:${subject}`,
          options.privacyKey,
        ),
        maximum: maximum * 5,
      },
    ];

    const decisions = await Promise.all(
      keys.map((item) =>
        options.limiter.consume(
          item.key,
          item.maximum,
          options.rateLimit.windowSeconds,
        ),
      ),
    );
    const denied = decisions.find((decision) => !decision.allowed);
    const remaining = Math.min(
      ...decisions.map((decision) => decision.remaining),
    );

    reply
      .header("x-ratelimit-limit", maximum)
      .header("x-ratelimit-remaining", Math.max(0, remaining));

    if (denied) {
      reply.header(
        "retry-after",
        Math.max(...decisions.map((decision) => decision.retryAfterSeconds)),
      );
      return reply
        .code(429)
        .send({ error: "rate_limit_exceeded", requestId: request.id });
    }
  };

  app.post(
    "/organizations",
    {
      preHandler: limited("organizations_create", options.rateLimit.writeMaximum),
      config: {
        rateLimit: {
          max: options.rateLimit.writeMaximum,
          timeWindow: options.rateLimit.windowSeconds * 1000,
        },
      },
      schema: {
        security: bearerSecurity,
        headers: {
          type: "object",
          required: ["x-idempotency-key"],
          properties: {
            "x-idempotency-key": {
              type: "string",
              minLength: 8,
              maxLength: 128,
              pattern: "^[A-Za-z0-9._:-]+$",
            },
          },
        },
        body: {
          type: "object",
          additionalProperties: false,
          required: ["slug", "name"],
          properties: {
            slug: { type: "string", minLength: 3, maxLength: 63 },
            name: { type: "string", minLength: 2, maxLength: 120 },
          },
        },
        response: {
          201: {
            type: "object",
            additionalProperties: false,
            required: ["organization", "replayed"],
            properties: {
              organization: organizationSchema,
              replayed: { type: "boolean" },
            },
          },
          400: errorSchema,
          401: errorSchema,
          409: errorSchema,
          429: errorSchema,
        },
      },
    },
    async (request, reply) => {
      const key = String(request.headers["x-idempotency-key"] ?? "");
      const result = await options.platformService.createOrganization(
        await actor(request, options.identityService),
        request.body as { slug: string; name: string },
        key,
      );
      return reply.code(201).send(result);
    },
  );

  app.get(
    "/organizations",
    {
      preHandler: limited("organizations_list", options.rateLimit.readMaximum),
      config: {
        rateLimit: {
          max: options.rateLimit.readMaximum,
          timeWindow: options.rateLimit.windowSeconds * 1000,
        },
      },
      schema: {
        security: bearerSecurity,
        response: {
          200: {
            type: "object",
            additionalProperties: false,
            required: ["organizations"],
            properties: {
              organizations: {
                type: "array",
                items: organizationSchema,
              },
            },
          },
          401: errorSchema,
          429: errorSchema,
        },
      },
    },
    async (request) => ({
      organizations: await options.platformService.listOrganizations(
        await actor(request, options.identityService),
      ),
    }),
  );

  app.get(
    "/organizations/:organizationId",
    {
      preHandler: limited("organization_read", options.rateLimit.readMaximum),
      config: {
        rateLimit: {
          max: options.rateLimit.readMaximum,
          timeWindow: options.rateLimit.windowSeconds * 1000,
        },
      },
      schema: {
        security: bearerSecurity,
        params: {
          type: "object",
          required: ["organizationId"],
          properties: {
            organizationId: { type: "string", format: "uuid" },
          },
        },
        response: {
          200: {
            type: "object",
            additionalProperties: false,
            required: ["organization", "membership"],
            properties: {
              organization: organizationSchema,
              membership: membershipSchema,
            },
          },
          401: errorSchema,
          404: errorSchema,
          429: errorSchema,
        },
      },
    },
    async (request) => {
      const context = await options.platformService.getOrganization(
        await actor(request, options.identityService),
        (request.params as { organizationId: string }).organizationId,
      );
      return {
        organization: context.organization,
        membership: context.membership,
      };
    },
  );

  app.get(
    "/organizations/:organizationId/members",
    {
      preHandler: limited("memberships_list", options.rateLimit.readMaximum),
      config: {
        rateLimit: {
          max: options.rateLimit.readMaximum,
          timeWindow: options.rateLimit.windowSeconds * 1000,
        },
      },
      schema: {
        security: bearerSecurity,
        params: {
          type: "object",
          required: ["organizationId"],
          properties: {
            organizationId: { type: "string", format: "uuid" },
          },
        },
        response: {
          200: {
            type: "object",
            additionalProperties: false,
            required: ["memberships"],
            properties: {
              memberships: {
                type: "array",
                items: membershipSchema,
              },
            },
          },
          401: errorSchema,
          404: errorSchema,
          429: errorSchema,
        },
      },
    },
    async (request) => ({
      memberships: await options.platformService.listMemberships(
        await actor(request, options.identityService),
        (request.params as { organizationId: string }).organizationId,
      ),
    }),
  );

  app.post(
    "/organizations/:organizationId/members",
    {
      preHandler: limited("membership_create", options.rateLimit.writeMaximum),
      config: {
        rateLimit: {
          max: options.rateLimit.writeMaximum,
          timeWindow: options.rateLimit.windowSeconds * 1000,
        },
      },
      schema: {
        security: bearerSecurity,
        params: {
          type: "object",
          required: ["organizationId"],
          properties: {
            organizationId: { type: "string", format: "uuid" },
          },
        },
        body: {
          type: "object",
          additionalProperties: false,
          required: ["userId", "role"],
          properties: {
            userId: { type: "string", format: "uuid" },
            role: { type: "string", enum: ["admin", "member"] },
          },
        },
        response: {
          201: {
            type: "object",
            additionalProperties: false,
            required: ["membership"],
            properties: {
              membership: membershipSchema,
            },
          },
          400: errorSchema,
          401: errorSchema,
          404: errorSchema,
          409: errorSchema,
          429: errorSchema,
        },
      },
    },
    async (request, reply) => {
      const membership = await options.platformService.addMembership(
        await actor(request, options.identityService),
        (request.params as { organizationId: string }).organizationId,
        request.body as { userId: string; role: "admin" | "member" },
      );
      return reply.code(201).send({ membership });
    },
  );

  app.setErrorHandler(async (error, request, reply) => {
    if (error instanceof PlatformError || error instanceof IdentityError) {
      return reply
        .code(error.statusCode)
        .send({ error: error.code, requestId: request.id });
    }
    throw error;
  });
};
