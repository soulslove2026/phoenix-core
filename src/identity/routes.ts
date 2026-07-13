import type { FastifyPluginAsync } from "fastify";
import { IdentityError, IdentityService } from "./service.js";

const userSchema = {
  type: "object",
  required: ["id", "email", "displayName", "status", "createdAt"],
  properties: {
    id: { type: "string", format: "uuid" },
    email: { type: "string" },
    displayName: { type: "string" },
    status: { type: "string", enum: ["active", "disabled"] },
    createdAt: { type: "string", format: "date-time" }
  }
} as const;

export const identityRoutes: FastifyPluginAsync<{ service: IdentityService }> = async (app, options) => {
  const { service } = options;

  app.post("/register", {
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
      response: {
        201: {
          type: "object",
          required: ["user", "sessionToken"],
          properties: { user: userSchema, sessionToken: { type: "string" } }
        }
      }
    }
  }, async (request, reply) => {
    const result = await service.register(request.body as { email: string; displayName: string; password: string });
    request.log.info({ userId: result.user.id, event: "identity.user_registered" }, "user registered");
    return reply.code(201).send(result);
  });

  app.post("/login", {
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["email", "password"],
        properties: {
          email: { type: "string", minLength: 3, maxLength: 320 },
          password: { type: "string", minLength: 1, maxLength: 200 }
        }
      }
    }
  }, async (request) => {
    const result = await service.login(request.body as { email: string; password: string });
    request.log.info({ userId: result.user.id, event: "identity.user_logged_in" }, "user logged in");
    return result;
  });

  app.get("/me", async (request) => {
    const token = extractBearerToken(request.headers.authorization);
    return { user: await service.authenticate(token) };
  });

  app.post("/logout", async (request, reply) => {
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
