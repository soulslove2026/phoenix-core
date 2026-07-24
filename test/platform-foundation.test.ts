import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformRepositoryConflictError,
  type AddMembershipResult,
  type PlatformRepository,
} from "../src/platform/repository.js";
import { PlatformError, PlatformService } from "../src/platform/service.js";
import type {
  AuthenticatedActor,
  IdempotentOrganizationResult,
  OrganizationMembershipRecord,
  OrganizationRecord,
} from "../src/platform/types.js";

const ownerId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const outsiderId = "33333333-3333-4333-8333-333333333333";
const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function actor(userId: string): AuthenticatedActor {
  return { userId, sessionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", requestId: "req-1" };
}

class MemoryPlatformRepository implements PlatformRepository {
  organizations = new Map<string, OrganizationRecord>();
  memberships = new Map<string, OrganizationMembershipRecord>();
  idempotency = new Map<string, { requestHash: string; result: IdempotentOrganizationResult }>();

  async createOrganization(input: {
    id: string;
    slug: string;
    name: string;
    actor: AuthenticatedActor;
    idempotencyKey: string;
    requestHash: string;
    idempotencyExpiresAt: string;
  }): Promise<IdempotentOrganizationResult> {
    const key = `${input.actor.userId}:${input.idempotencyKey}`;
    const existing = this.idempotency.get(key);
    if (existing) {
      if (existing.requestHash !== input.requestHash) {
        throw new PlatformRepositoryConflictError("idempotency");
      }
      return { organization: existing.result.organization, replayed: true };
    }
    if ([...this.organizations.values()].some((item) => item.slug === input.slug)) {
      throw new PlatformRepositoryConflictError("slug");
    }
    const now = new Date("2026-07-24T00:00:00.000Z").toISOString();
    const organization: OrganizationRecord = {
      id: input.id,
      slug: input.slug,
      name: input.name,
      status: "active",
      createdByUserId: input.actor.userId,
      createdAt: now,
      updatedAt: now,
    };
    const membership: OrganizationMembershipRecord = {
      organizationId: organization.id,
      userId: input.actor.userId,
      role: "owner",
      status: "active",
      createdByUserId: input.actor.userId,
      createdAt: now,
      updatedAt: now,
    };
    this.organizations.set(organization.id, organization);
    this.memberships.set(`${organization.id}:${input.actor.userId}`, membership);
    const result = { organization, replayed: false } as const;
    this.idempotency.set(key, { requestHash: input.requestHash, result });
    return result;
  }

  async listOrganizationsForActor(actorUserId: string): Promise<OrganizationRecord[]> {
    const ids = [...this.memberships.values()]
      .filter((item) => item.userId === actorUserId && item.status === "active")
      .map((item) => item.organizationId);
    return ids
      .map((id) => this.organizations.get(id))
      .filter((item): item is OrganizationRecord => item !== undefined);
  }

  async findOrganizationForActor(
    id: string,
    actorUserId: string,
  ): Promise<OrganizationRecord | null> {
    return this.memberships.has(`${id}:${actorUserId}`)
      ? this.organizations.get(id) ?? null
      : null;
  }

  async findMembershipForActor(
    id: string,
    actorUserId: string,
  ): Promise<OrganizationMembershipRecord | null> {
    return this.memberships.get(`${id}:${actorUserId}`) ?? null;
  }

  async listMembershipsForActor(
    id: string,
    actorUserId: string,
  ): Promise<OrganizationMembershipRecord[] | null> {
    if (!this.memberships.has(`${id}:${actorUserId}`)) return null;
    return [...this.memberships.values()].filter((item) => item.organizationId === id);
  }

  async addMembershipAsActor(input: {
    organizationId: string;
    actor: AuthenticatedActor;
    memberUserId: string;
    role: "admin" | "member";
  }): Promise<AddMembershipResult> {
    const acting = this.memberships.get(
      `${input.organizationId}:${input.actor.userId}`,
    );
    if (!acting || !["owner", "admin"].includes(acting.role)) {
      return { outcome: "not_found" };
    }
    const key = `${input.organizationId}:${input.memberUserId}`;
    if (this.memberships.has(key)) return { outcome: "conflict" };
    const now = new Date("2026-07-24T00:00:00.000Z").toISOString();
    const membership: OrganizationMembershipRecord = {
      organizationId: input.organizationId,
      userId: input.memberUserId,
      role: input.role,
      status: "active",
      createdByUserId: input.actor.userId,
      createdAt: now,
      updatedAt: now,
    };
    this.memberships.set(key, membership);
    return { outcome: "created", membership };
  }
}

test("organization creation is idempotent and normalizes authority fields", async () => {
  const repository = new MemoryPlatformRepository();
  const service = new PlatformService(repository);
  const first = await service.createOrganization(
    actor(ownerId),
    { slug: "  Phoenix-Team  ", name: "  Phoenix   Team  " },
    "create:phoenix-team",
  );
  const replay = await service.createOrganization(
    actor(ownerId),
    { slug: "phoenix-team", name: "Phoenix Team" },
    "create:phoenix-team",
  );

  assert.equal(first.organization.slug, "phoenix-team");
  assert.equal(first.organization.name, "Phoenix Team");
  assert.equal(first.replayed, false);
  assert.equal(replay.replayed, true);
  assert.equal(replay.organization.id, first.organization.id);
});

test("idempotency key cannot be reused for a different request", async () => {
  const repository = new MemoryPlatformRepository();
  const service = new PlatformService(repository);
  await service.createOrganization(
    actor(ownerId),
    { slug: "phoenix-one", name: "Phoenix One" },
    "create:phoenix",
  );

  await assert.rejects(
    () =>
      service.createOrganization(
        actor(ownerId),
        { slug: "phoenix-two", name: "Phoenix Two" },
        "create:phoenix",
      ),
    (error: unknown) =>
      error instanceof PlatformError && error.code === "idempotency_conflict",
  );
});

test("tenant isolation returns the same not-found result to outsiders", async () => {
  const repository = new MemoryPlatformRepository();
  const service = new PlatformService(repository);
  const created = await service.createOrganization(
    actor(ownerId),
    { slug: "isolated-team", name: "Isolated Team" },
    "create:isolated-team",
  );

  await assert.rejects(
    () => service.getOrganization(actor(outsiderId), created.organization.id),
    (error: unknown) =>
      error instanceof PlatformError &&
      error.code === "platform_resource_not_found" &&
      error.statusCode === 404,
  );

  await assert.rejects(
    () => service.getOrganization(actor(outsiderId), organizationId),
    (error: unknown) =>
      error instanceof PlatformError &&
      error.code === "platform_resource_not_found" &&
      error.statusCode === 404,
  );
});

test("only owner or admin may add a member", async () => {
  const repository = new MemoryPlatformRepository();
  const service = new PlatformService(repository);
  const created = await service.createOrganization(
    actor(ownerId),
    { slug: "roles-team", name: "Roles Team" },
    "create:roles-team",
  );

  const membership = await service.addMembership(
    actor(ownerId),
    created.organization.id,
    { userId: memberId, role: "member" },
  );
  assert.equal(membership.role, "member");

  await assert.rejects(
    () =>
      service.addMembership(actor(memberId), created.organization.id, {
        userId: outsiderId,
        role: "member",
      }),
    (error: unknown) =>
      error instanceof PlatformError &&
      error.code === "platform_resource_not_found",
  );
});

test("organization lists are scoped to the authenticated actor", async () => {
  const repository = new MemoryPlatformRepository();
  const service = new PlatformService(repository);
  const created = await service.createOrganization(
    actor(ownerId),
    { slug: "list-team", name: "List Team" },
    "create:list-team",
  );

  assert.equal((await service.listOrganizations(actor(ownerId))).length, 1);
  assert.equal((await service.listOrganizations(actor(outsiderId))).length, 0);

  await service.addMembership(actor(ownerId), created.organization.id, {
    userId: memberId,
    role: "member",
  });
  assert.equal((await service.listOrganizations(actor(memberId))).length, 1);
});


test("every protected platform route declares governed rate limiting", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(
    new URL("../src/platform/routes.ts", import.meta.url),
    "utf8",
  );

  const protectedRoutes = [
    ["post", "/organizations"],
    ["get", "/organizations"],
    ["get", "/organizations/:organizationId"],
    ["get", "/organizations/:organizationId/members"],
    ["post", "/organizations/:organizationId/members"],
  ] as const;

  for (const [method, path] of protectedRoutes) {
    const escaped = path.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const expression = new RegExp(
      `app\\.${method}\\(\\s*"${escaped}",\\s*\\{\\s*preHandler:\\s*limited\\(`,
      "su",
    );
    assert.match(source, expression, `${method.toUpperCase()} ${path}`);
  }

  assert.equal(
    (source.match(/429:\s*errorSchema/gu) ?? []).length >=
      protectedRoutes.length,
    true,
  );
  assert.equal(source.includes("authenticatedRateLimitConfig"), false);
});
