import { createHash, randomUUID } from "node:crypto";
import {
  PlatformRepositoryConflictError,
  type PlatformRepository,
} from "./repository.js";
import type {
  AuthenticatedActor,
  IdempotentOrganizationResult,
  OrganizationMembershipRecord,
  OrganizationRecord,
  TenantContext,
} from "./types.js";

export class PlatformError extends Error {
  constructor(
    public readonly code: string,
    public readonly statusCode: number,
  ) {
    super(code);
  }
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/u;
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

function canonicalRequestHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function normalizedOrganization(input: { slug: string; name: string }): {
  slug: string;
  name: string;
} {
  const slug = input.slug.trim().toLowerCase();
  const name = input.name.trim().replace(/\s+/gu, " ");

  if (slug.length < 3 || slug.length > 63 || !SLUG_PATTERN.test(slug)) {
    throw new PlatformError("organization_invalid", 400);
  }
  if (name.length < 2 || name.length > 120) {
    throw new PlatformError("organization_invalid", 400);
  }

  return { slug, name };
}

function organizationId(value: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new PlatformError("platform_resource_not_found", 404);
  }
  return value;
}

export class PlatformService {
  constructor(
    private readonly repository: PlatformRepository,
    private readonly idempotencyTtlSeconds = 86_400,
  ) {
    if (
      !Number.isInteger(idempotencyTtlSeconds) ||
      idempotencyTtlSeconds < 300 ||
      idempotencyTtlSeconds > 604_800
    ) {
      throw new Error("platform idempotency TTL must be between 300 and 604800 seconds");
    }
  }

  async createOrganization(
    actor: AuthenticatedActor,
    input: { slug: string; name: string },
    idempotencyKey: string,
  ): Promise<IdempotentOrganizationResult> {
    if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) {
      throw new PlatformError("idempotency_key_invalid", 400);
    }

    const normalized = normalizedOrganization(input);
    try {
      return await this.repository.createOrganization({
        id: randomUUID(),
        ...normalized,
        actor,
        idempotencyKey,
        requestHash: canonicalRequestHash(normalized),
        idempotencyExpiresAt: new Date(
          Date.now() + this.idempotencyTtlSeconds * 1000,
        ).toISOString(),
      });
    } catch (error) {
      if (error instanceof PlatformRepositoryConflictError) {
        if (error.conflict === "slug") {
          throw new PlatformError("organization_conflict", 409);
        }
        if (error.conflict === "idempotency") {
          throw new PlatformError("idempotency_conflict", 409);
        }
      }
      throw error;
    }
  }

  listOrganizations(actor: AuthenticatedActor): Promise<OrganizationRecord[]> {
    return this.repository.listOrganizationsForActor(actor.userId);
  }

  async getOrganization(
    actor: AuthenticatedActor,
    organizationIdInput: string,
  ): Promise<TenantContext> {
    const id = organizationId(organizationIdInput);
    const [organization, membership] = await Promise.all([
      this.repository.findOrganizationForActor(id, actor.userId),
      this.repository.findMembershipForActor(id, actor.userId),
    ]);

    if (!organization || !membership) {
      throw new PlatformError("platform_resource_not_found", 404);
    }

    return { organization, membership, actor };
  }

  async listMemberships(
    actor: AuthenticatedActor,
    organizationIdInput: string,
  ): Promise<OrganizationMembershipRecord[]> {
    const id = organizationId(organizationIdInput);
    const memberships = await this.repository.listMembershipsForActor(
      id,
      actor.userId,
    );
    if (!memberships) {
      throw new PlatformError("platform_resource_not_found", 404);
    }
    return memberships;
  }

  async addMembership(
    actor: AuthenticatedActor,
    organizationIdInput: string,
    input: { userId: string; role: "admin" | "member" },
  ): Promise<OrganizationMembershipRecord> {
    const id = organizationId(organizationIdInput);
    if (!UUID_PATTERN.test(input.userId)) {
      throw new PlatformError("membership_invalid", 400);
    }
    if (input.role !== "admin" && input.role !== "member") {
      throw new PlatformError("membership_invalid", 400);
    }

    const result = await this.repository.addMembershipAsActor({
      organizationId: id,
      actor,
      memberUserId: input.userId,
      role: input.role,
    });

    if (result.outcome === "not_found") {
      throw new PlatformError("platform_resource_not_found", 404);
    }
    if (result.outcome === "invalid_user") {
      throw new PlatformError("membership_invalid", 400);
    }
    if (result.outcome === "conflict") {
      throw new PlatformError("membership_conflict", 409);
    }
    return result.membership;
  }
}
