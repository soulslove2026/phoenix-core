import type { Pool, PoolClient } from "pg";
import type {
  AuthenticatedActor,
  IdempotentOrganizationResult,
  OrganizationMembershipRecord,
  OrganizationRecord,
  OrganizationRole,
} from "./types.js";

export class PlatformRepositoryConflictError extends Error {
  constructor(public readonly conflict: "slug" | "membership" | "idempotency") {
    super(`platform_${conflict}_conflict`);
  }
}

export type AddMembershipResult =
  | Readonly<{ outcome: "created"; membership: OrganizationMembershipRecord }>
  | Readonly<{ outcome: "not_found" }>
  | Readonly<{ outcome: "conflict" }>
  | Readonly<{ outcome: "invalid_user" }>;

export interface PlatformRepository {
  createOrganization(input: {
    id: string;
    slug: string;
    name: string;
    actor: AuthenticatedActor;
    idempotencyKey: string;
    requestHash: string;
    idempotencyExpiresAt: string;
  }): Promise<IdempotentOrganizationResult>;
  listOrganizationsForActor(actorUserId: string): Promise<OrganizationRecord[]>;
  findOrganizationForActor(organizationId: string, actorUserId: string): Promise<OrganizationRecord | null>;
  findMembershipForActor(organizationId: string, actorUserId: string): Promise<OrganizationMembershipRecord | null>;
  listMembershipsForActor(organizationId: string, actorUserId: string): Promise<OrganizationMembershipRecord[] | null>;
  addMembershipAsActor(input: {
    organizationId: string;
    actor: AuthenticatedActor;
    memberUserId: string;
    role: Exclude<OrganizationRole, "owner">;
  }): Promise<AddMembershipResult>;
}

function organizationFromRow(row: Record<string, unknown>): OrganizationRecord {
  return {
    id: String(row.id),
    slug: String(row.slug),
    name: String(row.name),
    status: row.status === "suspended" ? "suspended" : "active",
    createdByUserId: String(row.created_by_user_id),
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString(),
  };
}

function membershipFromRow(row: Record<string, unknown>): OrganizationMembershipRecord {
  const role = row.role === "owner" || row.role === "admin" ? row.role : "member";
  return {
    organizationId: String(row.organization_id),
    userId: String(row.user_id),
    role,
    status: row.status === "suspended" ? "suspended" : "active",
    createdByUserId: String(row.created_by_user_id),
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString(),
  };
}

function postgresError(error: unknown): { code?: string; constraint?: string } {
  if (typeof error !== "object" || error === null) return {};
  const candidate = error as { code?: unknown; constraint?: unknown };
  return {
    ...(typeof candidate.code === "string" ? { code: candidate.code } : {}),
    ...(typeof candidate.constraint === "string" ? { constraint: candidate.constraint } : {}),
  };
}

async function transaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await operation(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export class PostgresPlatformRepository implements PlatformRepository {
  constructor(private readonly pool: Pool) {}

  async createOrganization(input: {
    id: string;
    slug: string;
    name: string;
    actor: AuthenticatedActor;
    idempotencyKey: string;
    requestHash: string;
    idempotencyExpiresAt: string;
  }): Promise<IdempotentOrganizationResult> {
    return transaction(this.pool, async (client) => {
      await client.query(
        "select pg_advisory_xact_lock(hashtext($1))",
        [`platform_idempotency:${input.actor.userId}:${input.idempotencyKey}`],
      );

      const existing = await client.query<{
        request_hash: string;
        response_body: unknown;
      }>(
        `select request_hash,response_body
         from platform_idempotency_records
         where actor_user_id=$1 and operation='organization.create'
           and idempotency_key=$2 and expires_at>now()
         for update`,
        [input.actor.userId, input.idempotencyKey],
      );

      const prior = existing.rows[0];
      if (prior) {
        if (prior.request_hash !== input.requestHash) {
          throw new PlatformRepositoryConflictError("idempotency");
        }
        const body = prior.response_body as { organization?: Record<string, unknown> };
        if (!body.organization) throw new Error("platform_idempotency_response_invalid");
        return { organization: organizationFromRow({
          id: body.organization.id,
          slug: body.organization.slug,
          name: body.organization.name,
          status: body.organization.status,
          created_by_user_id: body.organization.createdByUserId,
          created_at: body.organization.createdAt,
          updated_at: body.organization.updatedAt,
        }), replayed: true };
      }

      let organization: OrganizationRecord;
      try {
        const inserted = await client.query(
          `insert into platform_organizations
             (id,slug,name,created_by_user_id)
           values ($1,$2,$3,$4)
           returning *`,
          [input.id, input.slug, input.name, input.actor.userId],
        );
        const row = inserted.rows[0] as Record<string, unknown> | undefined;
        if (!row) throw new Error("platform_organization_insert_returned_no_row");
        organization = organizationFromRow(row);
      } catch (error) {
        const details = postgresError(error);
        if (details.code === "23505" && details.constraint === "platform_organizations_slug_unique") {
          throw new PlatformRepositoryConflictError("slug");
        }
        throw error;
      }

      await client.query(
        `insert into platform_organization_memberships
           (organization_id,user_id,role,created_by_user_id)
         values ($1,$2,'owner',$2)`,
        [organization.id, input.actor.userId],
      );

      await client.query(
        `insert into platform_audit_events
           (id,organization_id,actor_user_id,event_type,outcome,request_id,metadata)
         values (gen_random_uuid(),$1,$2,'platform.organization.created','success',$3,$4::jsonb)`,
        [
          organization.id,
          input.actor.userId,
          input.actor.requestId,
          JSON.stringify({ slug: organization.slug }),
        ],
      );

      await client.query(
        `insert into platform_idempotency_records
           (actor_user_id,operation,idempotency_key,request_hash,response_status,response_body,expires_at)
         values ($1,'organization.create',$2,$3,201,$4::jsonb,$5)`,
        [
          input.actor.userId,
          input.idempotencyKey,
          input.requestHash,
          JSON.stringify({ organization }),
          input.idempotencyExpiresAt,
        ],
      );

      return { organization, replayed: false };
    });
  }

  async listOrganizationsForActor(actorUserId: string): Promise<OrganizationRecord[]> {
    const result = await this.pool.query(
      `select o.*
       from platform_organizations o
       join platform_organization_memberships m
         on m.organization_id=o.id
        and m.user_id=$1
        and m.status='active'
       where o.status='active'
       order by o.created_at asc,o.id asc`,
      [actorUserId],
    );
    return result.rows.map((row) => organizationFromRow(row as Record<string, unknown>));
  }

  async findOrganizationForActor(
    organizationId: string,
    actorUserId: string,
  ): Promise<OrganizationRecord | null> {
    const result = await this.pool.query(
      `select o.*
       from platform_organizations o
       join platform_organization_memberships m
         on m.organization_id=o.id
        and m.user_id=$2
        and m.status='active'
       where o.id=$1 and o.status='active'`,
      [organizationId, actorUserId],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? organizationFromRow(row) : null;
  }

  async findMembershipForActor(
    organizationId: string,
    actorUserId: string,
  ): Promise<OrganizationMembershipRecord | null> {
    const result = await this.pool.query(
      `select m.*
       from platform_organization_memberships m
       join platform_organizations o on o.id=m.organization_id and o.status='active'
       where m.organization_id=$1 and m.user_id=$2 and m.status='active'`,
      [organizationId, actorUserId],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    return row ? membershipFromRow(row) : null;
  }

  async listMembershipsForActor(
    organizationId: string,
    actorUserId: string,
  ): Promise<OrganizationMembershipRecord[] | null> {
    const authorized = await this.findMembershipForActor(organizationId, actorUserId);
    if (!authorized) return null;

    const result = await this.pool.query(
      `select *
       from platform_organization_memberships
       where organization_id=$1 and status='active'
       order by created_at asc,user_id asc`,
      [organizationId],
    );
    return result.rows.map((row) => membershipFromRow(row as Record<string, unknown>));
  }

  async addMembershipAsActor(input: {
    organizationId: string;
    actor: AuthenticatedActor;
    memberUserId: string;
    role: "admin" | "member";
  }): Promise<AddMembershipResult> {
    return transaction(this.pool, async (client) => {
      const authorized = await client.query<{ id: string }>(
        `select o.id
         from platform_organizations o
         join platform_organization_memberships actor
           on actor.organization_id=o.id
          and actor.user_id=$2
          and actor.status='active'
          and actor.role in ('owner','admin')
         where o.id=$1 and o.status='active'
         for update`,
        [input.organizationId, input.actor.userId],
      );

      if (!authorized.rows[0]) {
        await client.query(
          `insert into platform_audit_events
             (id,organization_id,actor_user_id,event_type,outcome,request_id,metadata)
           values (gen_random_uuid(),null,$1,'platform.membership.create','denied',$2,'{}'::jsonb)`,
          [input.actor.userId, input.actor.requestId],
        );
        return { outcome: "not_found" };
      }

      const user = await client.query<{ id: string }>(
        "select id from identity_users where id=$1 and status='active'",
        [input.memberUserId],
      );
      if (!user.rows[0]) return { outcome: "invalid_user" };

      const inserted = await client.query(
        `insert into platform_organization_memberships
           (organization_id,user_id,role,created_by_user_id)
         values ($1,$2,$3,$4)
         on conflict (organization_id,user_id) do nothing
         returning *`,
        [
          input.organizationId,
          input.memberUserId,
          input.role,
          input.actor.userId,
        ],
      );

      const row = inserted.rows[0] as Record<string, unknown> | undefined;
      if (!row) return { outcome: "conflict" };

      await client.query(
        `insert into platform_audit_events
           (id,organization_id,actor_user_id,event_type,outcome,request_id,metadata)
         values (gen_random_uuid(),$1,$2,'platform.membership.created','success',$3,$4::jsonb)`,
        [
          input.organizationId,
          input.actor.userId,
          input.actor.requestId,
          JSON.stringify({ memberUserId: input.memberUserId, role: input.role }),
        ],
      );

      return { outcome: "created", membership: membershipFromRow(row) };
    });
  }
}
