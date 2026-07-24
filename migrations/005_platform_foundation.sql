create table if not exists platform_organizations (
  id uuid primary key,
  slug text not null,
  name text not null,
  status text not null default 'active' check (status in ('active','suspended')),
  created_by_user_id uuid not null references identity_users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (char_length(slug) between 3 and 63),
  check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  check (char_length(name) between 2 and 120)
);

create unique index if not exists platform_organizations_slug_unique
  on platform_organizations (lower(slug));

create table if not exists platform_organization_memberships (
  organization_id uuid not null references platform_organizations(id) on delete cascade,
  user_id uuid not null references identity_users(id) on delete cascade,
  role text not null check (role in ('owner','admin','member')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_by_user_id uuid not null references identity_users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (organization_id,user_id)
);

create index if not exists platform_memberships_user_active_idx
  on platform_organization_memberships (user_id,organization_id)
  where status='active';

create index if not exists platform_memberships_org_active_idx
  on platform_organization_memberships (organization_id,role,user_id)
  where status='active';

create table if not exists platform_idempotency_records (
  actor_user_id uuid not null references identity_users(id) on delete cascade,
  operation text not null,
  idempotency_key text not null,
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response_status integer not null check (response_status between 200 and 299),
  response_body jsonb not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  primary key (actor_user_id,operation,idempotency_key),
  check (expires_at > created_at)
);

create index if not exists platform_idempotency_expiry_idx
  on platform_idempotency_records (expires_at);

create table if not exists platform_audit_events (
  id uuid primary key,
  organization_id uuid null references platform_organizations(id) on delete set null,
  actor_user_id uuid null references identity_users(id) on delete set null,
  event_type text not null,
  outcome text not null check (outcome in ('success','denied','accepted')),
  request_id text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists platform_audit_events_org_created_idx
  on platform_audit_events (organization_id,created_at desc);

create index if not exists platform_audit_events_actor_created_idx
  on platform_audit_events (actor_user_id,created_at desc);
