alter table identity_users add column if not exists email_verified_at timestamptz null;
alter table identity_users add column if not exists password_changed_at timestamptz not null default now();
alter table identity_users add column if not exists auth_version integer not null default 1;

do $$ begin
  if not exists (select 1 from pg_constraint where conname='identity_users_auth_version_check') then
    alter table identity_users add constraint identity_users_auth_version_check check (auth_version > 0);
  end if;
end $$;

alter table identity_sessions add column if not exists auth_version integer not null default 1;
alter table identity_sessions add column if not exists user_agent_hash text null;
alter table identity_sessions add column if not exists ip_hash text null;
alter table identity_sessions add column if not exists rotated_from_session_id uuid null references identity_sessions(id) on delete set null;
alter table identity_sessions add column if not exists last_seen_at timestamptz not null default now();
alter table identity_sessions add column if not exists idle_expires_at timestamptz null;
update identity_sessions set idle_expires_at=least(expires_at,created_at+interval '12 hours') where idle_expires_at is null;
alter table identity_sessions alter column idle_expires_at set not null;

-- Session hashes change from unkeyed SHA-256 to HMAC-SHA-256. Existing sessions must reauthenticate.
update identity_sessions set revoked_at=coalesce(revoked_at,now()) where revoked_at is null;

do $$ begin
  if not exists (select 1 from pg_constraint where conname='identity_sessions_idle_expiry_check') then
    alter table identity_sessions add constraint identity_sessions_idle_expiry_check check (idle_expires_at <= expires_at and idle_expires_at > created_at);
  end if;
end $$;

create table if not exists identity_action_tokens (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  purpose text not null check (purpose in ('verify_email','password_reset')),
  token_hash text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  check (expires_at > created_at)
);
create index if not exists identity_action_tokens_active_idx on identity_action_tokens(user_id,purpose,expires_at) where consumed_at is null;
create unique index if not exists identity_action_tokens_one_active_idx on identity_action_tokens(user_id,purpose) where consumed_at is null;

create table if not exists identity_notification_outbox (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  kind text not null check (kind in ('email_verification','password_reset','security_notice')),
  ciphertext text not null,
  iv text not null,
  auth_tag text not null,
  created_at timestamptz not null default now(),
  available_at timestamptz not null default now(),
  sent_at timestamptz null,
  attempts integer not null default 0 check (attempts >= 0)
);
create index if not exists identity_notification_outbox_pending_idx on identity_notification_outbox(available_at) where sent_at is null;

create table if not exists identity_security_events (
  id uuid primary key,
  user_id uuid null references identity_users(id) on delete set null,
  event_type text not null,
  outcome text not null check (outcome in ('success','denied','accepted')),
  subject_hash text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists identity_security_events_user_time_idx on identity_security_events(user_id,created_at desc);
create index if not exists identity_security_events_type_time_idx on identity_security_events(event_type,created_at desc);

create or replace function identity_prevent_security_event_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'identity security events are immutable';
end;
$$;
drop trigger if exists identity_security_events_immutable on identity_security_events;
create trigger identity_security_events_immutable before update or delete on identity_security_events
for each row execute function identity_prevent_security_event_mutation();

create table if not exists identity_rate_limits (
  bucket_key text primary key,
  count integer not null check (count > 0),
  reset_at timestamptz not null
);
create index if not exists identity_rate_limits_reset_idx on identity_rate_limits(reset_at);
