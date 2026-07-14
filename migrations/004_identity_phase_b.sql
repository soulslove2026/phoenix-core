create table if not exists identity_passkeys (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  credential_id text not null unique,
  webauthn_user_id text not null,
  public_key bytea not null,
  counter bigint not null default 0 check (counter >= 0),
  device_type text not null check (device_type in ('singleDevice','multiDevice')),
  backed_up boolean not null,
  transports text[] not null default '{}',
  label text not null check (char_length(label) between 1 and 64),
  created_at timestamptz not null default now(),
  last_used_at timestamptz null
);
create index if not exists identity_passkeys_user_idx on identity_passkeys(user_id,created_at desc);

create table if not exists identity_webauthn_challenges (
  id uuid primary key,
  user_id uuid null references identity_users(id) on delete cascade,
  purpose text not null check (purpose in ('register','authenticate')),
  challenge_ciphertext text not null,
  challenge_iv text not null,
  challenge_auth_tag text not null,
  ip_hash text not null,
  user_agent_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  check (expires_at > created_at)
);
create index if not exists identity_webauthn_challenges_active_idx on identity_webauthn_challenges(expires_at) where consumed_at is null;

create table if not exists identity_totp_enrollments (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  secret_ciphertext text not null,
  secret_iv text not null,
  secret_auth_tag text not null,
  ip_hash text not null,
  user_agent_hash text not null,
  attempts integer not null default 0 check (attempts >= 0),
  max_attempts integer not null check (max_attempts between 1 and 20),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  check (expires_at > created_at)
);
create unique index if not exists identity_totp_enrollments_one_active_idx on identity_totp_enrollments(user_id) where consumed_at is null;

create table if not exists identity_totp_factors (
  id uuid primary key,
  user_id uuid not null unique references identity_users(id) on delete cascade,
  secret_ciphertext text not null,
  secret_iv text not null,
  secret_auth_tag text not null,
  algorithm text not null default 'SHA1' check (algorithm='SHA1'),
  digits integer not null default 6 check (digits=6),
  period_seconds integer not null default 30 check (period_seconds=30),
  last_used_step bigint not null default -1,
  enabled_at timestamptz not null default now(),
  disabled_at timestamptz null
);

create table if not exists identity_recovery_codes (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  code_hash text not null unique,
  created_at timestamptz not null default now(),
  consumed_at timestamptz null
);
create index if not exists identity_recovery_codes_active_idx on identity_recovery_codes(user_id) where consumed_at is null;

create table if not exists identity_mfa_transactions (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  token_hash text not null unique,
  ip_hash text not null,
  user_agent_hash text not null,
  attempts integer not null default 0 check (attempts >= 0),
  max_attempts integer not null check (max_attempts between 1 and 20),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  check (expires_at > created_at)
);
create index if not exists identity_mfa_transactions_active_idx on identity_mfa_transactions(expires_at) where consumed_at is null;

create table if not exists identity_session_assurance (
  session_id uuid primary key references identity_sessions(id) on delete cascade,
  user_id uuid not null references identity_users(id) on delete cascade,
  method text not null check (method in ('email_verification','password','password_totp','recovery_code','passkey','passkey_step_up')),
  assurance_level smallint not null check (assurance_level in (1,2)),
  authenticated_at timestamptz not null,
  authenticator_id uuid null references identity_passkeys(id) on delete set null
);
create index if not exists identity_session_assurance_user_idx on identity_session_assurance(user_id,authenticated_at desc);
insert into identity_session_assurance(session_id,user_id,method,assurance_level,authenticated_at)
select id,user_id,'password',1,created_at from identity_sessions
on conflict (session_id) do nothing;

alter table identity_notification_outbox add column if not exists locked_at timestamptz null;
alter table identity_notification_outbox add column if not exists lock_token uuid null;
alter table identity_notification_outbox add column if not exists last_error_code text null;
alter table identity_notification_outbox add column if not exists dead_lettered_at timestamptz null;
drop index if exists identity_notification_outbox_pending_idx;
create index if not exists identity_notification_outbox_pending_idx on identity_notification_outbox(available_at,created_at)
where sent_at is null and dead_lettered_at is null;
