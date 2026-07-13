create table if not exists identity_users (
  id uuid primary key,
  email text not null,
  display_name text not null,
  password_hash text not null,
  status text not null default 'active' check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists identity_users_email_unique
  on identity_users (lower(email));

create table if not exists identity_sessions (
  id uuid primary key,
  user_id uuid not null references identity_users(id) on delete cascade,
  token_hash text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz null
);

create index if not exists identity_sessions_user_id_idx on identity_sessions(user_id);
create index if not exists identity_sessions_active_idx
  on identity_sessions(token_hash)
  where revoked_at is null;
