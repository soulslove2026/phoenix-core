create or replace function identity_set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists identity_users_set_updated_at on identity_users;
create trigger identity_users_set_updated_at
before update on identity_users
for each row execute function identity_set_updated_at();

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'identity_users_email_normalized_check'
  ) then
    alter table identity_users
      add constraint identity_users_email_normalized_check
      check (email = lower(btrim(email)) and char_length(email) between 3 and 320);
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'identity_users_display_name_length_check'
  ) then
    alter table identity_users
      add constraint identity_users_display_name_length_check
      check (char_length(btrim(display_name)) between 2 and 80);
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'identity_sessions_expiry_check'
  ) then
    alter table identity_sessions
      add constraint identity_sessions_expiry_check
      check (expires_at > created_at);
  end if;
end;
$$;
