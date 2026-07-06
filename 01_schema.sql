-- =============================================================
-- ObservAItion — Supabase Schema
-- Drop old tables if re-running
-- =============================================================

drop table if exists licenses cascade;
drop table if exists users cascade;
drop table if exists admin_config cascade;

drop function if exists verify_user cascade;
drop function if exists add_license_admin cascade;
drop function if exists reset_hwid_admin cascade;
drop function if exists revoke_license_admin cascade;

-- =============================================================
-- USERS — Discord ID + HWID binding
-- =============================================================
create table users (
  discord_id  text primary key,
  hwid        text,
  created_at  timestamptz not null default now()
);

-- =============================================================
-- LICENSES — one user can have multiple, only the latest active one counts
-- =============================================================
create table licenses (
  id           bigint generated always as identity primary key,
  discord_id   text not null references users(discord_id) on delete cascade,
  type         text not null check (type in ('1d','7d','30d','90d','lifetime')),
  activated_at timestamptz,
  expires_at   timestamptz,
  active       boolean not null default true,
  created_at   timestamptz not null default now()
);

-- =============================================================
-- ADMIN CONFIG — md5 hashed password (no extensions needed)
-- =============================================================
create table admin_config (
  id       int primary key default 1 check (id = 1),
  password text not null       -- md5 hash
);

-- Insert default admin password (md5 of '!Th3Sep@ration$')
insert into admin_config (id, password)
values (1, '7111d5a6b558613b30e5221f75b0a6bf')
on conflict (id) do nothing;

-- =============================================================
-- RPC: VERIFY USER
-- Called by .pyd on script launch
--  - If first activation, binds HWID
--  - Returns active license info
-- =============================================================
create or replace function verify_user(
  p_discord_id text,
  p_hwid       text
) returns json
language plpgsql security definer as $$
declare
  v_user       users%rowtype;
  v_license    licenses%rowtype;
  v_is_new     boolean := false;
  v_hwid_ok    boolean := false;
  v_valid      boolean := false;
  v_remaining  int;
  v_expires    timestamptz;
  v_lifetime   boolean := false;
  v_message    text;
begin
  -- Upsert user (first activation binds HWID)
  insert into users (discord_id, hwid)
  values (p_discord_id, p_hwid)
  on conflict (discord_id) do update
    set hwid = case
      when users.hwid is null then excluded.hwid
      else users.hwid
    end
  returning * into v_user;

  -- Check HWID match
  if v_user.hwid = p_hwid then
    v_hwid_ok := true;
  end if;

  -- Find the latest active license
  select * into v_license
  from licenses
  where discord_id = p_discord_id
    and active = true
    and (expires_at is null or expires_at > now())
  order by
    case when type = 'lifetime' then 0 else 1 end,
    created_at desc
  limit 1;

  if v_license.id is not null then
    v_valid := true;
    v_lifetime := (v_license.type = 'lifetime');

    if v_lifetime then
      v_remaining := 99999;
      v_expires := null;
    else
      v_remaining := extract(epoch from (v_license.expires_at - now())) / 86400;
      v_expires := v_license.expires_at;
    end if;

    -- Activate license if not yet activated
    if v_license.activated_at is null then
      update licenses set activated_at = now()
      where id = v_license.id;
    end if;

    v_message := 'ok';
  else
    -- Check if there's an expired or revoked license
    select * into v_license
    from licenses
    where discord_id = p_discord_id
    order by created_at desc
    limit 1;

    if v_license.id is not null then
      if v_license.active = false then
        v_message := 'revoked';
      else
        v_message := 'expired';
      end if;
    else
      v_message := 'no_license';
    end if;

    v_remaining := 0;
    v_expires := null;
  end if;

  return json_build_object(
    'valid',        v_valid,
    'hwid_ok',      v_hwid_ok,
    'remaining_days', v_remaining,
    'expires_at',   v_expires,
    'is_lifetime',  v_lifetime,
    'message',      v_message
  );
end;
$$;

-- =============================================================
-- RPC: ADD LICENSE (admin, password-protected)
-- =============================================================
create or replace function add_license_admin(
  p_discord_id text,
  p_type       text,
  p_password   text
) returns json
language plpgsql security definer as $$
declare
  v_stored    text;
  v_expires   timestamptz;
  v_days      int;
begin
  select password into v_stored from admin_config where id = 1;
  if v_stored is null or v_stored <> md5(p_password) then
    return json_build_object('success', false, 'error', 'invalid password');
  end if;

  if p_type not in ('1d','7d','30d','90d','lifetime') then
    return json_build_object('success', false, 'error', 'invalid type');
  end if;

  -- Ensure user exists
  insert into users (discord_id) values (p_discord_id)
  on conflict (discord_id) do nothing;

  -- Calculate expiry
  v_days := case p_type
    when '1d'       then 1
    when '7d'       then 7
    when '30d'      then 30
    when '90d'      then 90
    when 'lifetime' then null
  end;

  if p_type = 'lifetime' then
    v_expires := null;
  else
    v_expires := now() + (v_days || ' days')::interval;
  end if;

  insert into licenses (discord_id, type, expires_at)
  values (p_discord_id, p_type, v_expires);

  return json_build_object(
    'success', true,
    'discord_id', p_discord_id,
    'type', p_type,
    'expires_at', v_expires
  );
end;
$$;

-- =============================================================
-- RPC: RESET HWID (admin, password-protected)
-- =============================================================
create or replace function reset_hwid_admin(
  p_discord_id text,
  p_password   text
) returns json
language plpgsql security definer as $$
declare
  v_stored text;
begin
  select password into v_stored from admin_config where id = 1;
  if v_stored is null or v_stored <> md5(p_password) then
    return json_build_object('success', false, 'error', 'invalid password');
  end if;

  update users set hwid = null
  where discord_id = p_discord_id;

  if found then
    return json_build_object('success', true, 'discord_id', p_discord_id);
  else
    return json_build_object('success', false, 'error', 'user not found');
  end if;
end;
$$;

-- =============================================================
-- RPC: REVOKE LICENSE (admin, password-protected)
-- =============================================================
create or replace function revoke_license_admin(
  p_discord_id  text,
  p_password    text
) returns json
language plpgsql security definer as $$
declare
  v_stored text;
begin
  select password into v_stored from admin_config where id = 1;
  if v_stored is null or v_stored <> md5(p_password) then
    return json_build_object('success', false, 'error', 'invalid password');
  end if;

  update licenses set active = false
  where discord_id = p_discord_id and active = true;

  if found then
    return json_build_object('success', true, 'discord_id', p_discord_id);
  else
    return json_build_object('success', false, 'error', 'no active license found');
  end if;
end;
$$;

-- =============================================================
-- RPC: CHECK REMAINING (called every 60s during a session)
-- Lightweight — no HWID check, just license validity
-- =============================================================
create or replace function check_remaining(p_discord_id text)
returns json
language plpgsql security definer as $$
declare
  v_license licenses%rowtype;
  v_remaining int;
  v_valid boolean := false;
  v_message text;
begin
  select * into v_license
  from licenses
  where discord_id = p_discord_id
    and active = true
    and (expires_at is null or expires_at > now())
  order by
    case when type = 'lifetime' then 0 else 1 end,
    created_at desc
  limit 1;

  if v_license.id is not null then
    v_valid := true;
    if v_license.type = 'lifetime' then
      v_remaining := 99999;
    else
      v_remaining := extract(epoch from (v_license.expires_at - now())) / 86400;
    end if;
    v_message := 'ok';
  else
    select * into v_license
    from licenses
    where discord_id = p_discord_id
    order by created_at desc
    limit 1;

    if v_license.id is null then
      v_message := 'no_license';
    elsif v_license.active = false then
      v_message := 'revoked';
    else
      v_message := 'expired';
    end if;
    v_remaining := 0;
  end if;

  return json_build_object(
    'valid', v_valid,
    'remaining_days', v_remaining,
    'message', v_message
  );
end;
$$;

-- =============================================================
-- RPC: EXTEND LICENSE (admin, password-protected)
-- Adds N days to the active license's expiry
-- =============================================================
create or replace function extend_license_admin(
  p_discord_id text,
  p_days       int,
  p_password   text
) returns json
language plpgsql security definer as $$
declare
  v_stored text;
  v_license licenses%rowtype;
begin
  select password into v_stored from admin_config where id = 1;
  if v_stored is null or v_stored <> md5(p_password) then
    return json_build_object('success', false, 'error', 'invalid password');
  end if;

  if p_days not in (1,2,3,4,5,6,7) then
    return json_build_object('success', false, 'error', 'days must be 1-7');
  end if;

  select * into v_license
  from licenses
  where discord_id = p_discord_id
    and active = true
    and (expires_at is null or expires_at > now())
  order by
    case when type = 'lifetime' then 0 else 1 end,
    created_at desc
  limit 1;

  if v_license.id is null then
    return json_build_object('success', false, 'error', 'no active license found');
  end if;

  if v_license.type = 'lifetime' then
    return json_build_object('success', false, 'error', 'cannot extend a lifetime license');
  end if;

  update licenses
  set expires_at = expires_at + (p_days || ' days')::interval
  where id = v_license.id;

  return json_build_object(
    'success', true,
    'discord_id', p_discord_id,
    'new_expires_at', (select expires_at from licenses where id = v_license.id),
    'days_added', p_days
  );
end;
$$;

-- =============================================================
-- RPC: LIST USERS (admin, password-protected)
-- Shows all users with their latest license info
-- =============================================================
create or replace function list_users_admin(p_password text)
returns json
language plpgsql security definer as $$
declare
  v_stored text;
  v_result json;
begin
  select password into v_stored from admin_config where id = 1;
  if v_stored is null or v_stored <> md5(p_password) then
    return json_build_object('success', false, 'error', 'invalid password');
  end if;

  select json_agg(
    json_build_object(
      'discord_id',   u.discord_id,
      'hwid',         u.hwid,
      'created_at',   u.created_at,
      'license',      case when l.id is not null then
        json_build_object(
          'id',         l.id,
          'type',       l.type,
          'active',     l.active,
          'activated_at', l.activated_at,
          'expires_at', l.expires_at,
          'created_at', l.created_at
        )
      else null end
    )
    order by u.created_at desc
  ) into v_result
  from users u
  cross join lateral (
    select * from licenses
    where discord_id = u.discord_id
      and active = true
      and (expires_at is null or expires_at > now())
    order by
      case when type = 'lifetime' then 0 else 1 end,
      created_at desc
    limit 1
  ) l;

  return json_build_object('success', true, 'users', coalesce(v_result, '[]'::json));
end;
$$;

-- =============================================================
-- RLS: Allow anon to call RPCs
-- =============================================================
alter table users    enable row level security;
alter table licenses enable row level security;
alter table admin_config enable row level security;

-- Allow anon to read nothing from tables (RPCs handle everything)
create policy anon_block on users    for select using (false);
create policy anon_block on licenses for select using (false);
create policy anon_block on admin_config for select using (false);

-- Grant anon access to RPCs
grant usage on schema public to anon;
grant execute on function verify_user(text, text) to anon;
grant execute on function add_license_admin(text, text, text) to anon;
grant execute on function reset_hwid_admin(text, text) to anon;
grant execute on function revoke_license_admin(text, text) to anon;
grant execute on function check_remaining(text) to anon;
grant execute on function extend_license_admin(text, int, text) to anon;
grant execute on function list_users_admin(text) to anon;
