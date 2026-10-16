-- FirstAid Hub: run this whole file once in Supabase -> SQL Editor -> New query -> Run

create table profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  created_at timestamptz default now()
);
create table login_events (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  email text not null,
  created_at timestamptz default now()
);
create table messages (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  email text not null,
  text text not null check (char_length(text) between 1 and 500),
  created_at timestamptz default now()
);
create table admins (user_id uuid primary key references auth.users on delete cascade);
create table viewers (
  user_id uuid primary key references auth.users on delete cascade,
  email text,
  created_at timestamptz default now()
);
create table app_config (id int primary key default 1 check (id = 1), passkey text);
insert into app_config (id) values (1);

alter table profiles enable row level security;
alter table login_events enable row level security;
alter table messages enable row level security;
alter table admins enable row level security;
alter table viewers enable row level security;
alter table app_config enable row level security;   -- no policies: nobody can read the passkey directly

-- Role helpers
create function is_admin() returns boolean language sql security definer set search_path = public stable as
$$ select exists (select 1 from admins where user_id = auth.uid()) $$;

create function is_staff() returns boolean language sql security definer set search_path = public stable as
$$ select exists (select 1 from admins where user_id = auth.uid())
       or exists (select 1 from viewers where user_id = auth.uid()) $$;

create function my_role() returns text language sql security definer set search_path = public stable as
$$ select case when is_admin() then 'admin' when is_staff() then 'staff' else 'user' end $$;

-- Passkey: anyone logged in can try a key; only a correct key grants viewer access
create function redeem_passkey(k text) returns boolean language plpgsql security definer set search_path = public as $$
declare real_key text;
begin
  if auth.uid() is null then return false; end if;
  select passkey into real_key from app_config where id = 1;
  if real_key is null or real_key = '' or k is distinct from real_key then return false; end if;
  insert into viewers (user_id, email) values (auth.uid(), auth.jwt() ->> 'email') on conflict do nothing;
  return true;
end $$;

-- Only the admin can change the passkey
create function set_passkey(k text) returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'not allowed'; end if;
  update app_config set passkey = k where id = 1;
end $$;

-- Save every new account's email automatically (passwords stay hashed inside Supabase Auth)
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email) values (new.id, new.email);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- Permissions (row level security)
create policy "read profiles" on profiles for select to authenticated
  using (id = auth.uid() or is_staff());
create policy "log own login" on login_events for insert to authenticated
  with check (user_id = auth.uid() and email = (auth.jwt() ->> 'email'));
create policy "staff read logins" on login_events for select to authenticated
  using (is_staff());
create policy "read chat" on messages for select to authenticated using (true);
create policy "send chat" on messages for insert to authenticated
  with check (user_id = auth.uid() and email = (auth.jwt() ->> 'email'));
create policy "admin delete chat" on messages for delete to authenticated
  using (is_admin());
create policy "admin read viewers" on viewers for select to authenticated using (is_admin());
create policy "admin remove viewers" on viewers for delete to authenticated using (is_admin());

-- Live updates for chat and login history
alter publication supabase_realtime add table messages, login_events;