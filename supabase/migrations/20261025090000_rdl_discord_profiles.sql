create table if not exists public.rdl_discord_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  discord_id text not null unique,
  discord_username text not null,
  discord_global_name text,
  updated_at timestamptz not null default now()
);

alter table public.rdl_discord_profiles enable row level security;

grant select on public.rdl_discord_profiles to anon, authenticated;
revoke insert, update, delete on public.rdl_discord_profiles from anon, authenticated;

drop policy if exists "Public can read linked Discord profiles" on public.rdl_discord_profiles;
create policy "Public can read linked Discord profiles"
  on public.rdl_discord_profiles
  for select
  to anon, authenticated
  using (true);
