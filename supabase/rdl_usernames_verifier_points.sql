-- RDL usernames and verifier-point system.
-- Run once in Supabase Dashboard > SQL Editor for project jcdzinddbqdygfewzotp.

create table if not exists public.rdl_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint rdl_profiles_username_format check (username ~ '^[A-Za-z0-9_]{3,20}$')
);

create unique index if not exists rdl_profiles_username_ci_unique
  on public.rdl_profiles (lower(username));

alter table public.rdl_profiles enable row level security;
revoke all on table public.rdl_profiles from anon, authenticated;
grant select on table public.rdl_profiles to anon, authenticated;

drop policy if exists "Anyone can search RDL usernames" on public.rdl_profiles;
create policy "Anyone can search RDL usernames"
  on public.rdl_profiles for select to anon, authenticated using (true);

alter table public.record_submissions
  add column if not exists verifier_user_id uuid references public.rdl_profiles(user_id) on delete set null,
  add column if not exists submitted_by_user_id uuid references auth.users(id) on delete set null;

create index if not exists record_submissions_verifier_user_id_idx
  on public.record_submissions (verifier_user_id)
  where verifier_user_id is not null;

create or replace function public.rdl_make_username(p_raw text)
returns text
language plpgsql
immutable
set search_path = public
as $function$
declare
  cleaned text;
begin
  cleaned := regexp_replace(coalesce(p_raw, ''), '[^A-Za-z0-9_]', '', 'g');
  cleaned := left(cleaned, 20);
  if length(cleaned) < 3 then
    cleaned := 'RDLUser';
  end if;
  return cleaned;
end;
$function$;

create or replace function public.rdl_create_profile_for_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $function$
declare
  requested_username text;
  base_username text;
  candidate text;
  suffix integer := 1;
begin
  requested_username := nullif(btrim(new.raw_user_meta_data->>'rdl_username'), '');
  if requested_username is not null then
    if requested_username !~ '^[A-Za-z0-9_]{3,20}$' then
      raise exception 'RDL username must be 3–20 characters using only letters, numbers, and underscores.';
    end if;
    if exists (select 1 from public.rdl_profiles p where lower(p.username) = lower(requested_username)) then
      raise exception 'That RDL username is already taken.';
    end if;
    candidate := requested_username;
  else
    base_username := public.rdl_make_username(coalesce(
      new.raw_user_meta_data->>'name',
      new.raw_user_meta_data->>'full_name',
      new.raw_user_meta_data->>'user_name',
      split_part(coalesce(new.email, ''), '@', 1),
      'RDLUser'
    ));
    candidate := base_username;
    while exists (select 1 from public.rdl_profiles p where lower(p.username) = lower(candidate)) loop
      suffix := suffix + 1;
      candidate := left(base_username, 20 - length(suffix::text)) || suffix::text;
    end loop;
  end if;

  insert into public.rdl_profiles(user_id, username)
  values (new.id, candidate)
  on conflict (user_id) do nothing;
  return new;
end;
$function$;

drop trigger if exists rdl_create_profile_after_auth_signup on auth.users;
create trigger rdl_create_profile_after_auth_signup
  after insert on auth.users
  for each row execute function public.rdl_create_profile_for_auth_user();

-- Backfill all existing Auth users with unique usernames based on their provider name/email.
do $function$
declare
  u record;
  base_username text;
  candidate text;
  suffix integer;
begin
  for u in
    select id, email, raw_user_meta_data
      from auth.users
     order by created_at, id
  loop
    if not exists (select 1 from public.rdl_profiles p where p.user_id = u.id) then
      base_username := public.rdl_make_username(coalesce(
        u.raw_user_meta_data->>'name',
        u.raw_user_meta_data->>'full_name',
        u.raw_user_meta_data->>'user_name',
        split_part(coalesce(u.email, ''), '@', 1),
        'RDLUser'
      ));
      candidate := base_username;
      suffix := 1;
      while exists (select 1 from public.rdl_profiles p where lower(p.username) = lower(candidate)) loop
        suffix := suffix + 1;
        candidate := left(base_username, 20 - length(suffix::text)) || suffix::text;
      end loop;
      insert into public.rdl_profiles(user_id, username)
      values (u.id, candidate);
    end if;
  end loop;
end;
$function$;

create or replace function public.set_rdl_username(p_username text)
returns text
language plpgsql
security definer
set search_path = public, auth
as $function$
declare
  clean_username text := btrim(coalesce(p_username, ''));
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Sign in to change your RDL username.';
  end if;
  if clean_username !~ '^[A-Za-z0-9_]{3,20}$' then
    raise exception 'Username must be 3–20 characters using only letters, numbers, and underscores.';
  end if;
  if exists (
    select 1 from public.rdl_profiles
     where lower(username) = lower(clean_username)
       and user_id <> current_user_id
  ) then
    raise exception 'That RDL username is already taken.';
  end if;

  insert into public.rdl_profiles(user_id, username, updated_at)
  values (current_user_id, clean_username, now())
  on conflict (user_id) do update
    set username = excluded.username, updated_at = now();

  return clean_username;
end;
$function$;

revoke all on function public.set_rdl_username(text) from public, anon;
grant execute on function public.set_rdl_username(text) to authenticated;

-- Only award points for newly approved 100% completions. Old rows have a NULL verifier_user_id.
-- A selected verifier must be a real RDL profile and cannot verify their own authenticated submission.
create or replace function public.rdl_validate_verifier()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $function$
begin
  if new.verifier_user_id is not null then
    if not exists (select 1 from public.rdl_profiles p where p.user_id = new.verifier_user_id) then
      raise exception 'Select an existing RDL user as verifier.';
    end if;
    if new.submitted_by_user_id is not null and new.verifier_user_id = new.submitted_by_user_id then
      raise exception 'You cannot verify your own submission.';
    end if;
  end if;
  return new;
end;
$function$;

drop trigger if exists rdl_validate_verifier_before_record_write on public.record_submissions;
create trigger rdl_validate_verifier_before_record_write
  before insert or update of verifier_user_id, submitted_by_user_id on public.record_submissions
  for each row execute function public.rdl_validate_verifier();

comment on column public.record_submissions.verifier_user_id is
  'RDL account that verified the completion. One point is counted only while the record is approved at 100%.';
comment on column public.record_submissions.submitted_by_user_id is
  'Authenticated RDL account that submitted the record, used to prevent self-verification.';
