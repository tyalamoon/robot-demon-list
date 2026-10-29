-- Secure owner-only access for the RDL contributions inbox.
-- Run in Supabase Dashboard > SQL Editor for project jcdzinddbqdygfewzotp.
-- Uses the existing public.is_rdl_owner() function used by index.html.

alter table public.rdl_contributions enable row level security;

revoke all on table public.rdl_contributions from anon, authenticated;
grant insert on table public.rdl_contributions to anon, authenticated;
grant usage, select on sequence public.rdl_contributions_id_seq to anon, authenticated;
grant select, update on table public.rdl_contributions to authenticated;

drop policy if exists "Anyone can submit pending RDL contributions" on public.rdl_contributions;
create policy "Anyone can submit pending RDL contributions"
  on public.rdl_contributions
  for insert
  to anon, authenticated
  with check (
    status = 'pending'
    and jsonb_typeof(payload) = 'object'
    and pg_column_size(payload) <= 12000
    and contribution_type in (
      'general_suggestion',
      'level_suggestion',
      'level_pack_suggestion',
      'list_change_suggestion',
      'idea'
    )
  );

drop policy if exists "RDL owner can view contributions" on public.rdl_contributions;
create policy "RDL owner can view contributions"
  on public.rdl_contributions
  for select
  to authenticated
  using ((select public.is_rdl_owner()));

drop policy if exists "RDL owner can review contributions" on public.rdl_contributions;
create policy "RDL owner can review contributions"
  on public.rdl_contributions
  for update
  to authenticated
  using ((select public.is_rdl_owner()))
  with check ((select public.is_rdl_owner()));

 
-- Owner-only, atomic approval for a suggested level. Unlike general suggestions,
-- approving a level creates a public list entry before marking the contribution approved.
create or replace function public.approve_rdl_level_suggestion(p_contribution_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $function$
declare
  contribution_row public.rdl_contributions%rowtype;
  inserted_record_id public.record_submissions.id%type;
  suggested_rank bigint;
  suggested_name text;
  suggested_author text;
  suggested_verifier text;
  suggested_list text;
  suggested_level_id text;
  suggested_youtube text;
  level_note text;
  previous_level_name text;
begin
  if not coalesce(public.is_rdl_owner(), false) then
    raise exception 'Only the RDL owner can approve level suggestions.';
  end if;

  select *
    into contribution_row
    from public.rdl_contributions
   where id = p_contribution_id
     and contribution_type = 'level_suggestion'
     and status = 'pending'
   for update;

  if not found then
    raise exception 'This pending level suggestion was not found. Refresh the admin inbox.';
  end if;

  suggested_name := nullif(btrim(contribution_row.payload->>'level_name'), '');
  suggested_author := nullif(btrim(contribution_row.payload->>'author'), '');
  suggested_verifier := nullif(btrim(contribution_row.payload->>'verifier'), '');
  suggested_list := nullif(btrim(contribution_row.payload->>'list'), '');
  suggested_level_id := nullif(btrim(contribution_row.payload->>'level_id'), '');
  suggested_youtube := nullif(btrim(contribution_row.payload->>'youtube_link'), '');

  if suggested_name is null or suggested_author is null or suggested_verifier is null
     or suggested_list is null or suggested_level_id is null or suggested_youtube is null then
    raise exception 'The level suggestion is missing a required field.';
  end if;

  if suggested_list not in ('Classic', 'Platformer List') then
    raise exception 'Unsupported RDL list: %', suggested_list;
  end if;

  begin
    suggested_rank := (contribution_row.payload->>'desired_position')::bigint;
  exception when others then
    raise exception 'The suggested position must be a positive whole number.';
  end;

  if suggested_rank < 1 then
    raise exception 'The suggested position must be a positive whole number.';
  end if;

  level_note := 'RDL_LEVEL_SUGGESTION:' || contribution_row.id::text
    || ' | list=' || suggested_list
    || ' | level_id=' || suggested_level_id
    || ' | verifier=' || suggested_verifier;

  -- Read and clear the current occupant before inserting, because the table
  -- enforces unique approved ranks and would reject a duplicate rank at INSERT.
  select level_name
    into previous_level_name
    from public.record_submissions
   where status = 'approved'
     and rank_position = suggested_rank
   order by id
   limit 1
   for update;

  update public.record_submissions
     set rank_position = null
   where status = 'approved'
     and rank_position = suggested_rank;

  insert into public.record_submissions
    (player_name, level_name, percent, proof_url, notes, status, rank_position)
  values
    (suggested_author, suggested_name, 0, suggested_youtube, level_note, 'approved', suggested_rank)
  returning id into inserted_record_id;

  if previous_level_name is not null and previous_level_name <> suggested_name then
    insert into public.rdl_changelog (message)
    values (suggested_name || ' was placed at #' || suggested_rank::text
      || ', above ' || previous_level_name || '.');
  else
    insert into public.rdl_changelog (message)
    values (suggested_name || ' was placed at #' || suggested_rank::text || '.');
  end if;

  update public.rdl_contributions
     set status = 'approved'
   where id = contribution_row.id;
end;
$function$;

revoke all on function public.approve_rdl_level_suggestion(bigint) from public, anon;
grant execute on function public.approve_rdl_level_suggestion(bigint) to authenticated;


-- Public changelog for automatic leaderboard-change announcements.
create table if not exists public.rdl_changelog (
  id bigint generated by default as identity primary key,
  message text not null check (char_length(message) between 1 and 500),
  created_at timestamptz not null default now()
);

alter table public.rdl_changelog enable row level security;
revoke all on table public.rdl_changelog from anon, authenticated;
grant select on table public.rdl_changelog to anon, authenticated;
grant insert on table public.rdl_changelog to authenticated;

drop policy if exists "Anyone can read RDL changelog" on public.rdl_changelog;
create policy "Anyone can read RDL changelog"
  on public.rdl_changelog for select
  to anon, authenticated
  using (true);

drop policy if exists "RDL owner can add changelog entries" on public.rdl_changelog;
create policy "RDL owner can add changelog entries"
  on public.rdl_changelog for insert
  to authenticated
  with check (
    (select public.is_rdl_owner())
    and char_length(message) between 1 and 500
  );


-- Owner-only rank insertion. Occupied ranks shift down atomically instead of
-- being cleared/replaced. Rank updates are staged through a temporary table to
-- avoid collisions with the unique approved-rank constraint.
create or replace function public.set_rdl_record_rank(
  p_record_id bigint,
  p_rank_position bigint
)
returns void
language plpgsql
security definer
set search_path = public
as $function$
declare
  current_rank bigint;
begin
  if not coalesce(public.is_rdl_owner(), false) then
    raise exception 'Only the RDL owner can change leaderboard rankings.';
  end if;

  if p_rank_position is not null and p_rank_position < 1 then
    raise exception 'Rank must be a positive whole number.';
  end if;

  select rank_position
    into current_rank
    from public.record_submissions
   where id = p_record_id and status = 'approved'
   for update;

  if not found then
    raise exception 'Approved record not found.';
  end if;

  if p_rank_position is null then
    update public.record_submissions
       set rank_position = null
     where id = p_record_id and status = 'approved';
    return;
  end if;

  -- If the record already has a rank, free its old slot first.
  update public.record_submissions
     set rank_position = null
   where id = p_record_id and status = 'approved';

  -- Preserve every occupant at the requested rank and below, shifting each
  -- one position down. Temporarily null these ranks to satisfy uniqueness.
  create temporary table if not exists rdl_rank_shift_stage (
    record_id bigint primary key,
    shifted_rank bigint not null
  ) on commit drop;
  truncate table rdl_rank_shift_stage;

  insert into rdl_rank_shift_stage (record_id, shifted_rank)
  select id, rank_position + 1
    from public.record_submissions
   where status = 'approved'
     and rank_position >= p_rank_position
     and id <> p_record_id
   order by rank_position desc
   for update;

  update public.record_submissions
     set rank_position = null
   where status = 'approved'
     and rank_position >= p_rank_position
     and id <> p_record_id;

  update public.record_submissions r
     set rank_position = s.shifted_rank
    from rdl_rank_shift_stage s
   where r.id = s.record_id;

  update public.record_submissions
     set rank_position = p_rank_position
   where id = p_record_id and status = 'approved';
end;
$function$;

revoke all on function public.set_rdl_record_rank(bigint, bigint) from public, anon;
grant execute on function public.set_rdl_record_rank(bigint, bigint) to authenticated;
