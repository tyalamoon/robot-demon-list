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


-- Owner-only rank insertion/reordering. Rebuilds the approved display ranks atomically:
-- inserting at a rank shifts following levels down; moving an existing level
-- also closes the gap at its former position.
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
  current_display_rank bigint;
begin
  if not coalesce(public.is_rdl_owner(), false) then
    raise exception 'Only the RDL owner can change leaderboard rankings.';
  end if;

  if p_rank_position is not null and p_rank_position < 1 then
    raise exception 'Rank must be a positive whole number.';
  end if;

  -- Serialize ranking changes so two owner actions cannot interleave.
  lock table public.record_submissions in share row exclusive mode;

  if not exists (
    select 1 from public.record_submissions
     where id = p_record_id and status = 'approved'
  ) then
    raise exception 'Approved record not found.';
  end if;

  if p_rank_position is null then
    update public.record_submissions
       set rank_position = null
     where id = p_record_id and status = 'approved';
    return;
  end if;

  create temporary table if not exists rdl_rank_shift_stage (
    record_id bigint primary key,
    old_rank bigint not null,
    new_rank bigint not null
  ) on commit drop;
  truncate table rdl_rank_shift_stage;

  -- Match getDisplayRanks(): explicit ranks first, then automatic records
  -- ordered by percent descending and submitted_at ascending.
  insert into rdl_rank_shift_stage (record_id, old_rank, new_rank)
  with approved as (
    select id, rank_position, percent, submitted_at
      from public.record_submissions
     where status = 'approved'
  ),
  highest as (
    select coalesce(max(rank_position), 0) as max_rank
      from approved
     where rank_position is not null
  ),
  display_ranked as (
    select id, rank_position as old_rank
      from approved
     where rank_position is not null
    union all
    select a.id,
           h.max_rank + row_number() over (
             order by a.percent desc, a.submitted_at asc, a.id
           ) as old_rank
      from approved a
      cross join highest h
     where a.rank_position is null
  )
  select id, old_rank, old_rank
    from display_ranked;

  select old_rank
    into current_display_rank
    from rdl_rank_shift_stage
   where record_id = p_record_id;

  -- Moving a level upward shifts the intervening levels down.
  -- Moving it downward closes its old gap by shifting intervening levels up.
  update rdl_rank_shift_stage
     set new_rank = case
       when record_id = p_record_id then p_rank_position
       when current_display_rank < p_rank_position
         and old_rank > current_display_rank
         and old_rank <= p_rank_position
         then old_rank - 1
       when current_display_rank > p_rank_position
         and old_rank >= p_rank_position
         and old_rank < current_display_rank
         then old_rank + 1
       else old_rank
     end;

  -- Null ranks first to avoid transient collisions with the unique-rank index,
  -- then restore the complete reordered ranking within this same transaction.
  update public.record_submissions
     set rank_position = null
   where status = 'approved';

  update public.record_submissions r
     set rank_position = s.new_rank
    from rdl_rank_shift_stage s
   where r.id = s.record_id;
end;
$function$;

revoke all on function public.set_rdl_record_rank(bigint, bigint) from public, anon;
grant execute on function public.set_rdl_record_rank(bigint, bigint) to authenticated;

-- Approval of a suggested level uses the same insertion/reordering function,
-- so accepting a suggestion at an occupied rank never replaces the occupant.
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
  above_level_name text;
  below_level_name text;
  changelog_message text;
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
  end;

  level_note := 'RDL_LEVEL_SUGGESTION:' || contribution_row.id::text
    || ' | list=' || suggested_list
    || ' | level_id=' || suggested_level_id
    || ' | verifier=' || suggested_verifier;

  insert into public.record_submissions
    (player_name, level_name, percent, proof_url, notes, status, rank_position)
  values
    (suggested_author, suggested_name, 0, suggested_youtube, level_note, 'approved', null)
  returning id into inserted_record_id;

  perform public.set_rdl_record_rank(inserted_record_id, suggested_rank);

  select level_name
    into above_level_name
    from public.record_submissions
   where status = 'approved'
     and rank_position = suggested_rank - 1
     and id <> inserted_record_id
   order by id
   limit 1;

  select level_name
    into below_level_name
    from public.record_submissions
   where status = 'approved'
     and rank_position = suggested_rank + 1
     and id <> inserted_record_id
   order by id
   limit 1;

  changelog_message := suggested_name || ' was placed at #' || suggested_rank::text;
  if above_level_name is not null then
    changelog_message := changelog_message || ', below ' || above_level_name;
  end if;
  if below_level_name is not null then
    changelog_message := changelog_message || ' and above ' || below_level_name;
  end if;
  changelog_message := changelog_message || '.';

  insert into public.rdl_changelog (message)
  values (changelog_message);

  update public.rdl_contributions
     set status = 'approved'
   where id = contribution_row.id;
end;
$function$;

revoke all on function public.approve_rdl_level_suggestion(bigint) from public, anon;
grant execute on function public.approve_rdl_level_suggestion(bigint) to authenticated;
