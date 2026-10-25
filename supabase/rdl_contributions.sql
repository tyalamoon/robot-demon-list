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
