-- Allows only the configured RDL owner account to clear changelog entries.
-- Apply this migration in the Supabase SQL Editor if migrations are not auto-applied.

create or replace function public.reset_rdl_changelog()
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if lower(coalesce(auth.jwt() ->> 'email', '')) <> 'tyalamoon@outlook.com'
     or not coalesce(public.is_rdl_owner(), false) then
    raise exception 'Only the designated RDL owner may reset the changelog'
      using errcode = '42501';
  end if;

  delete from public.rdl_changelog;
end;
$$;

revoke all on function public.reset_rdl_changelog() from public;
grant execute on function public.reset_rdl_changelog() to authenticated;
