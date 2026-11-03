-- 005: take EXECUTE on delete_user() away from anon.
--
-- Found in the 2026-11-03 security pass. Calling the RPC with nothing but the
-- bundled anon key returns 204:
--
--   curl -X POST "$SUPABASE_URL/rest/v1/rpc/delete_user" \
--        -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
--
-- That 204 is harmless today. delete_user() is SECURITY DEFINER but scoped to
-- auth.uid(), which is NULL for an anonymous caller, so it matches no rows and
-- deletes nothing. This is NOT a mass-deletion vector and was not one before
-- this migration.
--
-- It is revoked anyway, for the same reason 004 revoked grants that RLS already
-- covered: the safety here rests entirely on one auth.uid() predicate inside a
-- SECURITY DEFINER function — a function that, by definition, runs with the
-- owner's privileges and bypasses RLS. That is a single point of failure one
-- careless edit away from being a real mass-deletion vector, and the edit would
-- look innocuous in review. Removing the grant means anon cannot reach the
-- function at all, so the predicate stops being the only thing standing between
-- an anonymous caller and a DELETE.
--
-- Safe for the app: the in-app "delete my account" flow sends the user's access
-- token, so PostgREST runs it as `authenticated`, which keeps its grant.

revoke execute on function public.delete_user() from anon;

-- Belt and braces, matching the posture 004 established: stop the NEXT
-- SECURITY DEFINER function from being reachable by anon the moment it is
-- created. Postgres grants EXECUTE to PUBLIC on new functions by default, which
-- is how this one ended up callable in the first place.
alter default privileges in schema public revoke execute on functions from anon;

-- Verify (expect 0 rows). Re-run after applying:
--
--   select p.proname, a.rolname
--   from pg_proc p
--   join pg_namespace n on n.oid = p.pronamespace
--   cross join lateral (select rolname from pg_roles where rolname = 'anon') a
--   where n.nspname = 'public'
--     and has_function_privilege(a.rolname, p.oid, 'execute');
--
-- And from outside, which is the check that actually counts — an explicit
-- 42501 is the evidence, not an empty result:
--
--   curl -X POST "$SUPABASE_URL/rest/v1/rpc/delete_user" \
--        -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
--   -- expect: {"code":"42501", ... "permission denied for function delete_user"}
