-- Close the view back door around RLS.
--
-- A Postgres view runs with its OWNER's privileges unless told otherwise, and
-- the owner bypasses row-level security. So influencer_payouts and
-- influencer_payouts_due read the underlying tables as a privileged role no
-- matter who calls them — and Supabase grants anon SELECT on public-schema views
-- by default. Net effect: the anon key that ships inside the app could read
-- influencer handles, commission rates and revenue, despite every base table
-- having RLS with zero policies. Supabase's dashboard flags this as
-- "Data is publicly accessible via API as this is a Security definer view".
--
-- This is the same mistake as audit finding DATA-01 (referral_uses had a
-- permissive read policy and leaked user_id), arriving by a different route.
-- Views were the blind spot: locking the tables was not enough.
--
-- Two fixes, both applied:
--   1. security_invoker — the view is evaluated as the CALLER, so RLS on the
--      base tables applies and anon sees nothing. This is the correct semantic
--      fix and survives someone re-granting privileges later.
--   2. Revoke the grants anyway. Defence in depth: if a policy is ever added to
--      a base table by mistake, the missing grant still stops anon reading.

alter view influencer_payouts      set (security_invoker = on);
alter view influencer_payouts_due  set (security_invoker = on);

revoke all on influencer_payouts     from anon, authenticated;
revoke all on influencer_payouts_due from anon, authenticated;

-- Same treatment for the base tables. RLS already blocks these, but an explicit
-- revoke means a future accidental policy cannot open them on its own.
revoke all on influencers              from anon, authenticated;
revoke all on promo_codes              from anon, authenticated;
revoke all on code_redemptions         from anon, authenticated;
revoke all on transaction_attributions from anon, authenticated;
revoke all on revenue_events           from anon, authenticated;

-- Stop the next view from repeating the mistake.
alter default privileges in schema public revoke all on tables from anon, authenticated;
