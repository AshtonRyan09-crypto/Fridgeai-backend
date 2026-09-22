-- Record of free access granted outside the App Store.
--
-- Promotional entitlements are granted in the RevenueCat dashboard, which has no
-- notion of WHY someone has free access, WHO approved it, or what to do when the
-- arrangement ends. Six months later, "which of these 4,000 customers is the
-- influencer we stopped working with" is unanswerable from RevenueCat alone.
-- This table is the answer: grant it, write it down, and offboarding becomes a
-- lookup rather than an archaeology exercise.
--
-- RLS enabled with no policies, same as every other table here: the anon key
-- ships in the app bundle and must never reach commercial data.

create table if not exists comp_grants (
    id                uuid primary key default gen_random_uuid(),
    -- Who, in human terms. Fill both: emails change, names are ambiguous.
    subject_name      text not null,
    subject_email     text not null,
    -- The RevenueCat App User ID, copied EXACTLY as the dashboard shows it.
    -- This is the only thing you need to find the person again: paste it into
    -- RevenueCat's customer search and revoke.
    --
    -- text, not uuid, deliberately. Anonymous ids look like
    -- "938eef2c45c6402991b9756c288d7ae3" — 32 hex with no dashes. Postgres would
    -- happily accept that as a uuid and store it re-hyphenated, and the
    -- re-hyphenated version does NOT match in RevenueCat's search. Storing the
    -- literal string means copy-paste round-trips correctly.
    app_user_id       text unique,
    reason            text not null
                      check (reason in ('family', 'influencer', 'press', 'support', 'other')),
    entitlement       text not null default 'elite',
    -- Free-text, e.g. 'Lifetime' or '12 months'. RevenueCat holds the real
    -- expiry; this is for humans reading the ledger.
    duration          text not null default 'Lifetime',
    granted_at        timestamptz not null default now(),
    granted_by        text,
    -- Set when access is withdrawn. Rows are never deleted: the history of who
    -- had free access and when is exactly what you need in a dispute.
    revoked_at        timestamptz,
    revoked_reason    text,
    -- For influencers, ties the comp back to their campaign.
    influencer_id     uuid references influencers(id),
    notes             text
);
alter table comp_grants enable row level security;
create index if not exists comp_grants_email_idx  on comp_grants (lower(subject_email));
create index if not exists comp_grants_rcid_idx   on comp_grants (app_user_id);
create index if not exists comp_grants_active_idx on comp_grants (revoked_at) where revoked_at is null;

-- Everyone currently getting the app for free, and how to find them.
-- security_invoker so the view is evaluated as the CALLER and RLS on
-- comp_grants actually applies. Without it a view silently bypasses RLS,
-- because it runs with its owner's privileges. See migration 004.
create or replace view comp_grants_active with (security_invoker = on) as
select subject_name, subject_email, app_user_id, reason, entitlement, duration,
       granted_at, influencer_id, notes
from comp_grants
where revoked_at is null
order by reason, subject_name;

revoke all on comp_grants        from anon, authenticated;
revoke all on comp_grants_active from anon, authenticated;
