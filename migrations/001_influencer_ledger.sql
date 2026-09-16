-- Influencer attribution and revenue ledger.
--
-- RLS IS ENABLED WITH ZERO POLICIES ON EVERY TABLE HERE, DELIBERATELY.
-- The anon key ships inside the app bundle, so anything reachable with it is
-- public. The previous referral system got this wrong: `referral_uses` carried a
-- permissive "Anyone can read" policy and leaked user_id to anonymous callers
-- (audit finding DATA-01). These tables are written and read ONLY by the Railway
-- proxy using the service-role key, which bypasses RLS. No policy means no
-- anonymous access, which is the correct posture for commercial data.
--
-- Money is stored in integer cents, never floats. Currency is recorded per row
-- because subscribers pay in their own storefront currency; do not sum across
-- currencies without converting.

create table if not exists influencers (
    id              uuid primary key default gen_random_uuid(),
    handle          text not null unique,          -- matches the ASC offer code reference name
    display_name    text,
    contact_email   text,
    -- 'bounty'   = flat commission_cents per paid conversion. Payable today from
    --              redemption counts alone.
    -- 'revshare' = commission_pct of NET proceeds, needs the webhook stream.
    commission_type text not null default 'bounty'
                    check (commission_type in ('bounty', 'revshare')),
    bounty_cents    integer check (bounty_cents >= 0),
    commission_pct  numeric(5,2) check (commission_pct >= 0 and commission_pct <= 100),
    active          boolean not null default true,
    notes           text,
    created_at      timestamptz not null default now()
);
alter table influencers enable row level security;

create table if not exists promo_codes (
    code            text primary key,              -- vanity code, stored UPPERCASE
    influencer_id   uuid not null references influencers(id) on delete restrict,
    -- The offer code reference name configured in App Store Connect. This is what
    -- arrives in the transaction, and it identifies the OFFER, not an individual
    -- one-time code — which is why each influencer needs their own campaign.
    apple_offer_ref text,
    -- RevenueCat offering to serve if/when in-app code entry ships. Unused until
    -- then; the column exists so the data is ready and no migration is needed.
    offering_id     text,
    active          boolean not null default true,
    created_at      timestamptz not null default now()
);
alter table promo_codes enable row level security;
create index if not exists promo_codes_influencer_idx on promo_codes (influencer_id);
create index if not exists promo_codes_apple_ref_idx  on promo_codes (apple_offer_ref);

-- One attribution per user, first code wins. Without the unique constraint a
-- user could re-enter a different code later and move their revenue to whoever
-- paid the most recently.
create table if not exists code_redemptions (
    id            uuid primary key default gen_random_uuid(),
    user_id       uuid not null unique,
    code          text not null references promo_codes(code),
    influencer_id uuid not null references influencers(id),
    source        text not null default 'in_app'   -- 'in_app' | 'apple_offer' | 'manual'
                  check (source in ('in_app', 'apple_offer', 'manual')),
    redeemed_at   timestamptz not null default now()
);
alter table code_redemptions enable row level security;
create index if not exists code_redemptions_influencer_idx on code_redemptions (influencer_id);

-- Every webhook event lands here, including ones that move no money, because the
-- raw payload is the only audit trail if a payout is ever disputed. event_id is
-- the primary key so a redelivered webhook is a no-op: providers retry on any
-- non-2xx and duplicates would otherwise double-pay.
create table if not exists revenue_events (
    event_id        text primary key,
    app_user_id     text not null,
    user_id         uuid,
    influencer_id   uuid references influencers(id),
    event_type      text not null,
    product_id      text,
    store           text,
    offer_ref       text,
    currency        text,
    gross_cents     integer not null default 0,
    net_cents       integer not null default 0,   -- after store commission; negative on refund
    is_revenue      boolean not null default false,
    occurred_at     timestamptz not null,
    raw             jsonb not null,
    created_at      timestamptz not null default now()
);
alter table revenue_events enable row level security;
create index if not exists revenue_events_influencer_idx on revenue_events (influencer_id, occurred_at);
create index if not exists revenue_events_type_idx       on revenue_events (event_type);

-- Payout rollup, by influencer and calendar month, in each currency.
-- Query it from the Supabase SQL editor; there is deliberately no public
-- endpoint for it, so there is no new authenticated admin surface to defend.
create or replace view influencer_payouts as
select
    i.handle,
    i.commission_type,
    date_trunc('month', e.occurred_at) as month,
    e.currency,
    count(*) filter (where e.is_revenue and e.net_cents > 0)          as paid_events,
    count(distinct e.app_user_id) filter (where e.is_revenue
        and e.event_type = 'INITIAL_PURCHASE')                       as conversions,
    sum(e.gross_cents) filter (where e.is_revenue)                   as gross_cents,
    sum(e.net_cents)   filter (where e.is_revenue)                   as net_cents,
    case i.commission_type
        when 'bounty' then coalesce(i.bounty_cents, 0) * count(distinct e.app_user_id)
                             filter (where e.is_revenue and e.event_type = 'INITIAL_PURCHASE')
        when 'revshare' then round(sum(e.net_cents) filter (where e.is_revenue)
                             * coalesce(i.commission_pct, 0) / 100.0)
    end                                                              as commission_cents
from revenue_events e
join influencers i on i.id = e.influencer_id
group by i.handle, i.commission_type, i.bounty_cents, i.commission_pct,
         date_trunc('month', e.occurred_at), e.currency;
