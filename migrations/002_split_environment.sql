-- Keep sandbox money out of real payouts.
--
-- Sandbox and production events arrive on the same webhook and land in the same
-- table, and the first version of influencer_payouts summed both — so a test
-- purchase would have shown up in a real payout figure. Verified in practice: a
-- SANDBOX INITIAL_PURCHASE produced gross 356 / net 227 / commission 34 in the
-- payout view with nothing marking it as unreal.
--
-- Rather than FILTER sandbox out, the view now GROUPS BY environment. Filtering
-- would silently drop any row whose environment we failed to record, and a
-- silently missing payment is worse than a visible one you have to ignore: read
-- the PRODUCTION row, and anything else is immediately obvious.

alter table revenue_events
    add column if not exists environment text;

-- Backfill from the stored payload. This is exactly why the raw jsonb is kept.
update revenue_events
   set environment = coalesce(raw -> 'event' ->> 'environment', 'UNKNOWN')
 where environment is null;

create index if not exists revenue_events_env_idx on revenue_events (environment);

create or replace view influencer_payouts as
select
    i.handle,
    i.commission_type,
    coalesce(e.environment, 'UNKNOWN')                               as environment,
    date_trunc('month', e.occurred_at)                               as month,
    count(distinct e.original_transaction_id)
        filter (where e.event_type = 'INITIAL_PURCHASE')             as conversions,
    count(*) filter (where e.is_revenue and e.net_usd_cents > 0)     as paid_events,
    count(*) filter (where e.net_usd_cents < 0)                      as refunds,
    sum(e.gross_usd_cents) filter (where e.is_revenue)               as gross_usd_cents,
    sum(e.net_usd_cents)   filter (where e.is_revenue)               as net_usd_cents,
    case i.commission_type
        when 'bounty' then coalesce(i.bounty_cents, 0)
                           * count(distinct e.original_transaction_id)
                             filter (where e.event_type = 'INITIAL_PURCHASE')
        when 'revshare' then greatest(round(
                             sum(e.net_usd_cents) filter (where e.is_revenue)
                             * coalesce(i.commission_pct, 0) / 100.0), 0)
    end                                                              as commission_usd_cents
from revenue_events e
join influencers i on i.id = e.influencer_id
group by i.handle, i.commission_type, i.bounty_cents, i.commission_pct,
         coalesce(e.environment, 'UNKNOWN'), date_trunc('month', e.occurred_at);

-- What to actually pay: production only.
create or replace view influencer_payouts_due as
select * from influencer_payouts where environment = 'PRODUCTION';
