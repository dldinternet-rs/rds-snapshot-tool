-- invoices by day view
CREATE OR REPLACE view v_invoices_by_day
as
select
    case
        when c.parent_company_id is null then i.company_id
        else c.parent_company_id
        end company_id,
    case
        when c.parent_company_id is null then concat('l_',i.location_id)
        else concat('c_',c.id)
        end location_id,
    case i.type
        when 0 then 'Unknown'
        when 1 then 'Cash'
        when 2 then 'Check'
        when 3 then 'Paycode'
        when 4 then 'Card'
        when 5 then 'RemoteCheckout'
        when 6 then 'DirectBill'
        when 7 then 'HostBill'
        when 8 then 'ACH'
        when 9 then 'Batch'
        end payment_type,
    case i.initial_type
        when 5 then true
        else false
        end remote_checkout_flag,
    date(i.created_at) created_at,
    count(*) num_trx,
    sum(i.amount) volume,
    sum(ia.amount) revenue,
    sum(i.amount - ia.amount) payout
from invoices i
         join invoice_amounts ia on i.id = ia.invoice_id
         join companies c on i.company_id = c.id
where ia.company_id = 1
  and i.status = 3
  and i.deleted_at is null
  and i.payment_error = 0
group by 1,2,3,4,5;
-- companies view
CREATE OR REPLACE view v_companies
as
select c.*, i.first_trx_dt
from
    (select distinct coalesce(parent_company_id, id) id
     from companies) u
        join companies c on c.id = u.id
        join (
        select coalesce(c2.parent_company_id, c2.id) company_id, date(min(i.created_at)) first_trx_dt
        from invoices i
                 join companies c2 on i.company_id = c2.id
        group by 1
    ) i
             on i.company_id = u.id;
-- platform fees view
CREATE OR REPLACE view v_platform_fees
as
select coalesce(c.parent_company_id, c.id) id,
       date(bt.created_at),
       bt.amount
from banking_transfers bt
         join ledger_accounts la on bt.account_id = la.id
         join companies c on la.company_id = c.id
where bt.type = 4;
-- location view
CREATE OR REPLACE view v_locations
as
select concat('l_',l.id) id,
       l.name,
       to_char(l.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'EST', 'YYYY-MM-DD') created_at
from locations l
         join companies c on l.company_id = c.id
where c.parent_company_id is null
union
select concat('c_',c.id) id,
       c.name,
       to_char(c.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'EST', 'YYYY-MM-DD') created_at
from companies c
where c.parent_company_id is not null;
-- card charges view
CREATE OR REPLACE view v_card_charges
as
select id,
       invoice_id,
       company_id,
       amount,
       payout_amount,
       fee,
       transferred_amount,
       payment_stage,
       payment_processor,
       to_char(created_at, 'YYYY-MM-DD') created_at,
       external_charge_id
--       payment_error, deleted_at, decline_reason
from card_charges
where payment_error = 0 and deleted_at is null and (decline_reason is null or decline_reason = '')
  and payment_stage in (2,7,8)
order by id desc;

-- HQ, Company & Locations
CREATE OR REPLACE VIEW HQ_COMPANY_LOC
AS
select
       case
           when c.parent_company_id in (5, 1079,1330,1080,1336) then 'FHI'
           when c.parent_company_id in (211, 173, 284) then 'Lineage'
           when c.parent_company_id in (59, 14, 57, 58, 60) then 'PFS'
           -- when c.parent_company_id in (5049) then cast(c.parent_company_id AS TEXT) -- Quirch
           when c.parent_company_id in (438, 190, 482, 218, 191, 263, 2460) then 'USCS'
           else cast(c.parent_company_id AS TEXT)
       end hq_id,
       case
           when c.parent_company_id in (5, 1079,1330,1080,1336) then 'FHI'
           when c.parent_company_id in (211, 173, 284) then 'Lineage'
           when c.parent_company_id in (59, 14, 57, 58, 60) then 'Preferred Freezer Services'
           -- when c.parent_company_id in (5049) then p.name -- Quirch
           when c.parent_company_id in (438, 190, 482, 218, 191, 263, 2460) then 'US Cold Storage'
           else p.name
       end hq_name,
       c.parent_company_id company_id,
       p.name company_name,
       concat('c_', c.id) location_id,
       c.name location_name
from companies c
join companies p on c.parent_company_id = p.id

union -- Quirch (breaks the pattern)
select cast(c.parent_company_id AS TEXT) as hq_id,
       p.name aS hq_name,
       c.id company_id,
       c.name company_name,
       concat('l_', l.id) location_id,
       l.name location_name
from companies c
join companies p on c.parent_company_id = p.id
join locations l on c.id = l.company_id
where c.parent_company_id in (5049)

union -- Does not have a parent
select cast( c.id AS TEXT) as hq_id,
       c.name aS hq_name,
       c.id company_id,
       c.name company_name,
       concat('l_', l.id) location_id,
       l.name location_name
from companies c
join locations l on c.id = l.company_id
where c.parent_company_id is null;