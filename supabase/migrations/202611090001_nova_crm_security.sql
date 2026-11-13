
-- Nova CRM security and username migration
-- Run once in Supabase SQL Editor after taking a database backup.

alter table public.profiles add column if not exists username text;
-- Give existing accounts a usable initial username. Add a short stable suffix
-- only when multiple accounts share the same email prefix.
with candidates as (
  select id, lower(split_part(email, '@', 1)) as base_name,
         count(*) over (partition by lower(split_part(email, '@', 1))) as duplicates
  from public.profiles
  where username is null and email is not null
)
update public.profiles p
set username = case when c.duplicates > 1
                    then c.base_name || '-' || left(replace(p.id::text, '-', ''), 6)
                    else c.base_name end
from candidates c
where p.id = c.id;

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username)) where username is not null;

create or replace function public.nova_is_manager()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'manager' and coalesce(p.is_active, true)
  );
$$;
grant execute on function public.nova_is_manager() to authenticated;

-- Move medical information out of the generally readable customer table.
create table if not exists public.customer_medical_records (
  customer_id uuid primary key references public.customers(id) on delete cascade,
  medical_history text,
  updated_at timestamptz not null default now()
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema='public' and table_name='customers' and column_name='medical_history'
  ) then
    execute 'insert into public.customer_medical_records(customer_id, medical_history)
             select id, medical_history from public.customers
             where medical_history is not null
             on conflict (customer_id) do update
             set medical_history = excluded.medical_history';
    execute 'alter table public.customers drop column medical_history';
  end if;
end $$;

alter table public.customer_medical_records enable row level security;
grant select, insert, update, delete on public.customer_medical_records to authenticated;
drop policy if exists "Managers can manage customer medical records" on public.customer_medical_records;
create policy "Managers can manage customer medical records"
on public.customer_medical_records
for all to authenticated
using (public.nova_is_manager())
with check (public.nova_is_manager());

-- Enforce manager-only writes even if an older permissive RLS policy exists.
create or replace function public.nova_manager_only_customer_write()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.nova_is_manager() then
    raise exception 'این عملیات فقط برای مدیر مجاز است';
  end if;
  if TG_OP = 'DELETE' then return OLD; end if;
  return NEW;
end;
$$;

drop trigger if exists nova_customer_manager_write on public.customers;
create trigger nova_customer_manager_write
before insert or update or delete on public.customers
for each row execute function public.nova_manager_only_customer_write();

drop trigger if exists nova_payment_manager_write on public.payments;
create trigger nova_payment_manager_write
before insert or update or delete on public.payments
for each row execute function public.nova_manager_only_customer_write();

-- The app's employee experience is read-only for customer and payment records.
-- Medical data is in a separate manager-only table and is not exposed to employees.
