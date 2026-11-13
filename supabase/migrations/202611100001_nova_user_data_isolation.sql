-- Nova CRM: strict per-user isolation for customers, payments and medical records.
-- Run this migration in Supabase SQL Editor after taking a database backup.
-- Every signed-in account (manager or employee) can access ONLY its own records.

-- Ensure RLS is enabled.
alter table public.customers enable row level security;
alter table public.payments enable row level security;
alter table public.customer_medical_records enable row level security;

-- Remove older permissive policies; PostgreSQL policies are OR-combined.
do $$
declare p record;
begin
  for p in select tablename, policyname from pg_policies where schemaname='public' and tablename in ('customers','payments','customer_medical_records') loop
    execute format('drop policy if exists %I on public.%I', p.policyname, p.tablename);
  end loop;
end $$;

-- Each customer belongs to the account that created it. Existing non-null
-- created_by values are retained; unassigned legacy records stay inaccessible
-- until an administrator explicitly assigns them to the correct account.

create policy nova_customers_select_own on public.customers
for select to authenticated using (created_by = auth.uid());
create policy nova_customers_insert_own on public.customers
for insert to authenticated with check (created_by = auth.uid());
create policy nova_customers_update_own on public.customers
for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
create policy nova_customers_delete_own on public.customers
for delete to authenticated using (created_by = auth.uid());

-- Payments are visible only through a customer owned by the signed-in user.
create policy nova_payments_select_own on public.payments
for select to authenticated using (received_by = auth.uid() and exists (
  select 1 from public.customers c where c.id = payments.customer_id and c.created_by = auth.uid()
));
create policy nova_payments_insert_own on public.payments
for insert to authenticated with check (
  received_by = auth.uid() and exists (
    select 1 from public.customers c where c.id = payments.customer_id and c.created_by = auth.uid()
  )
);
create policy nova_payments_update_own on public.payments
for update to authenticated using (received_by = auth.uid() and exists (
  select 1 from public.customers c where c.id = payments.customer_id and c.created_by = auth.uid()
)) with check (received_by = auth.uid() and exists (
  select 1 from public.customers c where c.id = payments.customer_id and c.created_by = auth.uid()
));
create policy nova_payments_delete_own on public.payments
for delete to authenticated using (received_by = auth.uid() and exists (
  select 1 from public.customers c where c.id = payments.customer_id and c.created_by = auth.uid()
));

-- Medical records follow the same customer ownership boundary for all roles.
create policy nova_medical_select_own on public.customer_medical_records
for select to authenticated using (exists (
  select 1 from public.customers c where c.id = customer_medical_records.customer_id and c.created_by = auth.uid()
));
create policy nova_medical_insert_own on public.customer_medical_records
for insert to authenticated with check (exists (
  select 1 from public.customers c where c.id = customer_medical_records.customer_id and c.created_by = auth.uid()
));
create policy nova_medical_update_own on public.customer_medical_records
for update to authenticated using (exists (
  select 1 from public.customers c where c.id = customer_medical_records.customer_id and c.created_by = auth.uid()
)) with check (exists (
  select 1 from public.customers c where c.id = customer_medical_records.customer_id and c.created_by = auth.uid()
));
create policy nova_medical_delete_own on public.customer_medical_records
for delete to authenticated using (exists (
  select 1 from public.customers c where c.id = customer_medical_records.customer_id and c.created_by = auth.uid()
));

-- Replace the former manager-only trigger with an ownership check. This is
-- defense in depth in addition to RLS, including for privileged API paths.
create or replace function public.nova_manager_only_customer_write()
returns trigger language plpgsql security definer set search_path = public as $$
declare owner_id uuid;
begin
  if TG_TABLE_NAME = 'customers' then
    if TG_OP = 'DELETE' then owner_id := OLD.created_by; else owner_id := NEW.created_by; end if;
  else
    if TG_OP = 'DELETE' then
      select created_by into owner_id from public.customers where id = OLD.customer_id;
    else
      select created_by into owner_id from public.customers where id = NEW.customer_id;
    end if;
  end if;
  if owner_id is distinct from auth.uid() then
    raise exception 'شما فقط به اطلاعات اختصاصی حساب خود دسترسی دارید';
  end if;
  if TG_OP = 'DELETE' then return OLD; end if;
  return NEW;
end;
$$;

-- Keep trigger names already used by the app migration.
drop trigger if exists nova_customer_manager_write on public.customers;
create trigger nova_customer_manager_write before insert or update or delete on public.customers
for each row execute function public.nova_manager_only_customer_write();
drop trigger if exists nova_payment_manager_write on public.payments;
create trigger nova_payment_manager_write before insert or update or delete on public.payments
for each row execute function public.nova_manager_only_customer_write();

-- Medical rows are protected by RLS; add trigger protection as well.
drop trigger if exists nova_medical_owner_write on public.customer_medical_records;
create trigger nova_medical_owner_write before insert or update or delete on public.customer_medical_records
for each row execute function public.nova_manager_only_customer_write();
