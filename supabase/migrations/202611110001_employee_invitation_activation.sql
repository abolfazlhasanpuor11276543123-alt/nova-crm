-- Keep invited employees locked until they accept the invitation and choose a password.
alter table public.profiles
  add column if not exists invitation_accepted boolean not null default false;

-- Backfill existing profiles using the authoritative Auth email-confirmation state.
update public.profiles p
set invitation_accepted = (u.email_confirmed_at is not null)
from auth.users u
where u.id = p.id;

-- Existing accepted employees retain their current active state; pending employees stay locked.
update public.profiles p
set is_active = false
from auth.users u
where u.id = p.id
  and u.email_confirmed_at is null
  and p.role = 'employee';
