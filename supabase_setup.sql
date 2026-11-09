-- DEVELOPMENT ONLY: all RPCs below are available to anonymous callers.
-- Use only with fake data in a disposable test project. Do not deploy publicly.

create table if not exists public.students (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null,
  fee bigint not null check (fee >= 0),
  trainer text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students (id) on delete cascade,
  month text not null check (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  amount bigint not null check (amount >= 0),
  paid_at timestamptz not null default now(),
  paid_by text not null,
  unique (student_id, month)
);

alter table public.payments
  drop constraint if exists payments_month_check;
alter table public.payments
  add constraint payments_month_check
  check (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$');

alter table public.students enable row level security;
alter table public.payments enable row level security;
revoke all on table public.students, public.payments from anon, authenticated;

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.trainer_access (
  id boolean primary key default true check (id),
  password_hash text not null
);
alter table public.trainer_access enable row level security;
revoke all on table public.trainer_access from public, anon, authenticated;

create or replace function public.verify_trainer_password(p_password text)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_password_hash text;
begin
  if nullif(p_password, '') is null then
    return false;
  end if;

  select ta.password_hash into v_password_hash
  from public.trainer_access as ta
  where ta.id = true;

  if not found then
    raise exception 'Trainer password is not configured';
  end if;

  return extensions.crypt(p_password, v_password_hash) = v_password_hash;
end;
$$;

-- Set or change the trainer password in the Supabase SQL Editor, not in this file:
-- insert into public.trainer_access (id, password_hash)
-- values (true, extensions.crypt('REPLACE_WITH_YOUR_PASSWORD', extensions.gen_salt('bf', 12)))
-- on conflict (id) do update set password_hash = excluded.password_hash;

create or replace function public.list_data()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_students jsonb;
  v_payments jsonb;
begin
  select coalesce(
    jsonb_agg(jsonb_build_object(
      'id', s.id,
      'code', s.code,
      'name', s.name,
      'fee', s.fee,
      'trainer', s.trainer,
      'created_at', s.created_at
    ) order by s.name),
    '[]'::jsonb
  ) into v_students
  from public.students as s;

  select coalesce(
    jsonb_agg(jsonb_build_object(
      'student_id', p.student_id,
      'month', p.month,
      'amount', p.amount,
      'paid_at', p.paid_at,
      'by', p.paid_by
    ) order by p.month desc),
    '[]'::jsonb
  ) into v_payments
  from public.payments as p;

  return jsonb_build_object('students', v_students, 'payments', v_payments);
end;
$$;

create or replace function public.parent_lookup(p_code text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'id', s.id,
    'code', s.code,
    'name', s.name,
    'fee', s.fee,
    'trainer', s.trainer,
    'created_at', s.created_at,
    'payments', coalesce((
      select jsonb_agg(jsonb_build_object(
        'month', p.month,
        'amount', p.amount,
        'paid_at', p.paid_at
      ) order by p.month desc)
      from public.payments as p
      where p.student_id = s.id
    ), '[]'::jsonb)
  )
  from public.students as s
  where s.code = upper(trim(p_code))
  limit 1;
$$;

create or replace function public.add_student(
  p_name text,
  p_fee bigint,
  p_trainer text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_code text;
  v_student public.students%rowtype;
begin
  if nullif(trim(p_name), '') is null then
    raise exception 'Student name is required' using errcode = '22023';
  end if;
  if p_fee is null or p_fee < 0 then
    raise exception 'Fee must be zero or greater' using errcode = '22023';
  end if;
  loop
    v_code := 'OW-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 24));
    exit when not exists (select 1 from public.students as s where s.code = v_code);
  end loop;

  insert into public.students (code, name, fee, trainer)
  values (v_code, trim(p_name), p_fee, p_trainer)
  returning * into v_student;

  return jsonb_build_object(
    'id', v_student.id,
    'code', v_student.code,
    'name', v_student.name,
    'fee', v_student.fee,
    'trainer', v_student.trainer,
    'created_at', v_student.created_at
  );
end;
$$;

create or replace function public.set_payment(
  p_sid uuid,
  p_month text,
  p_amount bigint,
  p_by text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_trainer text;
  v_payment public.payments%rowtype;
begin
  v_trainer := coalesce(nullif(trim(p_by), ''), 'Public test access');

  if p_month !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' then
    raise exception 'Month must use YYYY-MM format' using errcode = '22023';
  end if;
  if p_amount is null or p_amount < 0 then
    raise exception 'Amount must be zero or greater' using errcode = '22023';
  end if;

  insert into public.payments (student_id, month, amount, paid_by)
  values (p_sid, p_month, p_amount, v_trainer)
  on conflict (student_id, month) do update
    set amount = excluded.amount,
        paid_at = now(),
        paid_by = excluded.paid_by
  returning * into v_payment;

  return jsonb_build_object(
    'student_id', v_payment.student_id,
    'month', v_payment.month,
    'amount', v_payment.amount,
    'paid_at', v_payment.paid_at,
    'by', v_payment.paid_by
  );
end;
$$;

create or replace function public.delete_payment(p_sid uuid, p_month text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.payments
  where student_id = p_sid and month = p_month;
  return found;
end;
$$;

create or replace function public.delete_student(p_sid uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.students where id = p_sid;
  return found;
end;
$$;

revoke all on function public.list_data() from public, anon, authenticated;
revoke all on function public.verify_trainer_password(text) from public, anon, authenticated;
revoke all on function public.parent_lookup(text) from public, anon, authenticated;
revoke all on function public.add_student(text, bigint, text) from public, anon, authenticated;
revoke all on function public.set_payment(uuid, text, bigint, text) from public, anon, authenticated;
revoke all on function public.delete_payment(uuid, text) from public, anon, authenticated;
revoke all on function public.delete_student(uuid) from public, anon, authenticated;

grant execute on function public.list_data() to anon, authenticated;
grant execute on function public.verify_trainer_password(text) to anon, authenticated;
grant execute on function public.parent_lookup(text) to anon, authenticated;
grant execute on function public.add_student(text, bigint, text) to anon, authenticated;
grant execute on function public.set_payment(uuid, text, bigint, text) to anon, authenticated;
grant execute on function public.delete_payment(uuid, text) to anon, authenticated;
grant execute on function public.delete_student(uuid) to anon, authenticated;

notify pgrst, 'reload schema';
