-- =====================================================================
--  Дольки — схема базы данных для Supabase (PostgreSQL), версия 2
--  Аккаунты по номеру телефона и паролю (пароль хранится как хэш bcrypt).
--
--  Как применить: Supabase → SQL Editor → New query → вставить весь файл → Run.
--  ВНИМАНИЕ: скрипт удаляет и пересоздаёт таблицы — все сборы и аккаунты
--  в базе будут удалены. Для учебного проекта с тестовыми данными это нормально.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Очистка (в том числе объектов версии 1) ----------
drop policy if exists "receipts: organizer uploads" on storage.objects;
drop policy if exists "receipts: organizer and members read" on storage.objects;
drop table if exists public.receipts         cascade;
drop table if exists public.memberships      cascade;
drop table if exists public.items            cascade;
drop table if exists public.collections      cascade;
drop table if exists public.profiles         cascade;   -- таблица из версии 1
drop table if exists public.account_sessions cascade;
drop table if exists public.accounts         cascade;
drop function if exists public.is_collection_member(uuid);
drop function if exists public.is_collection_organizer(uuid);
drop function if exists public.current_account_id();
drop function if exists public.get_invite(text);
drop function if exists public.join_collection(text);
drop function if exists public.demo_pay(uuid, numeric);
drop function if exists public.get_members(uuid);
drop function if exists public.register_account(text, text, text);
drop function if exists public.login_account(text, text);
drop function if exists public.logout_account();
drop function if exists public.me();
drop function if exists public.update_profile(text, text);
drop function if exists public.change_password(text, text);
drop function if exists public.attach_receipt(uuid, text, text, numeric);
drop function if exists public.get_collection_state(uuid);

-- =====================================================================
--  Аккаунты
-- =====================================================================
-- Учётные записи пользователей. Пароль хранится только в виде хэша bcrypt
-- (функция crypt + gen_salt('bf') из pgcrypto): соль генерируется для каждого
-- пароля и хранится внутри строки хэша. Сам пароль в базу не попадает.
create table public.accounts (
  id              uuid primary key default gen_random_uuid(),
  phone           varchar(10) not null unique check (phone ~ '^[0-9]{10}$'),  -- 10 цифр без +7
  name            text not null check (char_length(name) between 1 and 80),
  password_hash   text not null,
  failed_attempts int  not null default 0,        -- неудачные попытки входа подряд
  locked_until    timestamptz,                    -- временная блокировка после перебора
  created_at      timestamptz not null default now()
);

-- Привязка «браузер → аккаунт». Каждый браузер получает техническую
-- анонимную сессию Supabase (auth.uid()), а после входа по паролю она
-- связывается с аккаунтом. Выход — удаление связи.
create table public.account_sessions (
  auth_uid   uuid primary key references auth.users(id) on delete cascade,
  account_id uuid not null references public.accounts(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Прямого доступа к этим таблицам из браузера нет вообще: RLS включён,
-- политик нет. Работа с ними — только через функции ниже.
alter table public.accounts         enable row level security;
alter table public.account_sessions enable row level security;

-- Текущий аккаунт пользователя (или NULL, если он не вошёл)
create function public.current_account_id()
returns uuid language sql stable security definer set search_path = public as $$
  select account_id from public.account_sessions where auth_uid = auth.uid();
$$;

-- =====================================================================
--  Сборы, позиции, участники
-- =====================================================================
create table public.collections (
  id             uuid primary key default gen_random_uuid(),
  organizer_id   uuid not null default public.current_account_id() references public.accounts(id) on delete cascade,
  title          text not null check (char_length(title) between 1 and 120),
  recipient_name text,
  deadline       date not null,
  participants   int  not null check (participants between 2 and 30),
  allow_extra    boolean not null default false,
  invite_code    text not null unique default replace(gen_random_uuid()::text, '-', ''),
  status         text not null default 'open' check (status in ('open', 'closed', 'bought', 'cancelled')),
  created_at     timestamptz not null default now()
);

-- Сумма сбора не хранится отдельно: она всегда равна сумме цен позиций (БП-2).
create table public.items (
  id            bigint generated always as identity primary key,
  collection_id uuid not null references public.collections(id) on delete cascade,
  url           text not null check (url ~* '^https?://'),
  title         text not null check (char_length(title) between 1 and 200),
  price         numeric(12,2) not null check (price > 0),
  position      int not null default 0
);

create table public.memberships (
  collection_id uuid not null references public.collections(id) on delete cascade,
  user_id       uuid not null default public.current_account_id() references public.accounts(id) on delete cascade,
  role          text not null default 'participant' check (role in ('organizer', 'participant')),
  share_amount  numeric(12,2) not null check (share_amount > 0),
  paid_amount   numeric(12,2) not null default 0 check (paid_amount >= 0),
  joined_at     timestamptz not null default now(),
  primary key (collection_id, user_id)
);

create index on public.collections (organizer_id);
create index on public.items (collection_id);
create index on public.memberships (user_id);
create index on public.account_sessions (account_id);

-- =====================================================================
--  Разграничение доступа (Row Level Security)
-- =====================================================================
alter table public.collections enable row level security;
alter table public.items       enable row level security;
alter table public.memberships enable row level security;

create function public.is_collection_organizer(cid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.collections c
                 where c.id = cid and c.organizer_id = public.current_account_id());
$$;

create function public.is_collection_member(cid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.memberships m
                 where m.collection_id = cid and m.user_id = public.current_account_id());
$$;

-- Сборы: видят организатор и участники; создаёт и меняет только организатор
create policy "collection: read if organizer or member" on public.collections for select to authenticated
  using (organizer_id = public.current_account_id() or public.is_collection_member(id));
create policy "collection: create as organizer" on public.collections for insert to authenticated
  with check (organizer_id = public.current_account_id());
create policy "collection: organizer updates" on public.collections for update to authenticated
  using (organizer_id = public.current_account_id()) with check (organizer_id = public.current_account_id());
create policy "collection: organizer deletes" on public.collections for delete to authenticated
  using (organizer_id = public.current_account_id());

-- Позиции: видят все, у кого есть доступ к сбору; меняет только организатор
create policy "items: read with collection" on public.items for select to authenticated
  using (public.is_collection_organizer(collection_id) or public.is_collection_member(collection_id));
create policy "items: organizer inserts" on public.items for insert to authenticated
  with check (public.is_collection_organizer(collection_id));
create policy "items: organizer updates" on public.items for update to authenticated
  using (public.is_collection_organizer(collection_id)) with check (public.is_collection_organizer(collection_id));
create policy "items: organizer deletes" on public.items for delete to authenticated
  using (public.is_collection_organizer(collection_id));

-- Участие: свою строку видит участник, все строки сбора — организатор.
-- Напрямую добавить строку может только организатор (себя, при создании сбора).
-- Участники вступают через join_collection. Взносы меняет только сервер.
create policy "membership: read own or as organizer" on public.memberships for select to authenticated
  using (user_id = public.current_account_id() or public.is_collection_organizer(collection_id));
create policy "membership: organizer joins own collection" on public.memberships for insert to authenticated
  with check (user_id = public.current_account_id() and role = 'organizer' and paid_amount = 0
              and public.is_collection_organizer(collection_id));

-- =====================================================================
--  Функции аккаунтов: регистрация, вход, выход, профиль
-- =====================================================================

-- Регистрация. Пароль хэшируется bcrypt с cost 10.
create function public.register_account(p_phone text, p_name text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare a public.accounts;
begin
  if auth.uid() is null then raise exception 'no_session'; end if;
  if p_phone !~ '^[0-9]{10}$' then raise exception 'bad_phone'; end if;
  if char_length(coalesce(trim(p_name), '')) = 0 then raise exception 'bad_name'; end if;
  if char_length(coalesce(p_password, '')) < 8 then raise exception 'weak_password'; end if;
  if exists (select 1 from public.accounts where phone = p_phone) then raise exception 'phone_taken'; end if;
  insert into public.accounts (phone, name, password_hash)
  values (p_phone, trim(p_name), crypt(p_password, gen_salt('bf', 10)))
  returning * into a;
  insert into public.account_sessions (auth_uid, account_id) values (auth.uid(), a.id)
  on conflict (auth_uid) do update set account_id = excluded.account_id, created_at = now();
  return json_build_object('id', a.id, 'name', a.name, 'phone', a.phone);
end $$;

-- Вход по телефону и паролю.
-- Ошибки возвращаются как JSON, а не исключением: иначе откатился бы
-- счётчик неудачных попыток. После 5 неудачных попыток подряд вход
-- блокируется на 15 минут (защита от перебора паролей).
-- Для несуществующего номера ответ такой же, как для неверного пароля:
-- по ответу нельзя узнать, зарегистрирован ли номер.
create function public.login_account(p_phone text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare a public.accounts;
begin
  if auth.uid() is null then return json_build_object('error', 'no_session'); end if;
  select * into a from public.accounts where phone = p_phone for update;
  if not found then
    perform crypt(coalesce(p_password, ''), gen_salt('bf', 10));   -- выравниваем время ответа
    return json_build_object('error', 'invalid_credentials');
  end if;
  if a.locked_until is not null and a.locked_until > now() then
    return json_build_object('error', 'locked', 'until', a.locked_until);
  end if;
  if crypt(coalesce(p_password, ''), a.password_hash) <> a.password_hash then
    update public.accounts
       set failed_attempts = failed_attempts + 1,
           locked_until = case when failed_attempts + 1 >= 5 then now() + interval '15 minutes' else null end
     where id = a.id;
    return json_build_object('error', 'invalid_credentials');
  end if;
  update public.accounts set failed_attempts = 0, locked_until = null where id = a.id;
  insert into public.account_sessions (auth_uid, account_id) values (auth.uid(), a.id)
  on conflict (auth_uid) do update set account_id = excluded.account_id, created_at = now();
  return json_build_object('id', a.id, 'name', a.name, 'phone', a.phone);
end $$;

-- Выход: браузер отвязывается от аккаунта
create function public.logout_account()
returns void language sql security definer set search_path = public as $$
  delete from public.account_sessions where auth_uid = auth.uid();
$$;

-- Текущий пользователь: только имя и телефон, без хэша пароля
create function public.me()
returns json language sql stable security definer set search_path = public as $$
  select json_build_object('id', a.id, 'name', a.name, 'phone', a.phone)
    from public.accounts a where a.id = public.current_account_id();
$$;

create function public.update_profile(p_name text, p_phone text)
returns json language plpgsql security definer set search_path = public as $$
declare a public.accounts; me uuid := public.current_account_id();
begin
  if me is null then raise exception 'not_authenticated'; end if;
  if p_phone !~ '^[0-9]{10}$' then raise exception 'bad_phone'; end if;
  if char_length(coalesce(trim(p_name), '')) = 0 then raise exception 'bad_name'; end if;
  if exists (select 1 from public.accounts where phone = p_phone and id <> me) then raise exception 'phone_taken'; end if;
  update public.accounts set name = trim(p_name), phone = p_phone where id = me returning * into a;
  return json_build_object('id', a.id, 'name', a.name, 'phone', a.phone);
end $$;

create function public.change_password(p_old text, p_new text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare a public.accounts;
begin
  select * into a from public.accounts where id = public.current_account_id();
  if not found then raise exception 'not_authenticated'; end if;
  if crypt(coalesce(p_old, ''), a.password_hash) <> a.password_hash then raise exception 'wrong_password'; end if;
  if char_length(coalesce(p_new, '')) < 8 then raise exception 'weak_password'; end if;
  update public.accounts set password_hash = crypt(p_new, gen_salt('bf', 10)) where id = a.id;
end $$;

-- =====================================================================
--  Функции сборов: приглашение, вступление, демо-оплата, участники
-- =====================================================================

-- Просмотр сбора по коду приглашения. Доступно и без входа: код длинный
-- и случайный. Отдаётся только нужное приглашённому, без телефонов.
create function public.get_invite(code text)
returns json language plpgsql stable security definer set search_path = public as $$
declare c public.collections; total numeric; me uuid := public.current_account_id();
begin
  select * into c from public.collections where invite_code = code;
  if not found then return null; end if;
  select coalesce(sum(price), 0) into total from public.items where collection_id = c.id;
  return json_build_object(
    'id', c.id, 'title', c.title, 'deadline', c.deadline, 'participants', c.participants,
    'allow_extra', c.allow_extra, 'status', c.status, 'recipient_name', c.recipient_name,
    'invite_code', c.invite_code,
    'organizer_name', (select name from public.accounts where id = c.organizer_id),
    'total', total,
    'share', ceil(total / c.participants),
    'joined', (select count(*) from public.memberships where collection_id = c.id),
    'paid_count', (select count(*) from public.memberships where collection_id = c.id and paid_amount > 0),
    'paid_total', (select coalesce(sum(paid_amount), 0) from public.memberships where collection_id = c.id),
    'is_organizer', coalesce(c.organizer_id = me, false),
    'is_member', exists (select 1 from public.memberships where collection_id = c.id and user_id = me),
    'my_paid', (select paid_amount from public.memberships where collection_id = c.id and user_id = me),
    'items', coalesce((select json_agg(json_build_object('url', url, 'title', title, 'price', price) order by position)
                       from public.items where collection_id = c.id), '[]'::json),
    -- чек видят только организатор и участники сбора
    'receipt', case when c.organizer_id = me
                      or exists (select 1 from public.memberships where collection_id = c.id and user_id = me)
                    then (select json_build_object('path', r.file_path, 'type', r.file_type, 'total', r.total, 'uploaded_at', r.uploaded_at)
                            from public.receipts r where r.collection_id = c.id)
               end
  );
end $$;

create function public.join_collection(code text)
returns uuid language plpgsql security definer set search_path = public as $$
declare c public.collections; total numeric; cnt int; me uuid := public.current_account_id();
begin
  if me is null then raise exception 'not_authenticated'; end if;
  select * into c from public.collections where invite_code = code for update;
  if not found then raise exception 'invite_not_found'; end if;
  if exists (select 1 from public.memberships where collection_id = c.id and user_id = me) then return c.id; end if;
  if c.status <> 'open'        then raise exception 'collection_closed'; end if;
  if c.deadline < current_date then raise exception 'deadline_passed';   end if;
  select count(*) into cnt from public.memberships where collection_id = c.id;
  if cnt >= c.participants     then raise exception 'collection_full';   end if;
  select coalesce(sum(price), 0) into total from public.items where collection_id = c.id;
  insert into public.memberships (collection_id, user_id, role, share_amount)
  values (c.id, me, 'participant', ceil(total / c.participants));
  return c.id;
end $$;

-- Имитация оплаты. В настоящем сервисе взнос отмечает сервер после
-- подтверждения банком. Правила: не меньше дольки; больше — только если
-- организатор разрешил (БП-4, БП-5).
create function public.demo_pay(cid uuid, amount numeric default null)
returns numeric language plpgsql security definer set search_path = public as $$
declare m public.memberships; c public.collections; pay numeric; me uuid := public.current_account_id();
begin
  select * into m from public.memberships where collection_id = cid and user_id = me for update;
  if not found then raise exception 'not_member'; end if;
  select * into c from public.collections where id = cid;
  if c.status <> 'open' then raise exception 'collection_closed'; end if;
  if m.paid_amount > 0  then raise exception 'already_paid';      end if;
  pay := coalesce(amount, m.share_amount);
  if pay < m.share_amount                       then raise exception 'amount_too_small';  end if;
  if pay > m.share_amount and not c.allow_extra then raise exception 'extra_not_allowed'; end if;
  update public.memberships set paid_amount = pay where collection_id = cid and user_id = me;
  return pay;
end $$;

-- Участники сбора: имена и суммы, без телефонов. Только для участников сбора.
create function public.get_members(cid uuid)
returns table (name text, role text, share_amount numeric, paid_amount numeric, is_me boolean)
language sql stable security definer set search_path = public as $$
  select a.name, m.role, m.share_amount, m.paid_amount, m.user_id = public.current_account_id()
    from public.memberships m
    join public.accounts a on a.id = m.user_id
   where m.collection_id = cid
     and (public.is_collection_organizer(cid) or public.is_collection_member(cid))
   order by (m.role = 'organizer') desc, m.joined_at;
$$;

-- =====================================================================
--  Права на вызов функций
-- =====================================================================
revoke all on function public.current_account_id()                 from public, anon;
revoke all on function public.is_collection_organizer(uuid)         from public, anon;
revoke all on function public.is_collection_member(uuid)            from public, anon;
revoke all on function public.register_account(text, text, text)    from public, anon;
revoke all on function public.login_account(text, text)             from public, anon;
revoke all on function public.logout_account()                      from public, anon;
revoke all on function public.me()                                  from public, anon;
revoke all on function public.update_profile(text, text)            from public, anon;
revoke all on function public.change_password(text, text)           from public, anon;
revoke all on function public.get_invite(text)                      from public;
revoke all on function public.join_collection(text)                 from public, anon;
revoke all on function public.demo_pay(uuid, numeric)               from public, anon;
revoke all on function public.get_members(uuid)                     from public, anon;

grant execute on function public.current_account_id()               to anon, authenticated;
grant execute on function public.is_collection_organizer(uuid)      to authenticated;
grant execute on function public.is_collection_member(uuid)         to authenticated;
grant execute on function public.register_account(text, text, text) to authenticated;
grant execute on function public.login_account(text, text)          to authenticated;
grant execute on function public.logout_account()                   to authenticated;
grant execute on function public.me()                               to authenticated;
grant execute on function public.update_profile(text, text)         to authenticated;
grant execute on function public.change_password(text, text)        to authenticated;
grant execute on function public.get_invite(text)                   to anon, authenticated;
grant execute on function public.join_collection(text)              to authenticated;
grant execute on function public.demo_pay(uuid, numeric)            to authenticated;
grant execute on function public.get_members(uuid)                  to authenticated;

-- =====================================================================
--  Чеки (процессы П4–П5): покупка подарка и подтверждение чеком
-- =====================================================================
-- Один чек на сбор. Файл чека (фото или PDF) лежит в закрытом хранилище
-- Supabase Storage (бакет receipts) по пути <id сбора>/<имя файла>.
create table if not exists public.receipts (
  collection_id uuid primary key references public.collections(id) on delete cascade,
  file_path     text not null,
  file_type     text,
  total         numeric(12,2) not null check (total > 0),
  uploaded_at   timestamptz not null default now()
);
alter table public.receipts enable row level security;
drop policy if exists "receipts: read by organizer and members" on public.receipts;
create policy "receipts: read by organizer and members" on public.receipts for select to authenticated
  using (public.is_collection_organizer(collection_id) or public.is_collection_member(collection_id));

-- Безопасное превращение текста в uuid (для имён папок в хранилище)
create or replace function public.try_uuid(t text)
returns uuid language plpgsql immutable as $$
begin
  return t::uuid;
exception when others then
  return null;
end $$;

-- Закрытый бакет для файлов чеков: до 5 МБ, только изображения и PDF
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('receipts', 'receipts', false, 5242880,
        array['image/jpeg', 'image/png', 'image/webp', 'image/heic', 'application/pdf'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- Загружать файл в папку сбора может только его организатор,
-- смотреть — организатор и участники этого сбора.
drop policy if exists "receipts: organizer uploads" on storage.objects;
create policy "receipts: organizer uploads" on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts'
              and public.is_collection_organizer(public.try_uuid((storage.foldername(name))[1])));
drop policy if exists "receipts: organizer and members read" on storage.objects;
create policy "receipts: organizer and members read" on storage.objects for select to authenticated
  using (bucket_id = 'receipts'
         and (public.is_collection_organizer(public.try_uuid((storage.foldername(name))[1]))
              or public.is_collection_member(public.try_uuid((storage.foldername(name))[1]))));

-- Приложить чек. Проверяет: вызывает организатор, сбор открыт, вся сумма
-- собрана, файл лежит в папке этого сбора. После этого сбор переходит
-- в статус «подарок куплен» (bought), и новые взносы больше не принимаются.
create or replace function public.attach_receipt(cid uuid, p_path text, p_type text, p_total numeric)
returns json language plpgsql security definer set search_path = public as $$
declare c public.collections; total numeric; paid numeric;
begin
  select * into c from public.collections where id = cid for update;
  if not found or c.organizer_id is distinct from public.current_account_id() then raise exception 'not_organizer'; end if;
  if c.status <> 'open' then raise exception 'collection_closed'; end if;
  if exists (select 1 from public.receipts where collection_id = cid) then raise exception 'receipt_exists'; end if;
  select coalesce(sum(price), 0) into total from public.items where collection_id = cid;
  select coalesce(sum(paid_amount), 0) into paid from public.memberships where collection_id = cid;
  if paid < total then raise exception 'not_fully_paid'; end if;
  if p_path is null or position(cid::text || '/' in p_path) <> 1 then raise exception 'bad_receipt_path'; end if;
  if p_total is null or p_total <= 0 then raise exception 'bad_receipt_total'; end if;
  insert into public.receipts (collection_id, file_path, file_type, total) values (cid, p_path, p_type, p_total);
  update public.collections set status = 'bought' where id = cid;
  return json_build_object('status', 'bought');
end $$;

-- Состояние сбора для страницы организатора: статус, суммы и чек
create or replace function public.get_collection_state(cid uuid)
returns json language plpgsql stable security definer set search_path = public as $$
declare c public.collections;
begin
  if not (public.is_collection_organizer(cid) or public.is_collection_member(cid)) then return null; end if;
  select * into c from public.collections where id = cid;
  return json_build_object(
    'status',     c.status,
    'total',      (select coalesce(sum(price), 0) from public.items where collection_id = cid),
    'paid_total', (select coalesce(sum(paid_amount), 0) from public.memberships where collection_id = cid),
    'paid_count', (select count(*) from public.memberships where collection_id = cid and paid_amount > 0),
    'receipt',    (select json_build_object('path', file_path, 'type', file_type, 'total', total, 'uploaded_at', uploaded_at)
                     from public.receipts where collection_id = cid)
  );
end $$;

revoke all on function public.attach_receipt(uuid, text, text, numeric) from public, anon;
revoke all on function public.get_collection_state(uuid)              from public, anon;
grant execute on function public.attach_receipt(uuid, text, text, numeric) to authenticated;
grant execute on function public.get_collection_state(uuid)              to authenticated;
grant execute on function public.try_uuid(text)                          to authenticated;
