-- =====================================================================
--  Дольки — приглашения, вступление в сбор и демо-оплата
--  Запустите в Supabase → SQL Editor ПОСЛЕ schema.sql.
--  Файл безопасно запускать повторно; данные в таблицах он не трогает.
-- =====================================================================

-- ---------- Участников добавляет только сервер ----------
-- Раньше вставить строку в memberships мог любой пользователь «за себя».
-- Теперь напрямую может только организатор (свою строку при создании сбора),
-- а участники вступают через функцию join_collection, которая проверяет
-- статус сбора, срок и число свободных мест.
drop policy if exists "membership: join yourself" on public.memberships;
drop policy if exists "membership: organizer joins own collection" on public.memberships;
create policy "membership: organizer joins own collection" on public.memberships for insert to authenticated
  with check (user_id = auth.uid() and role = 'organizer' and paid_amount = 0
              and public.is_collection_organizer(collection_id));

-- ---------- Просмотр сбора по коду приглашения ----------
-- Доступно и без входа: код длинный и случайный, подобрать его нельзя.
-- Возвращает только то, что нужно приглашённому: без телефонов и id пользователей.
create or replace function public.get_invite(code text)
returns json language plpgsql stable security definer set search_path = public as $$
declare
  c     public.collections;
  total numeric;
begin
  select * into c from public.collections where invite_code = code;
  if not found then return null; end if;
  select coalesce(sum(price), 0) into total from public.items where collection_id = c.id;
  return json_build_object(
    'id',             c.id,
    'title',          c.title,
    'deadline',       c.deadline,
    'participants',   c.participants,
    'allow_extra',    c.allow_extra,
    'status',         c.status,
    'recipient_name', c.recipient_name,
    'invite_code',    c.invite_code,
    'organizer_name', (select name from public.profiles where id = c.organizer_id),
    'total',          total,
    'share',          ceil(total / c.participants),
    'joined',         (select count(*) from public.memberships where collection_id = c.id),
    'paid_count',     (select count(*) from public.memberships where collection_id = c.id and paid_amount > 0),
    'paid_total',     (select coalesce(sum(paid_amount), 0) from public.memberships where collection_id = c.id),
    'is_organizer',   coalesce(c.organizer_id = auth.uid(), false),
    'is_member',      exists (select 1 from public.memberships where collection_id = c.id and user_id = auth.uid()),
    'my_paid',        (select paid_amount from public.memberships where collection_id = c.id and user_id = auth.uid()),
    'items',          coalesce((select json_agg(json_build_object('url', url, 'title', title, 'price', price) order by position)
                                from public.items where collection_id = c.id), '[]'::json)
  );
end $$;

-- ---------- Вступление в сбор ----------
create or replace function public.join_collection(code text)
returns uuid language plpgsql security definer set search_path = public as $$
declare
  c     public.collections;
  total numeric;
  cnt   int;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select * into c from public.collections where invite_code = code for update;
  if not found then raise exception 'invite_not_found'; end if;
  if exists (select 1 from public.memberships where collection_id = c.id and user_id = auth.uid()) then
    return c.id;                                   -- уже участник: ничего не делаем
  end if;
  if c.status <> 'open'            then raise exception 'collection_closed'; end if;
  if c.deadline < current_date     then raise exception 'deadline_passed';   end if;
  select count(*) into cnt from public.memberships where collection_id = c.id;
  if cnt >= c.participants         then raise exception 'collection_full';   end if;
  select coalesce(sum(price), 0) into total from public.items where collection_id = c.id;
  insert into public.memberships (collection_id, user_id, role, share_amount)
  values (c.id, auth.uid(), 'participant', ceil(total / c.participants));
  return c.id;
end $$;

-- ---------- Демо-оплата дольки ----------
-- В настоящем сервисе взнос отмечает сервер после подтверждения оплаты банком.
-- Эта функция имитирует такое подтверждение и проверяет правила:
-- не меньше дольки, больше — только если организатор разрешил (БП-4, БП-5).
create or replace function public.demo_pay(cid uuid, amount numeric default null)
returns numeric language plpgsql security definer set search_path = public as $$
declare
  m   public.memberships;
  c   public.collections;
  pay numeric;
begin
  select * into m from public.memberships where collection_id = cid and user_id = auth.uid() for update;
  if not found then raise exception 'not_member'; end if;
  select * into c from public.collections where id = cid;
  if c.status <> 'open'  then raise exception 'collection_closed'; end if;
  if m.paid_amount > 0   then raise exception 'already_paid';      end if;
  pay := coalesce(amount, m.share_amount);
  if pay < m.share_amount                     then raise exception 'amount_too_small';  end if;
  if pay > m.share_amount and not c.allow_extra then raise exception 'extra_not_allowed'; end if;
  update public.memberships set paid_amount = pay
   where collection_id = cid and user_id = auth.uid();
  return pay;
end $$;

-- ---------- Список участников сбора ----------
-- Видят организатор и участники. Отдаются только имена и суммы, без телефонов.
create or replace function public.get_members(cid uuid)
returns table (name text, role text, share_amount numeric, paid_amount numeric, is_me boolean)
language sql stable security definer set search_path = public as $$
  select p.name, m.role, m.share_amount, m.paid_amount, m.user_id = auth.uid()
    from public.memberships m
    join public.profiles p on p.id = m.user_id
   where m.collection_id = cid
     and (public.is_collection_organizer(cid) or public.is_collection_member(cid))
   order by (m.role = 'organizer') desc, m.joined_at;
$$;

-- ---------- Права на вызов ----------
revoke all on function public.get_invite(text)              from public;
revoke all on function public.join_collection(text)         from public, anon;
revoke all on function public.demo_pay(uuid, numeric)       from public, anon;
revoke all on function public.get_members(uuid)             from public, anon;
grant execute on function public.get_invite(text)           to anon, authenticated;
grant execute on function public.join_collection(text)      to authenticated;
grant execute on function public.demo_pay(uuid, numeric)    to authenticated;
grant execute on function public.get_members(uuid)          to authenticated;
