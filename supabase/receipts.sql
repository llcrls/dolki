-- =====================================================================
--  Дольки — добавление чеков (для базы, где уже запущен schema.sql версии 2)
--  Supabase → SQL Editor → New query → вставить весь файл → Run.
--  Данные в существующих таблицах не удаляются.
-- =====================================================================

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

-- Обновлённая функция приглашения: теперь отдаёт и чек (только участникам)
create or replace function public.get_invite(code text)
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
