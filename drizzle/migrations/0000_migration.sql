create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  xp integer not null default 0,
  streak integer not null default 0,
  longest_streak integer not null default 0,
  last_active_date date,
  hearts integer not null default 5,
  hearts_updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
grant select on public.profiles to authenticated;
grant update (username) on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;
create policy "own profile read" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "own profile update" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

create table public.activity_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  kind text not null check (kind in ('lesson','lab','test')),
  ref_id text not null,
  score integer not null check (score between 0 and 100),
  xp integer not null default 0,
  created_at timestamptz not null default now()
);
create index on public.activity_log (user_id, kind, ref_id);
create index on public.activity_log (created_at);
grant select on public.activity_log to authenticated;
grant all on public.activity_log to service_role;
alter table public.activity_log enable row level security;
create policy "own activity read" on public.activity_log for select to authenticated using (auth.uid() = user_id);

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(nullif(new.raw_user_meta_data->>'username',''), split_part(new.email,'@',1), 'hacker'));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- hearts regenerate 1 per 30 min, max 5
create or replace function public.refresh_hearts(_uid uuid) returns void
language plpgsql security definer set search_path = public as $$
declare p record; gained int;
begin
  select * into p from profiles where id = _uid for update;
  if p.hearts >= 5 then
    update profiles set hearts_updated_at = now() where id = _uid;
    return;
  end if;
  gained := floor(extract(epoch from (now() - p.hearts_updated_at)) / 1800);
  if gained > 0 then
    update profiles set hearts = least(5, hearts + gained),
      hearts_updated_at = p.hearts_updated_at + (gained * interval '30 minutes')
    where id = _uid;
  end if;
end $$;

create or replace function public.get_my_profile() returns public.profiles
language plpgsql security definer set search_path = public as $$
declare r profiles;
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  perform refresh_hearts(auth.uid());
  select * into r from profiles where id = auth.uid();
  return r;
end $$;

create or replace function public.lose_heart() returns integer
language plpgsql security definer set search_path = public as $$
declare h int;
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  perform refresh_hearts(auth.uid());
  update profiles set hearts = greatest(0, hearts - 1),
    hearts_updated_at = case when hearts >= 5 then now() else hearts_updated_at end
  where id = auth.uid() returning hearts into h;
  return h;
end $$;

create or replace function public.complete_activity(_kind text, _ref text, _score int) returns integer
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); base int; earned int; prior int; today date := (now() at time zone 'utc')::date; p record;
begin
  if uid is null then raise exception 'not authenticated'; end if;
  if _kind not in ('lesson','lab','test') then raise exception 'bad kind'; end if;
  if _score < 0 or _score > 100 or length(_ref) > 80 then raise exception 'bad input'; end if;
  base := case _kind when 'lesson' then 15 when 'lab' then 30 else 50 end;
  select count(*) into prior from activity_log where user_id = uid and kind = _kind and ref_id = _ref and score >= 80;
  if prior > 0 then earned := 3;
  else earned := round(base * _score / 100.0); end if;
  if _kind = 'test' and _score < 80 then earned := least(earned, 5); end if;
  insert into activity_log (user_id, kind, ref_id, score, xp) values (uid, _kind, _ref, _score, earned);
  select * into p from profiles where id = uid for update;
  update profiles set xp = xp + earned,
    streak = case when p.last_active_date = today then streak
                  when p.last_active_date = today - 1 then streak + 1 else 1 end,
    longest_streak = greatest(longest_streak, case when p.last_active_date = today then streak
                  when p.last_active_date = today - 1 then streak + 1 else 1 end),
    last_active_date = today
  where id = uid;
  return earned;
end $$;

create or replace function public.get_leaderboard() returns table(username text, weekly_xp bigint, total_xp int, is_me boolean)
language sql stable security definer set search_path = public as $$
  select p.username, coalesce(sum(a.xp),0) as weekly_xp, p.xp, p.id = auth.uid()
  from profiles p left join activity_log a on a.user_id = p.id and a.created_at > now() - interval '7 days'
  group by p.id order by weekly_xp desc, p.xp desc limit 50;
$$;

revoke execute on function public.refresh_hearts(uuid) from public, anon, authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.get_my_profile() from public, anon;
revoke execute on function public.lose_heart() from public, anon;
revoke execute on function public.complete_activity(text,text,int) from public, anon;
revoke execute on function public.get_leaderboard() from public, anon;
grant execute on function public.get_my_profile(), public.lose_heart(), public.complete_activity(text,text,int), public.get_leaderboard() to authenticated;