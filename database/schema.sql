-- =============================================================================
-- PRESTAZIONI AGGIUNTIVE AMBULATORIALI – S.O.C. Ortopedia e Traumatologia, Verduno
-- Database Supabase: da incollare tutto nel SQL Editor e lanciare (Run) una volta.
--
-- Sicurezza: le tabelle non sono leggibili né scrivibili direttamente dalla pagina
-- (RLS attivo e nessun permesso). La pagina usa solo le funzioni qui sotto, che
-- controllano ogni volta il "pass" di accesso del medico.
-- =============================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------- tabelle
create table if not exists public.medici (
  id       serial primary key,
  cognome  text not null,
  nome     text not null,
  titolo   text not null default 'Dott.' check (titolo in ('Dott.', 'Dott.ssa')),
  utente   text not null unique,
  attivo   boolean not null default true,
  admin    boolean not null default false,
  creato   timestamptz not null default now()
);

create table if not exists public.ambulatori (
  id          uuid primary key default gen_random_uuid(),
  medico_id   int not null references public.medici(id),
  data        date not null,
  sede        text not null check (sede in ('Verduno', 'Alba', 'Bra')),
  inizio      smallint not null check (inizio >= 0 and inizio % 15 = 0),
  fine        smallint not null check (fine <= 1440 and fine % 15 = 0 and fine > inizio),
  inserito    timestamptz not null default now(),
  inserito_da int references public.medici(id) on delete set null
);
create index if not exists ambulatori_data_idx on public.ambulatori (data);

create table if not exists public.impostazioni (
  id     int primary key default 1 check (id = 1),
  lordo  numeric not null default 100,   -- € lordi all'ora
  netto  numeric not null default 85,    -- € netti all'ora
  enpam  numeric not null default 2      -- % ENPAM sul netto
);
insert into public.impostazioni (id) values (1) on conflict do nothing;

create table if not exists public.credenziali (
  medico_id   int primary key references public.medici(id) on delete cascade,
  hash        text not null,
  provvisoria boolean not null default true,
  aggiornato  timestamptz not null default now()
);

create table if not exists public.sessioni (
  token_hash text primary key,
  medico_id  int not null references public.medici(id) on delete cascade,
  scade      timestamptz not null,
  creato     timestamptz not null default now()
);

create table if not exists public.tentativi (
  utente text not null,
  quando timestamptz not null default now()
);

alter table public.medici       enable row level security;
alter table public.ambulatori   enable row level security;
alter table public.impostazioni enable row level security;
alter table public.credenziali  enable row level security;
alter table public.sessioni     enable row level security;
alter table public.tentativi    enable row level security;
revoke all on public.medici, public.ambulatori, public.impostazioni,
              public.credenziali, public.sessioni, public.tentativi from anon, authenticated;

-- ---------------------------------------------------------------- funzioni interne
create or replace function public._etichetta(m public.medici) returns text
language sql immutable as $$ select upper(m.cognome) || ' ' || m.nome $$;

create or replace function public._hhmm(m int) returns text
language sql immutable as $$ select lpad((m / 60)::text, 2, '0') || ':' || lpad((m % 60)::text, 2, '0') $$;

create or replace function public._ora(m int) returns text            -- 8.30
language sql immutable as $$ select (m / 60)::text || '.' || lpad((m % 60)::text, 2, '0') $$;

create or replace function public._minuti(t text) returns int
language sql immutable as $$
  select case when t ~ '^\d{1,2}[:.]\d{2}$'
              then split_part(replace(t, '.', ':'), ':', 1)::int * 60 + split_part(replace(t, '.', ':'), ':', 2)::int end
$$;

create or replace function public._giorno(d date) returns text        -- Martedì 7 Ottobre
language sql immutable as $$
  select (array['Domenica','Lunedì','Martedì','Mercoledì','Giovedì','Venerdì','Sabato'])[extract(dow from d)::int + 1]
         || ' ' || extract(day from d)::int || ' ' ||
         (array['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'])[extract(month from d)::int]
$$;

create or replace function public._data(t text) returns date
language plpgsql immutable as $$
begin
  if t is null or t !~ '^\d{4}-\d{2}-\d{2}$' then return null; end if;
  return t::date;
exception when others then return null;
end $$;

create or replace function public._pulisci(t text) returns text
language sql immutable as $$
  select lower(regexp_replace(translate(coalesce(t, ''),
         'àáâäèéêëìíîïòóôöùúûüÀÁÂÄÈÉÊËÌÍÎÏÒÓÔÖÙÚÛÜçÇñÑ', 'aaaaeeeeiiiioooouuuuAAAAEEEEIIIIOOOOUUUUcCnN'), '[^A-Za-z]', '', 'g'))
$$;
-- utente = iniziale del nome + cognome (Paolo Bedino -> pbedino)
create or replace function public._utente_base(nome text, cognome text) returns text
language sql immutable as $$ select left(public._pulisci(nome), 1) || public._pulisci(cognome) $$;

-- controlla il pass; restituisce il medico collegato
create or replace function public._auth(p_token text, p_admin boolean default false) returns public.medici
language plpgsql stable security definer set search_path = public, extensions as $$
declare m public.medici;
begin
  select md.* into m
    from public.sessioni s join public.medici md on md.id = s.medico_id
   where s.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and s.scade > now() and md.attivo;
  if not found then raise exception 'AUTH: accesso scaduto, entra di nuovo.'; end if;
  if p_admin and not m.admin then raise exception 'Solo l''amministratore può farlo.'; end if;
  return m;
end $$;

create or replace function public._medico(p_label text) returns public.medici
language plpgsql stable security definer set search_path = public as $$
declare m public.medici;
begin
  select * into m from public.medici md where public._etichetta(md) = trim(coalesce(p_label, ''));
  if not found then raise exception 'Medico non riconosciuto: %', p_label; end if;
  return m;
end $$;

create or replace function public._genera_codice() returns text
language plpgsql volatile set search_path = public, extensions as $$
declare a text := 'abcdefghjkmnpqrstuvwxyz23456789'; b bytea := gen_random_bytes(8); s text := '';
begin
  for i in 0..7 loop s := s || substr(a, (get_byte(b, i) % length(a)) + 1, 1); end loop;
  return substr(s, 1, 4) || '-' || substr(s, 5, 4);
end $$;

-- nuovo codice provvisorio: sostituisce password e accessi precedenti
create or replace function public._nuovo_codice(p_medico int) returns text
language plpgsql volatile security definer set search_path = public, extensions as $$
declare c text := public._genera_codice();
begin
  insert into public.credenziali (medico_id, hash, provvisoria, aggiornato)
       values (p_medico, crypt(c, gen_salt('bf', 8)), true, now())
  on conflict (medico_id) do update set hash = excluded.hash, provvisoria = true, aggiornato = now();
  delete from public.sessioni where medico_id = p_medico;
  return c;
end $$;

create or replace function public._impostazioni() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object(
    'lordo', i.lordo, 'netto', i.netto, 'enpam', i.enpam,
    'inattivi', coalesce((select json_agg(public._etichetta(m) order by m.cognome) from public.medici m where not m.attivo), '[]'::json))
  from public.impostazioni i where i.id = 1
$$;

create or replace function public._medici_json() returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object(
           'v', public._etichetta(m), 'breve', m.titolo || ' ' || m.cognome,
           'cognome', m.cognome, 'nome', m.nome, 'utente', m.utente) order by public._etichetta(m)), '[]'::json)
  from public.medici m
$$;

create or replace function public._con_accesso() returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(public._etichetta(m)), '[]'::json)
  from public.medici m join public.credenziali c on c.medico_id = m.id
$$;

-- controlla e prepara una fascia; errore leggibile se qualcosa non va
create or replace function public._fascia(p_nome text, p_sede text, p_inizio text, p_fine text, out inizio int, out fine int)
language plpgsql immutable as $$
begin
  if coalesce(p_sede, '') not in ('Verduno', 'Alba', 'Bra') then raise exception '%: scegli la sede.', p_nome; end if;
  inizio := public._minuti(p_inizio); fine := public._minuti(p_fine);
  if inizio is null or fine is null then raise exception '%: manca un orario.', p_nome; end if;
  if fine <= inizio then raise exception '%: l''ora di fine deve essere dopo l''ora di inizio.', p_nome; end if;
  if inizio % 15 <> 0 or fine % 15 <> 0 then raise exception '%: gli orari vanno a quarti d''ora.', p_nome; end if;
end $$;

-- ---------------------------------------------------------------- accesso
create or replace function public.login(p_utente text, p_password text) returns json
language plpgsql volatile security definer set search_path = public, extensions as $$
declare m public.medici; c public.credenziali; n int; t text;
begin
  p_utente := lower(trim(coalesce(p_utente, '')));
  delete from public.tentativi where quando < now() - interval '1 day';
  select count(*) into n from public.tentativi where utente = p_utente and quando > now() - interval '15 minutes';
  if n >= 5 then return json_build_object('errore', 'Troppi tentativi sbagliati: riprova tra 15 minuti.'); end if;

  select * into m from public.medici where utente = p_utente;
  if found then
    if not m.attivo then return json_build_object('errore', 'Questo utente non è attivo: chiedi all''amministratore.'); end if;
    select * into c from public.credenziali where medico_id = m.id;
    if not found then
      return json_build_object('errore', 'Per ' || p_utente || ' non c''è ancora un accesso: chiedi il codice all''amministratore.');
    end if;
  end if;
  if m.id is null or crypt(coalesce(p_password, ''), c.hash) <> c.hash then
    insert into public.tentativi (utente) values (p_utente);
    return json_build_object('errore', 'Utente o password non corretti.');
  end if;

  delete from public.tentativi where utente = p_utente;
  delete from public.sessioni where scade < now();
  t := encode(gen_random_bytes(32), 'hex');
  insert into public.sessioni (token_hash, medico_id, scade)
       values (encode(digest(t, 'sha256'), 'hex'), m.id, now() + interval '60 days');
  return json_build_object('token', t, 'provvisoria', c.provvisoria);
end $$;

create or replace function public.logout(p_token text) returns void
language sql volatile security definer set search_path = public, extensions as $$
  delete from public.sessioni where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.cambia_password(p_token text, p_attuale text, p_nuova text) returns json
language plpgsql volatile security definer set search_path = public, extensions as $$
declare m public.medici := public._auth(p_token); c public.credenziali;
begin
  if length(coalesce(p_nuova, '')) < 8 then raise exception 'La password deve avere almeno 8 caratteri.'; end if;
  if length(p_nuova) > 100 then raise exception 'Password troppo lunga.'; end if;
  select * into c from public.credenziali where medico_id = m.id;
  if crypt(coalesce(p_attuale, ''), c.hash) <> c.hash then raise exception 'La password attuale non è corretta.'; end if;
  if p_attuale = p_nuova then raise exception 'Scegli una password diversa da quella attuale.'; end if;
  update public.credenziali set hash = crypt(p_nuova, gen_salt('bf', 8)), provvisoria = false, aggiornato = now()
   where medico_id = m.id;
  -- chiude gli altri accessi di questo medico, tiene quello attuale
  delete from public.sessioni where medico_id = m.id and token_hash <> encode(digest(p_token, 'sha256'), 'hex');
  return json_build_object('token', p_token);
end $$;

create or replace function public.codice_accesso(p_token text, p_medico text) returns json
language plpgsql volatile security definer set search_path = public as $$
declare a public.medici := public._auth(p_token, true); m public.medici := public._medico(p_medico);
begin
  return json_build_object('utente', m.utente, 'codice', public._nuovo_codice(m.id));
end $$;

-- Solo dal SQL Editor (non dalla pagina): primo codice per l'amministratore
--   select public.codice_iniziale('pbedino');
create or replace function public.codice_iniziale(p_utente text) returns text
language plpgsql volatile security definer set search_path = public as $$
declare m public.medici;
begin
  select * into m from public.medici where utente = lower(trim(p_utente));
  if not found then raise exception 'Utente % non trovato', p_utente; end if;
  return 'Utente: ' || m.utente || '   Codice provvisorio: ' || public._nuovo_codice(m.id);
end $$;

-- ---------------------------------------------------------------- dati
create or replace function public.dati_iniziali(p_token text) returns json
language plpgsql stable security definer set search_path = public as $$
declare m public.medici := public._auth(p_token);
begin
  return json_build_object(
    'medici', public._medici_json(),
    'sedi', json_build_array('Verduno', 'Alba', 'Bra'),
    'oraMin', 7, 'oraMax', 21, 'minutiVisita', 15,
    'oggi', to_char((now() at time zone 'Europe/Rome')::date, 'YYYY-MM-DD'),
    'io', public._etichetta(m),
    'admin', m.admin,
    'provvisoria', (select provvisoria from public.credenziali where medico_id = m.id),
    'impostazioni', public._impostazioni(),
    'conAccesso', case when m.admin then public._con_accesso() end,
    'link', json_build_object('pagina', '', 'foglio', '')
  );
end $$;

create or replace function public.ambulatori_mese(p_token text, p_anno int, p_mese int) returns json
language plpgsql stable security definer set search_path = public as $$
begin
  perform public._auth(p_token);
  return coalesce((
    select json_agg(json_build_object(
             'id', a.id, 'data', to_char(a.data, 'YYYY-MM-DD'), 'medico', public._etichetta(m),
             'breve', m.titolo || ' ' || m.cognome, 'sede', a.sede,
             'inizio', public._hhmm(a.inizio), 'fine', public._hhmm(a.fine), 'visite', (a.fine - a.inizio) / 15)
           order by a.data, a.inizio, m.cognome)
      from public.ambulatori a join public.medici m on m.id = a.medico_id
     where a.data >= make_date(p_anno, p_mese, 1) and a.data < make_date(p_anno, p_mese, 1) + interval '1 month'), '[]'::json);
end $$;

create or replace function public.ambulatori_anno(p_token text, p_anno int) returns json
language plpgsql stable security definer set search_path = public as $$
begin
  perform public._auth(p_token);
  return coalesce((
    select json_agg(json_build_object(
             'm', extract(month from a.data)::int, 'medico', public._etichetta(m), 'sede', a.sede,
             'min', a.fine - a.inizio, 'visite', (a.fine - a.inizio) / 15))
      from public.ambulatori a join public.medici m on m.id = a.medico_id
     where extract(year from a.data) = p_anno), '[]'::json);
end $$;

-- p = { giorni: [{ data: '2026-11-04', fasce: [{ sede, inizio: '08:00', fine: '12:00', medici: ['GIANI Guglielmo'] }] }] }
create or replace function public.salva(p_token text, p jsonb) returns json
language plpgsql volatile security definer set search_path = public as $$
declare io public.medici := public._auth(p_token);
        g jsonb; f jsonb; v text; d date; nome text; x record; med public.medici; c record; n int := 0; vis int := 0;
begin
  create temp table if not exists _nuovi (k serial, medico_id int, cognome text, titolo text, data date, sede text, inizio int, fine int) on commit drop;
  truncate _nuovi;
  if p is null or jsonb_array_length(coalesce(p->'giorni', '[]')) = 0 then raise exception 'Seleziona almeno un giorno sul calendario.'; end if;
  for g in select * from jsonb_array_elements(p->'giorni') loop
    d := public._data(g->>'data');
    if d is null then raise exception 'Data non valida: %', g->>'data'; end if;
    nome := public._giorno(d);
    if jsonb_array_length(coalesce(g->'fasce', '[]')) = 0 then raise exception '%: aggiungi almeno una fascia oraria.', nome; end if;
    for f in select * from jsonb_array_elements(g->'fasce') loop
      x := public._fascia(nome, f->>'sede', f->>'inizio', f->>'fine');
      if jsonb_array_length(coalesce(f->'medici', '[]')) = 0 then raise exception '% %: scegli almeno un medico.', nome, public._ora(x.inizio); end if;
      for v in select * from jsonb_array_elements_text(f->'medici') loop
        med := public._medico(v);
        insert into _nuovi (medico_id, cognome, titolo, data, sede, inizio, fine) values (med.id, med.cognome, med.titolo, d, f->>'sede', x.inizio, x.fine);
      end loop;
    end loop;
  end loop;

  -- sovrapposizioni dello stesso medico (tra i nuovi e con quelli già inseriti)
  select a.*, o.inizio as oi, o.fine as ofi, o.gia into c from _nuovi a
    join (select k, medico_id, data, inizio, fine, false as gia from _nuovi
          union all select null, medico_id, data, inizio, fine, true from public.ambulatori) o
      on o.medico_id = a.medico_id and o.data = a.data and a.inizio < o.fine and o.inizio < a.fine and (o.k is null or o.k <> a.k)
   limit 1;
  if found then
    raise exception '%', format('%s %s, %s: la fascia %s–%s si sovrappone a %s–%s%s.', c.titolo, c.cognome, public._giorno(c.data),
      public._ora(c.inizio), public._ora(c.fine), public._ora(c.oi), public._ora(c.ofi), case when c.gia then ' già inserita' else '' end);
  end if;

  insert into public.ambulatori (medico_id, data, sede, inizio, fine, inserito_da)
       select medico_id, data, sede, inizio, fine, io.id from _nuovi;
  select count(*), coalesce(sum((fine - inizio) / 15), 0) into n, vis from _nuovi;
  return json_build_object('ambulatori', n, 'visite', vis);
end $$;

-- x = { data: 'yyyy-mm-dd', medico, sede, inizio: 'HH:MM', fine: 'HH:MM' }
create or replace function public.modifica(p_token text, p_id uuid, x jsonb) returns boolean
language plpgsql volatile security definer set search_path = public as $$
declare d date; med public.medici; f record; c record;
begin
  perform public._auth(p_token);
  if not exists (select 1 from public.ambulatori where id = p_id) then
    raise exception 'Ambulatorio non trovato (forse eliminato da qualcun altro).';
  end if;
  d := public._data(x->>'data');
  if d is null then raise exception 'Data non valida.'; end if;
  if coalesce(x->>'medico', '') = '' then raise exception 'Scegli il medico.'; end if;
  med := public._medico(x->>'medico');
  f := public._fascia(public._giorno(d), x->>'sede', x->>'inizio', x->>'fine');
  select * into c from public.ambulatori o
   where o.id <> p_id and o.medico_id = med.id and o.data = d and f.inizio < o.fine and o.inizio < f.fine limit 1;
  if found then
    raise exception '% %, %: la fascia %–% si sovrappone a %–% già inserita.', med.titolo, med.cognome, public._giorno(d),
      public._ora(f.inizio), public._ora(f.fine), public._ora(c.inizio), public._ora(c.fine);
  end if;
  update public.ambulatori set medico_id = med.id, data = d, sede = x->>'sede', inizio = f.inizio, fine = f.fine where id = p_id;
  return true;
end $$;

create or replace function public.elimina(p_token text, p_id uuid) returns boolean
language plpgsql volatile security definer set search_path = public as $$
begin
  perform public._auth(p_token);
  delete from public.ambulatori where id = p_id;
  if not found then raise exception 'Ambulatorio non trovato (forse già eliminato).'; end if;
  return true;
end $$;

-- ---------------------------------------------------------------- amministrazione
create or replace function public.salva_impostazioni(p_token text, x jsonb) returns json
language plpgsql volatile security definer set search_path = public as $$
declare io public.medici := public._auth(p_token, true);
        num numeric;
begin
  if x ? 'lordo' then
    begin num := replace(x->>'lordo', ',', '.')::numeric; exception when others then raise exception 'Valore non valido: %', x->>'lordo'; end;
    if num < 0 or num > 10000 then raise exception 'Valore non valido: %', x->>'lordo'; end if;
    update public.impostazioni set lordo = round(num, 2) where id = 1;
  end if;
  if x ? 'netto' then
    begin num := replace(x->>'netto', ',', '.')::numeric; exception when others then raise exception 'Valore non valido: %', x->>'netto'; end;
    if num < 0 or num > 10000 then raise exception 'Valore non valido: %', x->>'netto'; end if;
    update public.impostazioni set netto = round(num, 2) where id = 1;
  end if;
  if x ? 'enpam' then
    begin num := replace(x->>'enpam', ',', '.')::numeric; exception when others then raise exception 'Valore non valido: %', x->>'enpam'; end;
    if num < 0 or num > 100 then raise exception 'Valore non valido: %', x->>'enpam'; end if;
    update public.impostazioni set enpam = round(num, 2) where id = 1;
  end if;
  if x ? 'inattivi' then
    if (x->'inattivi') ? public._etichetta(io) then raise exception 'Non puoi disattivare te stesso.'; end if;
    update public.medici m set attivo = not ((x->'inattivi') ? public._etichetta(m));
    delete from public.sessioni s using public.medici m where m.id = s.medico_id and not m.attivo;
  end if;
  return public._impostazioni();
end $$;

create or replace function public.aggiungi_medico(p_token text, x jsonb) returns json
language plpgsql volatile security definer set search_path = public as $$
declare io public.medici := public._auth(p_token, true);
        cog text := initcap(regexp_replace(trim(coalesce(x->>'cognome', '')), '\s+', ' ', 'g'));
        nom text := initcap(regexp_replace(trim(coalesce(x->>'nome', '')), '\s+', ' ', 'g'));
        tit text := case when x->>'titolo' = 'Dott.ssa' then 'Dott.ssa' else 'Dott.' end;
        u text; k int := 2;
begin
  if cog = '' or nom = '' then raise exception 'Inserisci nome e cognome.'; end if;
  if exists (select 1 from public.medici m where public._etichetta(m) = upper(cog) || ' ' || nom) then
    raise exception '% è già in elenco.', upper(cog) || ' ' || nom;
  end if;
  u := public._utente_base(nom, cog);
  while exists (select 1 from public.medici where utente = u) loop     -- es. gdipalma -> gidipalma
    if k > length(public._pulisci(nom)) then raise exception 'Non riesco a creare un utente unico.'; end if;
    u := left(public._pulisci(nom), k) || public._pulisci(cog);
    k := k + 1;
  end loop;
  insert into public.medici (cognome, nome, titolo, utente, attivo)
       values (cog, nom, tit, u, coalesce((x->>'attivo')::boolean, true));
  return json_build_object('medici', public._medici_json(), 'impostazioni', public._impostazioni(), 'conAccesso', public._con_accesso());
end $$;

create or replace function public.rimuovi_medico(p_token text, p_medico text) returns json
language plpgsql volatile security definer set search_path = public as $$
declare io public.medici := public._auth(p_token, true); m public.medici := public._medico(p_medico); n int;
begin
  if m.id = io.id then raise exception 'Non puoi eliminare te stesso.'; end if;
  select count(*) into n from public.ambulatori where medico_id = m.id;
  if n > 0 then raise exception '% ha % ambulatori registrati: non si può eliminare. Disattivalo invece.', p_medico, n; end if;
  update public.ambulatori set inserito_da = null where inserito_da = m.id;
  delete from public.medici where id = m.id;
  return json_build_object('medici', public._medici_json(), 'impostazioni', public._impostazioni(), 'conAccesso', public._con_accesso());
end $$;

-- tutti gli ambulatori di un anno, per scaricarli in CSV
create or replace function public.esporta(p_token text, p_anno int) returns json
language plpgsql stable security definer set search_path = public as $$
begin
  perform public._auth(p_token);
  return coalesce((
    select json_agg(json_build_object(
             'data', to_char(a.data, 'DD/MM/YYYY'), 'medico', public._etichetta(m), 'sede', a.sede,
             'inizio', public._hhmm(a.inizio), 'fine', public._hhmm(a.fine), 'visite', (a.fine - a.inizio) / 15,
             'inserito', to_char(a.inserito at time zone 'Europe/Rome', 'DD/MM/YYYY HH24:MI'))
           order by a.data, a.inizio, m.cognome)
      from public.ambulatori a join public.medici m on m.id = a.medico_id
     where extract(year from a.data) = p_anno), '[]'::json);
end $$;

-- per il controllo giornaliero che tiene sveglio il progetto
create or replace function public.ping() returns text
language sql stable as $$ select 'ok' $$;

-- ---------------------------------------------------------------- permessi funzioni
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function
  public.login(text, text), public.logout(text), public.cambia_password(text, text, text),
  public.codice_accesso(text, text), public.dati_iniziali(text),
  public.ambulatori_mese(text, int, int), public.ambulatori_anno(text, int),
  public.salva(text, jsonb), public.modifica(text, uuid, jsonb), public.elimina(text, uuid),
  public.salva_impostazioni(text, jsonb), public.aggiungi_medico(text, jsonb), public.rimuovi_medico(text, text),
  public.esporta(text, int), public.ping()
to anon, authenticated;
