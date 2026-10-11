<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import { ask, askText } from './dialog.svelte.js'
  import { dash } from './dash.svelte.js'
  import ProefPlan from './ProefPlan.svelte'

  // net → publiek: per naam of iemand op internet erbij kan, en welke login ervoor staat (Cloudflare Access, Authentik,
  // een toegangslijst in NPM). Het dashboard leest alleen: oplossen doe je in Cloudflare of NPM, of je markeert een naam
  // als bewust (met 2FA). onchanged: het aantal rode namen voor het tabblad.
  let { onchanged = null } = $props()
  let data = $state(null)
  let error = $state('')
  let busy = $state(false)
  let filter = $state('alles')
  let q = $state('')
  let open = $state(null)
  let plan = $state(null)

  function got(d) {
    data = d
    error = ''
    onchanged?.(d)
  }
  async function load() {
    try { got(await api('/exposure')) } catch (e) { error = e.message }
  }
  // De worker kijkt elk uur: elke 5 minuten opnieuw laden is ruim genoeg.
  onMount(() => { load(); return poll(load, 300000) })
  async function refresh() {
    busy = true
    try { got(await api('/exposure/refresh', { method: 'POST' })) } catch (e) { error = e.message } finally { busy = false }
  }
  async function calls() {
    try { plan = await api('/exposure/proef') } catch (e) { error = e.message }
  }

  const MARKABLE = ['open', 'wildcard', 'wees', 'verborgen', 'elders']
  const markLabel = (r) => (['wees', 'elders'].includes(r.base) ? 'bewust zo…' : 'bewust open…')
  async function intend(r) {
    const reason = await askText(`Waarom is ${r.name} zo in orde?`,
      { title: markLabel(r).replace('…', ''), ok: 'Bewaren', placeholder: 'bv. publieke blog, eigen login, VPN-adres' })
    if (!reason?.trim()) return
    try { got(await withReauth(() => api('/exposure/intended', { method: 'PUT', body: { name: r.name, reason: reason.trim() } }))) }
    catch (e) { error = e.message }
  }
  async function unintend(r) {
    if (!(await ask(`${r.name} weer als probleem tonen?`, { ok: 'Ja' }))) return
    try { got(await api(`/exposure/intended/${encodeURIComponent(r.name)}`, { method: 'DELETE' })) } catch (e) { error = e.message }
  }

  const STATE = { open: 'open zonder login', overname: 'kan overgenomen worden', wildcard: 'wildcard', wees: 'DNS zonder host',
    verborgen: 'open via thuis-IP', onbekend: 'niet na te gaan', slot: 'login ervoor', dicht: 'dicht van buitenaf',
    elders: 'elders', doorverwijzing: 'doorverwijzing', intern: 'alleen intern', bewust: 'bewust' }
  const PATH = { tunnel: 'tunnel', proxied: 'oranje wolk', 'dns-only': 'grijze wolk (rechtstreeks)',
    thuis: 'thuis-IP (langs Cloudflare heen)', extern: 'extern' }
  const KIND = { proxy: 'proxy host', redirect: 'redirection host', dead: '404-host' }
  const MANAGED = { cloudflare: 'beheerd in Cloudflare', local: 'lokaal beheerd (config.yml)' }
  // De rechten met hun naam zoals in Cloudflare en NPM (zelfde lijst als exposure.NEEDED en OPTIONAL).
  const NEEDED = { tunnel_config: 'Account → Cloudflare Tunnel → Read (instellingen van de tunnels)',
    access_read: 'Account → Access: Apps and Policies → Read', npm_access_lists: 'NPM: View op Access Lists',
    npm_redirects: 'NPM: View op Redirection Hosts en 404 Hosts' }
  const OPTIONAL = { zone_settings: 'Zone → Zone Settings → Read', access_zone: 'Zone → Access: Apps and Policies → Read' }
  const FILTERS = [['alles', null], ['rood', (r) => r.level === 'err'], ['let op', (r) => r.level === 'warn'],
    ['bewust', (r) => r.state === 'bewust'], ['in orde', (r) => r.level === 'ok'],
    ['overig', (r) => r.level === 'muted' || (r.level === 'info' && r.state !== 'bewust')]]

  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '—')
  const hay = (r) => [r.name, ...(r.dns || []).map((d) => d.to), r.npm?.target || ''].join(' ').toLowerCase()
  let rows = $derived(data?.rows || [])
  let counts = $derived(Object.fromEntries(FILTERS.map(([k, f]) => [k, f ? rows.filter(f).length : rows.length])))
  let shown = $derived.by(() => {
    const f = FILTERS.find(([k]) => k === filter)?.[1]
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return rows.filter((r) => (!f || f(r)) && words.every((w) => hay(r).includes(w)))
  })
  let missing = $derived(Object.keys(NEEDED).filter((k) => data?.rights?.[k] === false))
  let optional = $derived(Object.keys(OPTIONAL).filter((k) => data?.rights?.[k] === false))
  let inb = $derived(data?.inbound)
  let origin = $derived(inb?.origin)

  function npmPart(r) {
    if (!r.npm) return 'NPM'
    if (r.npm.kind === 'redirect') return 'NPM (doorverwijzing)'
    if (r.npm.kind === 'dead') return 'NPM (404)'
    return `NPM → ${r.npm.target || '?'}`
  }
  // Regel 2 van een rij: de weg van het record tot de app.
  function route(r) {
    const d = r.dns?.[0]
    if (!d) return r.state === 'verborgen' ? 'geen publiek DNS-record, maar bereikbaar via je thuis-IP' : 'geen publiek DNS-record'
    const out = [d.wildcard ? `${d.wildcard} (wildcard)` : null, d.proxied ? 'Cloudflare (oranje wolk)' : 'grijze wolk']
    if (r.tunnel) out.push(`tunnel ${r.tunnel.name}`, ['direct', 'dicht'].includes(r.tunnel.target) ? r.tunnel.service : npmPart(r))
    else if (/^thuis-IP|\(NPM\)|→ thuis-IP/.test(d.to)) out.push(d.to, npmPart(r))
    else out.push(d.to)
    return out.filter(Boolean).join(' → ')
  }
  const noLogin = (r) => !r.login?.length && ['open', 'verborgen', 'wildcard'].includes(r.base)
  function listText(al) {
    if (al.readable === false) return `toegangslijst #${al.id} (niet leesbaar)`
    const parts = [al.users ? `${al.users} gebruiker${al.users === 1 ? '' : 's'}` : '', ...(al.rules || [])].filter(Boolean)
    return `toegangslijst '${al.name}'${parts.length ? ` (${parts.join(', ')})` : ''}${al.satisfy_any ? ' · één van beide volstaat' : ''}`
  }
</script>

{#if error}<p class="err">{error}</p>{/if}

{#if data === null}
  {#if !error}<p class="hint">laden…</p>{/if}
{:else if !data.configured?.cloudflare}
  <p class="hint">Nog geen Cloudflare-API. Zet je Cloudflare-token in API-beheer (soort Cloudflare Tunnel) met Zone → Zone →
    Read, Zone → DNS → Read en Access: Apps and Policies → Read. Dan zie je hier welke namen publiek zijn.</p>
  <button class="mini" onclick={() => dash.open('apis')}>API-beheer openen</button>
{:else}
  <p class="hint intro">Per naam: staat er een DNS-record in Cloudflare, en zo ja, staat er een login voor (Cloudflare Access,
    Authentik of een toegangslijst in NPM)? Rood = van buitenaf bereikbaar zonder login ervoor.</p>

  {#if data.errors?.length}
    <section class="box warn">
      <b>niet gelukt</b>
      {#each data.errors as e, i (i)}<p>{e}</p>{/each}
    </section>
  {/if}

  {#if missing.length}
    <section class="box warn">
      <b>rechten ontbreken</b>
      <p>Daardoor zijn sommige namen niet na te gaan. Geef het Cloudflare-token of de NPM-gebruiker:</p>
      <ul>{#each missing as k (k)}<li>{NEEDED[k]}</li>{/each}</ul>
      {#if optional.length}<p class="sm">Optioneel (dan ontbreekt alleen een detail): {optional.map((k) => OPTIONAL[k]).join(', ')}.</p>{/if}
    </section>
  {:else if optional.length && data.at}
    <p class="sm m">Optioneel (dan ontbreekt alleen een detail): {optional.map((k) => OPTIONAL[k]).join(', ')}.</p>
  {/if}

  {#if !data.at}
    <p class="hint">{data.errors?.length ? 'Nog niet gelukt: zie de fout hierboven.' : 'Nog niet nagekeken. De worker doet dit elk uur.'}</p>
    <button class="mini" disabled={busy} onclick={refresh}>{busy ? 'bezig…' : 'nu nagaan'}</button>
  {:else}
    {#if data.stale}<p class="w sm">Laatst gelukt {when(data.at)}: ouder dan 3 uur.</p>{/if}
    {#if !data.configured?.npm}
      <p class="w sm">Nog geen NPM-tegel of -API: je ziet de DNS-records, maar niet of er een login voor staat.</p>
    {/if}

    <div class="status">
      <small>laatst nagekeken {when(data.checked_at || data.at)} · elk uur</small>
      <span class="sp"></span>
      <button class="mini" disabled={busy} onclick={refresh}>{busy ? 'bezig…' : 'vernieuwen'}</button>
      <button class="mini" onclick={calls}>welke calls?</button>
    </div>
    {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}

    {#if inb}
      <section class="box in">
        <b>hoe het binnenkomt</b>
        {#if inb.ip_known}
          <p>publiek IP <span class="v">{inb.public_ip}</span></p>
        {:else}
          <p class="w">publiek IP onbekend: {inb.ip_why || 'nog niet gekend'}</p>
        {/if}
        {#each inb.recent || [] as p (p.ip)}
          <p class="w">vorig IP {p.ip} tot {when(p.until)}: telt nog een dag als thuis</p>
        {/each}
        {#if origin}
          {#if origin.open === true}
            <p><span class="e">rechtstreeks naar NPM: open voor iedereen.</span> {origin.text}</p>
          {:else if origin.open === false}
            <p><span class="g">{origin.basis === 'cloudflare' ? 'alleen Cloudflare.' : 'geen doorverwijzing naar NPM.'}</span> {origin.text}</p>
          {:else}
            <p><span class="w">niet na te gaan.</span> Zet de nachtelijke kopie van OPNsense aan (Beheer → Configuratiewijzigingen):
              dan weet het dashboard of poort 443 open staat.</p>
          {/if}
        {/if}
        {#each inb.tunnels || [] as t (t.name)}
          <p class="sm">tunnel {t.name} · {t.deleted ? 'verwijderd' : t.status}{t.managed ? ` · ${MANAGED[t.managed] || t.managed}` : ''} · {t.names} {t.names === 1 ? 'naam' : 'namen'}</p>
        {/each}
        {#if inb.forwards}
          {#if inb.forwards.status === 'ok'}
            <p class="sm m">{inb.forwards.label}: {inb.forwards.rules.length ? 'doorverwijzingen op WAN' : 'geen doorverwijzingen op WAN'}</p>
            {#each inb.forwards.rules as f, i (i)}
              <p class="sm fw">{f.ext}{f.proto !== 'tcp' ? `/${f.proto}` : ''} → {f.to_ip}{f.to_port ? `:${f.to_port}` : ''}{f.descr ? ` (${f.descr})` : ''} · van: {f.from}{f.from_cf ? ' (Cloudflare)' : ''}</p>
            {/each}
          {:else}
            <p class="sm w">{inb.forwards.label}: niet te lezen ({inb.forwards.why})</p>
          {/if}
        {/if}
        <p class="sm m">tunnel {inb.paths?.tunnel || 0} · oranje wolk {inb.paths?.proxied || 0} · grijze wolk {inb.paths?.['dns-only'] || 0}</p>
      </section>
    {/if}

    <div class="filters">
      {#each FILTERS as [k] (k)}
        <button class="mini" class:on={filter === k} aria-pressed={filter === k} onclick={() => (filter = k)}>{k} <b>{counts[k]}</b></button>
      {/each}
      <input type="search" bind:value={q} placeholder="zoek een naam" aria-label="zoek een naam" />
    </div>

    {#each shown as r (r.name)}
      <div class="row lv-{r.level}">
        <button class="head" aria-expanded={open === r.name} onclick={() => (open = open === r.name ? null : r.name)}>
          <span class="l1"><i class="dot {r.level}"></i><b class="nm">{r.name}</b><span class="chip c-{r.level}">{STATE[r.state] || r.state}</span></span>
          <span class="l2">{route(r)}</span>
          {#if r.login?.length || noLogin(r) || r.https_forced != null}
            <span class="l2 l3">
              {#if r.login?.length}<span>login: {r.login.join(', ')}</span>{:else if noLogin(r)}<span class:e={r.level === 'err'}>geen login ervoor</span>{/if}
              {#if r.https_forced === true}<span>https afgedwongen</span>{:else if r.https_forced === false}<span class="w">geen https-doorverwijzing</span>{/if}
            </span>
          {/if}
        </button>
        {#if open === r.name}
          <div class="more">
            <p class="why">{r.why}</p>
            <dl>
              <dt>DNS</dt>
              <dd>{#each r.dns || [] as d, i (i)}<span class="ln">{d.type} → {d.to}{d.proxied ? ' (oranje wolk)' : ' (grijze wolk)'}{d.wildcard ? ` via ${d.wildcard}` : ''}</span>{:else}geen publiek record{/each}</dd>
              {#if r.paths?.length}
                <dt>wegen naar binnen</dt>
                <dd>{#each r.paths as p, i (i)}<span class="ln">{PATH[p.path] || p.path}: {STATE[p.state] || p.state}{p.login?.length ? ` (${p.login.join(', ')})` : ''}</span>{/each}</dd>
              {/if}
              {#if r.tunnel}
                <dt>tunnel</dt>
                <dd>{r.tunnel.name}{r.tunnel.service ? ` → ${r.tunnel.service}` : ''}{r.tunnel.managed ? ` · ${MANAGED[r.tunnel.managed] || r.tunnel.managed}` : ''}</dd>
              {/if}
              {#if r.npm}
                <dt>NPM</dt>
                <dd><span class="ln">{r.npm.source} · {KIND[r.npm.kind] || r.npm.kind}{r.npm.target ? ` → ${r.npm.target}` : ''}{r.npm.enabled === false ? ' · staat uit' : ''}</span>
                  {#if r.npm.access_list}<span class="ln">{listText(r.npm.access_list)}</span>{/if}
                  {#if r.npm.config_login}<span class="ln">eigen nginx-config: {r.npm.config_login}</span>{/if}</dd>
              {/if}
              <dt>login ervoor</dt>
              <dd>{r.login?.length ? r.login.join(', ') : 'geen'}</dd>
              {#if r.npm?.kind === 'proxy'}
                <dt>https</dt>
                <dd>{r.npm.cert ? 'certificaat' : 'geen certificaat'} · {r.npm.forced ? 'afgedwongen' : 'niet afgedwongen'}{r.npm.hsts ? ' · HSTS' : ''}</dd>
              {/if}
              {#if r.notes?.length}
                <dt>opmerkingen</dt>
                <dd>{#each r.notes as n, i (i)}<span class="ln" class:w={n.level === 'warn'}>{n.text}</span>{/each}</dd>
              {/if}
              {#if r.intended}
                <dt>bewust</dt>
                <dd>{r.intended.reason} · {r.intended.by} · {when(r.intended.at)}</dd>
              {/if}
            </dl>
            {#if r.state === 'bewust'}
              <button class="mini" onclick={() => unintend(r)}>niet meer bewust</button>
            {:else if MARKABLE.includes(r.base)}
              <button class="mini" onclick={() => intend(r)}>{markLabel(r)}</button>
            {/if}
          </div>
        {/if}
      </div>
    {:else}
      <p class="hint">Niets in deze lijst.</p>
    {/each}
  {/if}
{/if}

<style>
  .intro { margin-top: 0 }
  .box { padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: var(--fill); margin-bottom: 12px;
         font-size: 12.5px; overflow-wrap: anywhere }
  .box.warn { border-color: rgba(230, 181, 107, .55) }
  .box b { color: var(--text-h); font-weight: 500; font-size: 13px }
  .box p { margin: 4px 0 0 }
  .box ul { margin: 4px 0 0; padding-left: 18px }
  .status { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px }
  .status small { color: var(--muted) }
  .sp { flex: 1 }
  .v { color: var(--text-h) }
  .fw { padding-left: 10px }
  .sm { font-size: 11.5px }
  .m { color: var(--muted) }
  .g { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .filters { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 4px 0 10px }
  .filters b { font-weight: 500; color: var(--text-h); margin-left: 2px }
  .filters input { flex: 1 1 180px; width: auto; padding: 6px 10px; font-size: 12.5px }
  .row { display: block; border-bottom: 1px solid var(--line) }
  .head { display: flex; flex-direction: column; gap: 2px; width: 100%; min-height: 36px; padding: 7px 4px; text-align: left;
          background: none; border: 0; color: var(--text); cursor: pointer; font: inherit }
  .head:hover { background: var(--fill) }
  .head:focus-visible { outline: 2px solid #fff; outline-offset: -2px }
  .l1 { display: flex; flex-wrap: wrap; gap: 6px 8px; align-items: center; font-size: 12.5px }
  .l2 { display: block; font-size: 11.5px; color: var(--dim); overflow-wrap: anywhere }
  .l3 > span + span::before { content: '· '; color: var(--dim) }
  .nm { color: var(--text-h); font-weight: 500; overflow-wrap: anywhere; min-width: 0 }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); flex: none }
  .dot.err { background: var(--err) }
  .dot.warn { background: var(--mid) }
  .dot.ok { background: var(--ok) }
  .dot.info { background: #8fb8d6 }
  .chip { font-size: 10.5px; padding: 0 6px; border-radius: 6px; border: 1px solid var(--line-2); color: var(--muted) }
  .chip.c-err { color: var(--err); border-color: rgba(229, 139, 139, .5) }
  .chip.c-warn { color: var(--mid); border-color: rgba(230, 181, 107, .5) }
  .chip.c-ok { color: var(--ok); border-color: rgba(143, 214, 164, .45) }
  .more { padding: 2px 4px 10px 18px; font-size: 12px }
  .why { margin: 0 0 6px; color: var(--text-h); overflow-wrap: anywhere }
  dl { display: grid; grid-template-columns: 1fr; gap: 2px 12px; margin: 0 0 8px }
  dt { color: var(--muted); font-size: 11.5px; margin-top: 4px }
  dd { margin: 0; overflow-wrap: anywhere }
  .ln { display: block }
  .more .mini { min-height: 36px }
  @media (min-width: 480px) {
    dl { grid-template-columns: 9.5em 1fr }
    dt { margin-top: 0 }
  }
</style>
