<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import { boom } from './fx.js'
  import { CHANGELOG } from './changelog.js'
  import { dash } from './dash.svelte.js'
  import { byId, resolve } from './windows.js'
  import AttentionStrip from './AttentionStrip.svelte'
  import Card from './Card.svelte'
  import OutsideDialog from './OutsideDialog.svelte'
  import PageView, { endDrag, newPage } from './PageView.svelte'
  import ReauthDialog from './ReauthDialog.svelte'
  import SearchPanel from './SearchPanel.svelte'
  import Topbar from './Topbar.svelte'
  import WindowHost from './WindowHost.svelte'

  // Het hoofdscherm. De onderdelen staan elk in een eigen bestand; de gedeelde toestand in dash.svelte.js en welke
  // vensters er zijn in windows.js.
  // zonder: zonder login binnen (geen 2FA-code nodig); sessie: er is ook een echte login op dit toestel.
  let { user, zonder = false, sessie = true, onlogout } = $props()

  let query = $state('')
  let now = $state(new Date())
  let searchEl = $state()
  let search = $state()

  let summary = $derived.by(() => {
    const all = Object.values(dash.status)
    const active = all.filter((s) => !s.maintenance_until)
    return {
      // Een check die niets meer meldt (stale), staat grijs op de tegel: niet meetellen als up.
      up: active.filter((s) => s.status === 'up' && !s.stale).length,
      down: active.filter((s) => s.status === 'down').length,
      maint: all.length - active.length,
      paused: active.filter((s) => s.paused).length,
    }
  })
  let greeting = $derived.by(() => {
    const h = now.getHours()
    return h < 6 ? 'Goedenacht' : h < 12 ? 'Goedemorgen' : h < 18 ? 'Goedemiddag' : 'Goedenavond'
  })
  const hm = (d) => d.toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })
  let clock = $derived(hm(now))
  let date = $derived.by(() => {
    const d = now.toLocaleDateString('nl-BE', { weekday: 'long', day: 'numeric', month: 'long' })
    return d.charAt(0).toUpperCase() + d.slice(1)
  })
  // Hoe oud wat je ziet is: na twee gemiste verversingen oranje.
  let stale = $derived(!!dash.lastOk && now - dash.lastOk > 75000)

  // keep: met Logs uit het menu blijven periode en filters zoals je ze achterliet; van elders (zoekbalk, aandacht,
  // checklist, een melding) begint de logviewer opnieuw bij 24 uur.
  const openLogs = (host = null, q = '') => dash.open('logs', { host, q })

  async function logout() {
    boom()
    // Ook als de server niet antwoordt: lokaal uitloggen.
    try { await api('/auth/logout', { method: 'POST' }) } catch { /* sessie is dan toch weg of onbereikbaar */ }
    setTimeout(onlogout, dash.fx ? 600 : 0)
  }

  // --- Toetsenbord ----------------------------------------------------------

  function keydown(e) {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)
    if ((e.key === 'k' && (e.ctrlKey || e.metaKey)) || (e.key === '/' && !typing)) {
      e.preventDefault()
      searchEl?.focus()
    } else if (e.key === 'Escape' && document.activeElement === searchEl) {
      query = ''
      searchEl.blur()
    }
  }
  function searchKey(e) {
    if (e.key !== 'Enter') return
    // Zonder preventDefault drukt dezelfde Enter ook op de knop van een vraag die first() opent (een snelle actie).
    e.preventDefault()
    search?.first()
  }

  // Snelkoppelingen van de app (manifest), pushberichten en de Android-app: /?open=history, updates, network, ...
  // Alleen vensters uit een menu (en Aandacht); een tegel of formulier opent zo niet.
  function openFromUrl() {
    const q = new URLSearchParams(location.search)
    // Terug van Authentik na het koppelen (⚿ → authentik), met de fout als het niet lukte. Komt een loginfout terug
    // terwijl je al ingelogd bent, dan was het ook een koppeling: zelfde venster.
    const ssoErr = q.get('oidc_error') || q.get('login_error') || ''
    const what = q.get('open') || (ssoErr ? 'security' : null)
    if (!what) return
    history.replaceState(null, '', location.pathname)
    if (what === 'melding') return openPushed(q.get('n'))
    if (what === 'security') {
      return dash.open('security', { tab: ssoErr || q.get('tab') === 'sso' ? 'sso' : undefined, error: ssoErr })
    }
    const r = resolve(what)
    if (r && (byId[r.id]?.menu || r.id === 'attention')) dash.open(r)
  }
  // Tik op een pushbericht (/?open=melding&n=<id>): hetzelfde openen als een klik in het meldingencentrum.
  async function openPushed(id) {
    if (!/^\d+$/.test(id || '')) return
    try {
      const n = await api(`/notifications/${id}`)
      if (!n.read) api(`/notifications/${id}/read`, { method: 'POST' }).catch(() => {})
      // Een service openen kan pas als de indeling er is.
      for (let i = 0; i < 50 && !dash.loaded; i++) await new Promise((r) => setTimeout(r, 100))
      dash.openNotification(n)
    } catch { /* al gewist */ }
  }

  // Na een update één keer tonen wat er nieuw is (per gebruiker onthouden op de server).
  const latestNews = Math.max(0, ...CHANGELOG.map((c) => c.nr))
  async function checkNews() {
    try {
      const version = (dash.version = await api('/version'))
      const seen = Number(version.gezien) || 0
      if (seen >= latestNews) return
      if (!seen && version.nieuw_account) return markNews()
      const fresh = CHANGELOG.filter((c) => c.nr > seen)
      if (fresh.length && !dash.modal) dash.open('news', { entries: fresh, version })
    } catch { /* oudere backend zonder /version: niets tonen */ }
  }
  function markNews() {
    const version = dash.version
    if (version && Number(version.gezien) < latestNews) {
      dash.version = { ...version, gezien: String(latestNews) }
      api('/version/seen', { method: 'POST', body: { id: String(latestNews) } }).catch(() => {})
    }
  }

  onMount(() => {
    dash.modal = null
    dash.big = {}
    dash.order = []
    dash.editing = false
    dash.problemsOnly = false
    openFromUrl()
    checkNews()
    const stop = dash.start()
    const t = setInterval(() => (now = new Date()), 15000)
    return () => { stop(); clearInterval(t) }
  })
</script>

<svelte:window onkeydown={keydown} />

<main class="wrap" ondragend={endDrag}>
  <Card title="homepage" glow class="top">
    {#snippet right()}<Topbar {clock} uitloggen={!zonder || sessie} onlogout={logout} />{/snippet}
    <div class="body head">
      <div class="hello">
        <h1>{greeting}, {user.username}</h1>
        <p class="hint">
          {date}
          {#if zonder}{' · '}<button class="zl" onclick={() => dash.open('security', { tab: 'outside' })}
            title="Aanmelden staat uit (⚿ → van buitenaf): je bent {user.username}, zonder {sessie ? '2FA-code' : 'login of 2FA-code'}">zonder login</button>{/if}
          {#if summary.up + summary.down > 0}
            {' · '}<span class="ok">{summary.up} up</span>{#if summary.down}{' · '}<button class="down" onclick={() => (dash.problemsOnly = true)}
              title="Alleen de tegels met een probleem tonen, van alle pagina's">{summary.down} down</button>{/if}{#if summary.maint}{' · '}<span class="maint">{summary.maint} in onderhoud</span>{/if}{#if summary.paused}{' · '}<span class="maint">{summary.paused} gepauzeerd</span>{/if}
          {/if}
          {#if dash.lastOk}{' · '}<span class="upd" class:old={stale} title="Wanneer het dashboard de toestand laatst ophaalde">bijgewerkt {hm(dash.lastOk)}</span>{/if}<span class="cur"></span>
        </p>
      </div>
      <input
        class="search"
        type="search"
        placeholder="Zoeken...  (Ctrl+K of /)"
        aria-label="Zoeken"
        bind:value={query}
        bind:this={searchEl}
        onkeydown={searchKey}
        autocomplete="off"
      />
    </div>
    {#if dash.offline}
      <div class="offline" role="alert">
        <i></i>
        <span>Geen verbinding met de homepage sinds {hm(dash.offline)}{dash.offlineWhy ? ` (${dash.offlineWhy})` : ''}.
          {dash.lastOk ? `Wat je ziet is van ${hm(dash.lastOk)}.` : 'Er is nog niets geladen.'}</span>
        <button class="mini" onclick={() => dash.retry()}>opnieuw proberen</button>
      </div>
    {/if}
    <AttentionStrip />
    {#if !query.trim()}<PageView part="tabs" />{/if}
  </Card>

  {#if query.trim()}
    <SearchPanel bind:this={search} bind:query onlogs={openLogs} />
  {:else if dash.loaded && dash.pages.length === 0 && !dash.layoutError}
    <Card title="welkom" class="empty">
      <div class="body">
        <h3>Nog leeg</h3>
        <p class="hint">Begin met een pagina, of importeer meteen je <code>services.yaml</code> van homepage.dev.</p>
        <div class="row">
          <button class="btn" onclick={() => dash.open('import')}>Importeer services.yaml</button>
          <button class="btn alt" onclick={newPage}>Lege pagina</button>
        </div>
      </div>
    </Card>
  {:else}
    <PageView part="groups" />
  {/if}
</main>

<PageView part="forms" />
<WindowHost onnews={markNews} />
<OutsideDialog zonder={zonder && !sessie} onsettings={() => dash.open('security', { tab: 'outside' })} />
<ReauthDialog />

<style>
  /* Volle schermbreedte; op brede schermen komen er gewoon meer groepen naast elkaar. */
  .wrap { padding: min(4vh, 32px) clamp(14px, 2vw, 36px) 50px }
  /* De kopkaart boven de groepen houden: de menu's en de meldingen klappen eroverheen open
     (backdrop-filter maakt van elke kaart een eigen stapel). */
  .wrap > :global(.card:first-child) { z-index: 5 }
  .down { all: unset; cursor: pointer; color: var(--err); text-decoration: underline dotted; text-underline-offset: 3px }
  .down:hover, .down:focus-visible { color: #ffb0b0 }
  .zl { all: unset; cursor: pointer; color: var(--mid); text-decoration: underline dotted; text-underline-offset: 3px }
  .zl:hover, .zl:focus-visible { color: var(--text-h) }
  .maint { color: var(--mid) }
  .upd { color: var(--muted) }
  .upd.old { color: var(--mid) }
  .offline { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 0 24px 14px; padding: 8px 12px; border-radius: 9px;
             border: 1px solid rgba(229, 139, 139, .4); border-left: 3px solid var(--err); background: rgba(229, 139, 139, .08); font-size: 12.5px }
  .offline i { width: 7px; height: 7px; border-radius: 50%; background: var(--err); flex: none }
  .offline span { flex: 1; min-width: 200px }
  .head { display: flex; gap: 18px; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; padding-bottom: 12px }
  .hello .hint { margin: 6px 0 0 }
  .search { max-width: 340px }
  :global(.empty) { margin-top: 18px }
  @media (max-width: 560px) {
    .head { padding: 18px 16px 12px }
    .offline { margin: 0 16px 12px }
    .search { max-width: none }
  }
</style>
