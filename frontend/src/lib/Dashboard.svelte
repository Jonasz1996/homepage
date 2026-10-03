<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import Capacity from './Capacity.svelte'
  import Card from './Card.svelte'
  import History from './History.svelte'
  import ImportDialog from './ImportDialog.svelte'
  import NameForm from './NameForm.svelte'
  import Network from './Network.svelte'
  import Notifications from './Notifications.svelte'
  import ReauthDialog from './ReauthDialog.svelte'
  import Revisions from './Revisions.svelte'
  import Security from './Security.svelte'
  import ServiceForm from './ServiceForm.svelte'
  import ServiceDetail from './ServiceDetail.svelte'
  import ServiceTile from './ServiceTile.svelte'
  import Updates from './Updates.svelte'

  let { user, onlogout } = $props()

  let layout = $state({ pages: [] })
  let loaded = $state(false)
  let pageId = $state(readPref('page'))
  let editing = $state(false)
  let query = $state('')
  let modal = $state(null)
  let error = $state('')
  let now = $state(new Date())
  let searchEl = $state()
  let status = $state({})
  let widgets = $state({})
  let updates = $state({ total: 0, security: 0, by_service: {} })
  let net = $state(null)
  let menuOpen = $state(false)
  let termOpen = $state(false)
  let termUsed = $state(false)
  let termRequest = $state(null)
  let logsOpen = $state(false)
  let logsUsed = $state(false)
  let logsHost = $state(null)
  function openLogs(host = null) {
    logsUsed = true
    logsOpen = true
    logsHost = host
  }
  function openTerminal(hostId = null) {
    termUsed = true
    termOpen = true
    if (hostId) termRequest = { hostId }
  }

  // Slepen: wat er gesleept wordt en waar het zou landen.
  let drag = $state(null) // { kind: 'service' | 'group' | 'page', id }
  let over = $state(null) // service: { groupId, index } · group: { groupId } of { pageId } · page: { pageId }

  let page = $derived(layout.pages.find((p) => p.id === pageId) || layout.pages[0])
  let groupOptions = $derived(
    layout.pages.flatMap((p) => p.groups.map((g) => ({ id: g.id, label: `${p.name} / ${g.name}` })))
  )
  let allServices = $derived(layout.pages.flatMap((p) => p.groups.flatMap((g) => g.services)))
  let results = $derived.by(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    return layout.pages
      .flatMap((p) => p.groups.flatMap((g) => g.services))
      .filter((s) => [s.name, s.description, s.url, s.notes].some((v) => v && v.toLowerCase().includes(q)))
      .slice(0, 40)
  })

  // Snelle acties in de zoekbalk: commando's van het dashboard zelf en knoppen van de integraties.
  const COMMANDS = [
    { label: 'logs openen', run: () => openLogs() },
    { label: 'terminal openen', run: () => openTerminal() },
    { label: 'beveiliging: sessies en auditlog', run: () => (modal = { kind: 'security' }) },
    { label: 'capaciteit: opslag, cpu en ram', run: () => (modal = { kind: 'capacity' }) },
    { label: 'tijdlijn: storingen, herstarts, back-ups', run: () => (modal = { kind: 'history' }) },
    { label: 'weekrapport', run: () => (modal = { kind: 'history', tab: 'report' }) },
    { label: 'updates: openstaande pakketten en images', run: () => (modal = { kind: 'updates' }) },
    { label: 'netwerk: publiek ip, wan, tunnels, wake-on-lan', run: () => (modal = { kind: 'network' }) },
    { label: 'bewerken aan/uit', run: () => (editing = !editing) },
  ]
  let quick = $state([])
  let quickAt = 0
  let quickMsg = $state('')
  let quickBusy = $state(false)
  async function loadQuick() {
    if (Date.now() - quickAt < 60000) return
    quickAt = Date.now()
    try { quick = await api('/actions') } catch { quickAt = 0 }
  }
  $effect(() => { if (query.trim()) loadQuick(); else quickMsg = '' })
  let actionResults = $derived.by(() => {
    const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
    if (!words.length) return []
    const hit = (text) => words.every((w) => text.toLowerCase().includes(w))
    return [
      ...COMMANDS.filter((c) => hit(c.label)).map((c) => ({ ...c, kind: 'cmd' })),
      ...quick.filter((a) => hit(`${a.service} ${a.label} ${a.target || ''} ${a.id}`)).map((a) => ({ ...a, kind: 'act' })),
    ].slice(0, 8)
  })
  async function runQuick(a) {
    if (a.kind === 'cmd') {
      query = ''
      a.run()
      return
    }
    const what = `${a.label} ${a.target || ''}`.trim()
    if (a.confirm && !confirm(`${a.service}: ${what}?`)) return
    quickBusy = true
    try {
      const r = await withReauth(() => (a.endpoint
        ? api(a.endpoint, { method: 'POST' })
        : api(`/services/${a.service_id}/integration/action`, { method: 'POST', body: { action: a.id, params: a.params } })))
      quickMsg = `✓ ${a.service}: ${r.message}`
      quickAt = 0
      setTimeout(() => { loadWidgets(); if (query.trim()) loadQuick() }, 1500)
    } catch (e) {
      quickMsg = `✕ ${a.service}: ${e.message}`
    } finally {
      quickBusy = false
    }
  }
  let summary = $derived.by(() => {
    const all = Object.values(status)
    const active = all.filter((s) => !s.maintenance_until)
    return {
      up: active.filter((s) => s.status === 'up').length,
      down: active.filter((s) => s.status === 'down').length,
      maint: all.length - active.length,
    }
  })
  let greeting = $derived.by(() => {
    const h = now.getHours()
    return h < 6 ? 'Goedenacht' : h < 12 ? 'Goedemorgen' : h < 18 ? 'Goedemiddag' : 'Goedenavond'
  })
  let clock = $derived(now.toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' }))
  let date = $derived.by(() => {
    const d = now.toLocaleDateString('nl-BE', { weekday: 'long', day: 'numeric', month: 'long' })
    return d.charAt(0).toUpperCase() + d.slice(1)
  })

  function readPref(k) {
    try { return Number(localStorage.getItem('hp:' + k)) || null } catch { return null }
  }
  function writePref(k, v) {
    try { localStorage.setItem('hp:' + k, String(v)) } catch { /* privé-venster */ }
  }

  async function load() {
    try {
      layout = await api('/layout')
      error = ''
    } catch (e) {
      error = e.message
    } finally {
      loaded = true
    }
  }

  async function loadStatus() {
    try { status = await api('/status') } catch { /* volgende poging over 30 s */ }
  }
  async function groupMaintenance(g) {
    const v = prompt(`Hoeveel minuten onderhoud voor alle services in '${g.name}'? (0 = stoppen)`, '60')
    if (v === null) return
    await act(() => api(`/groups/${g.id}/maintenance`, { method: 'POST', body: { minutes: Math.max(0, parseInt(v, 10) || 0) } }))
    await loadStatus()
  }
  async function loadNet() {
    try { net = await api('/network') } catch { /* volgende poging */ }
  }
  // Rood als een WAN-gateway of tunnel niet in orde is, oranje bij problemen.
  let netLevel = $derived.by(() => {
    if (!net) return ''
    const gws = net.gateways.flatMap((g) => g.items.map((i) => i.level))
    const tus = net.tunnels.flatMap((t) => t.items.map((i) => i.status))
    if (gws.includes('err') || tus.some((x) => x === 'down' || x === 'inactive') || net.public_ip.error) return 'e'
    if (gws.includes('warn') || tus.includes('degraded')) return 'w'
    return gws.length || tus.length || net.public_ip.ip ? 'g' : ''
  })
  async function loadUpdates() {
    try { updates = await api('/updates') } catch { /* volgende poging */ }
  }
  function openNotification(n) {
    if (n.source === 'rapport') modal = { kind: 'history', tab: 'report' }
    else if (n.source === 'updates') modal = { kind: 'updates' }
    else if (n.service_id) {
      const s = allServices.find((x) => x.id === n.service_id)
      if (s) modal = { kind: 'detail', service: s }
    }
  }
  async function loadWidgets() {
    try { widgets = await api('/widgets') } catch { /* volgende poging over 60 s */ }
  }

  async function act(fn) {
    try {
      await fn()
    } catch (e) {
      error = e.message
    }
    await load()
  }

  function selectPage(p) {
    pageId = p.id
    writePref('page', p.id)
  }

  async function logout() {
    await api('/auth/logout', { method: 'POST' })
    onlogout()
  }

  // --- Pagina's en groepen -------------------------------------------------

  const savePage = (p) => async (data) => {
    if (p) await api(`/pages/${p.id}`, { method: 'PATCH', body: data })
    else selectPage({ id: (await api('/pages', { method: 'POST', body: data })).id })
    await load()
  }
  const deletePage = (p) => async () => {
    await api(`/pages/${p.id}`, { method: 'DELETE' })
    await load()
  }
  const saveGroup = (g) => async (data) => {
    const body = { ...data, page_id: g?.page_id ?? page.id, collapsed: g?.collapsed ?? false }
    if (g) await api(`/groups/${g.id}`, { method: 'PATCH', body })
    else await api('/groups', { method: 'POST', body })
    await load()
  }
  const deleteGroup = (g) => async () => {
    await api(`/groups/${g.id}`, { method: 'DELETE' })
    await load()
  }
  function toggleGroup(g) {
    g.collapsed = !g.collapsed
    act(() => api(`/groups/${g.id}`, {
      method: 'PATCH',
      body: { page_id: g.page_id, name: g.name, icon: g.icon, collapsed: g.collapsed },
    }))
  }

  // --- Slepen ---------------------------------------------------------------

  function startDrag(e, kind, id) {
    drag = { kind, id }
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', `${kind}:${id}`)
  }
  function endDrag() {
    drag = null
    over = null
  }
  function overService(e, groupId, index) {
    if (drag?.kind !== 'service') return
    e.preventDefault()
    e.stopPropagation()
    over = { groupId, index }
  }
  function overGroup(e, g) {
    if (drag?.kind === 'group') {
      e.preventDefault()
      over = { groupId: g.id }
    } else if (drag?.kind === 'service') {
      e.preventDefault()
      over = { groupId: g.id, index: g.services.length }
    }
  }
  function overTab(e, p) {
    if (drag?.kind === 'group' || drag?.kind === 'page') {
      e.preventDefault()
      over = { pageId: p.id }
    }
  }

  function findGroup(serviceId) {
    for (const p of layout.pages) for (const g of p.groups) if (g.services.some((s) => s.id === serviceId)) return g
  }

  async function drop(e) {
    e.preventDefault()
    const d = drag
    const o = over
    endDrag()
    if (!d || !o) return
    const body = {}
    if (d.kind === 'service' && o.groupId) {
      const src = findGroup(d.id)
      const dst = page.groups.find((g) => g.id === o.groupId)
      if (!src || !dst) return
      const from = src.services.findIndex((s) => s.id === d.id)
      let to = o.index
      if (src === dst && from < to) to--
      if (src === dst && from === to) return
      const [svc] = src.services.splice(from, 1)
      dst.services.splice(to, 0, svc)
      body.services = { [src.id]: src.services.map((s) => s.id), [dst.id]: dst.services.map((s) => s.id) }
    } else if (d.kind === 'group') {
      const srcPage = layout.pages.find((p) => p.groups.some((g) => g.id === d.id))
      const from = srcPage.groups.findIndex((g) => g.id === d.id)
      const [grp] = srcPage.groups.splice(from, 1)
      if (o.pageId) {
        const dstPage = layout.pages.find((p) => p.id === o.pageId)
        dstPage.groups.push(grp)
        body.groups = { [srcPage.id]: srcPage.groups.map((g) => g.id), [dstPage.id]: dstPage.groups.map((g) => g.id) }
      } else {
        const to = srcPage.groups.findIndex((g) => g.id === o.groupId)
        srcPage.groups.splice(to < 0 ? srcPage.groups.length : to, 0, grp)
        body.groups = { [srcPage.id]: srcPage.groups.map((g) => g.id) }
      }
    } else if (d.kind === 'page' && o.pageId && o.pageId !== d.id) {
      const from = layout.pages.findIndex((p) => p.id === d.id)
      const [pg] = layout.pages.splice(from, 1)
      layout.pages.splice(layout.pages.findIndex((p) => p.id === o.pageId), 0, pg)
      body.pages = layout.pages.map((p) => p.id)
    } else {
      return
    }
    await act(() => api('/layout/order', { method: 'PUT', body }))
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
    if (results[0]?.url) window.open(results[0].url, '_blank', 'noopener')
    else if (actionResults[0]) runQuick(actionResults[0])
  }

  // Snelkoppelingen van de app (manifest) en de Android-app: /?open=history, updates, network, ...
  function openFromUrl() {
    const q = new URLSearchParams(location.search)
    const what = q.get('open')
    if (!what) return
    history.replaceState(null, '', location.pathname)
    const kinds = { history: 'history', report: 'history', updates: 'updates', network: 'network', capacity: 'capacity',
                    security: 'security' }
    if (what === 'logs') openLogs()
    else if (what === 'terminal') openTerminal()
    else if (kinds[what]) modal = { kind: kinds[what], tab: what === 'report' ? 'report' : undefined }
  }

  onMount(() => {
    openFromUrl()
    load()
    loadStatus()
    loadWidgets()
    loadUpdates()
    loadNet()
    const stopNet = poll(loadNet, 120000)
    const stopWidgets = poll(loadWidgets, 60000)
    const stopUpdates = poll(loadUpdates, 300000)
    const stopClock = poll(() => (now = new Date()), 15000)
    const stopStatus = poll(loadStatus, 30000)
    return () => { stopClock(); stopStatus(); stopWidgets(); stopUpdates(); stopNet() }
  })
</script>

<svelte:window onkeydown={keydown} />

<main class="wrap" ondragend={endDrag}>
  <Card title="homepage" glow>
    {#snippet right()}
      <span class="clock">{clock}</span>
      <Notifications onopen={openNotification} />
      <button class="mini burger" class:on={menuOpen} onclick={() => (menuOpen = !menuOpen)} aria-label="Menu" aria-expanded={menuOpen}>☰</button>
      <!-- Op de gsm klapt dit open onder ☰; op een groot scherm staan de knoppen gewoon in de titelbalk. -->
      <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
      <span class="menu" class:open={menuOpen} onclick={() => (menuOpen = false)}>
        <button class="mini" onclick={() => openLogs()} title="Logs van je machines">logs</button>
        <button class="mini" onclick={() => openTerminal()} title="SSH-terminal">&gt;_<span class="ml">terminal</span></button>
        <button class="mini" onclick={() => (modal = { kind: 'capacity' })} title="Capaciteit: opslag, cpu en ram">df<span class="ml">capaciteit, stroom</span></button>
        <button class="mini" onclick={() => (modal = { kind: 'network' })} title="Internet: publiek IP, WAN, tunnels, Wake-on-LAN">net{#if netLevel}<i class="nd {netLevel}"></i>{/if}</button>
        <button class="mini" onclick={() => (modal = { kind: 'history' })} title="Tijdlijn en weekrapport">history</button>
        <button class="mini" class:upd={updates.security} onclick={() => (modal = { kind: 'updates' })}
                title="Openstaande updates">apt{#if updates.total}<b class="n">{updates.total}</b>{/if}</button>
        <button class="mini" onclick={() => (modal = { kind: 'security' })} title="Beveiliging: sessies, auditlog en wachtwoord">⚿<span class="ml">beveiliging</span></button>
        <button class="mini" class:on={editing} onclick={() => (editing = !editing)}>{editing ? '✓ klaar' : '✎ bewerken'}</button>
        <button class="mini x" onclick={logout} title="Uitloggen">⏻<span class="ml">uitloggen</span></button>
      </span>
    {/snippet}
    <div class="body head">
      <div class="hello">
        <h1>{greeting}, {user.username}</h1>
        <p class="hint">
          {date}
          {#if summary.up + summary.down > 0}
            {' · '}<span class="ok">{summary.up} up</span>{#if summary.down}{' · '}<span class="down">{summary.down} down</span>{/if}{#if summary.maint}{' · '}<span class="maint">{summary.maint} in onderhoud</span>{/if}
          {/if}<span class="cur"></span>
        </p>
      </div>
      <input
        class="search"
        type="search"
        placeholder="Zoeken...  (Ctrl+K of /)"
        bind:value={query}
        bind:this={searchEl}
        onkeydown={searchKey}
        autocomplete="off"
      />
    </div>
    {#if layout.pages.length > 0}
      <nav class="tabs">
        {#each layout.pages as p (p.id)}
          <button
            class="mini"
            class:on={page?.id === p.id}
            class:drop={over?.pageId === p.id}
            draggable={editing}
            ondragstart={(e) => startDrag(e, 'page', p.id)}
            ondragover={(e) => overTab(e, p)}
            ondrop={drop}
            onclick={() => selectPage(p)}
          >{p.name}</button>
        {/each}
        {#if editing}
          <button class="mini ok" onclick={() => (modal = { kind: 'page' })}>+ pagina</button>
        {/if}
      </nav>
    {/if}
    {#if editing}
      <div class="tools">
        {#if page}
          <button class="mini" onclick={() => (modal = { kind: 'group' })}>+ groep</button>
          <button class="mini" onclick={() => (modal = { kind: 'page', page })}>✎ pagina</button>
        {/if}
        <button class="mini" onclick={() => (modal = { kind: 'import' })}>import</button>
        <a class="mini" href="/api/export" download>export</a>
        <button class="mini" onclick={() => (modal = { kind: 'revisions' })}>versies</button>
        <span class="tip">Sleep tegels, groepen (aan ⠿) en tabbladen om ze te verplaatsen.</span>
      </div>
    {/if}
  </Card>

  {#if error}<p class="err banner">{error}</p>{/if}

  {#if query.trim()}
    <Card title={`grep -i "${query.trim()}"`} class="results">
      {#if actionResults.length || quickMsg}
        <div class="acts">
          {#each actionResults as a}
            <button class="act" class:danger={a.danger} disabled={quickBusy} onclick={() => runQuick(a)}>
              {#if a.kind === 'cmd'}<span class="src">dashboard</span>{a.label}
              {:else}<span class="src">{a.service}</span>{a.label} <b>{a.target || ''}</b>{/if}
            </button>
          {/each}
          {#if quickMsg}<span class="qmsg" class:bad={quickMsg.startsWith('✕')}>{quickMsg}</span>{/if}
        </div>
      {/if}
      <div class="tiles pad">
        {#each results as s (s.id)}
          <ServiceTile service={s} status={status[s.id]} widget={widgets[s.id]} updates={updates.by_service[s.id]} {editing} onedit={(svc) => (modal = { kind: 'service', service: svc })}
                       ondetail={(svc) => (modal = { kind: 'detail', service: svc })} />
        {:else}
          {#if !actionResults.length}<p class="hint">Niets gevonden.</p>{/if}
        {/each}
      </div>
    </Card>
  {:else if loaded && layout.pages.length === 0}
    <Card title="welkom" class="empty">
      <div class="body">
        <h3>Nog leeg</h3>
        <p class="hint">Begin met een pagina, of importeer meteen je <code>services.yaml</code> van homepage.dev.</p>
        <div class="row">
          <button class="btn" onclick={() => (modal = { kind: 'import' })}>Importeer services.yaml</button>
          <button class="btn alt" onclick={() => (modal = { kind: 'page' })}>Lege pagina</button>
        </div>
      </div>
    </Card>
  {:else if page}
    <div class="groups">
      {#each page.groups as g (g.id)}
        <div
          class="gwrap"
          class:dragging={drag?.kind === 'group' && drag.id === g.id}
          class:drop={drag?.kind === 'group' && over?.groupId === g.id}
          ondragover={(e) => overGroup(e, g)}
          ondrop={drop}
          role="list"
        >
          <Card prompt="~#" title={`ls ${g.name.toLowerCase()}/`}>
            {#snippet right()}
              {#if editing}
                <span class="handle" draggable="true" ondragstart={(e) => startDrag(e, 'group', g.id)} title="Sleep groep" role="button" tabindex="-1">⠿</span>
                <button class="mini" onclick={() => (modal = { kind: 'service', service: null, groupId: g.id })}>+</button>
                <button class="mini" onclick={() => (modal = { kind: 'group', group: g })}>✎</button>
              {/if}
              {#if editing}
                <button class="mini" onclick={() => groupMaintenance(g)} title="Onderhoud voor de hele groep">⏸</button>
              {/if}
              <button class="mini fold" onclick={() => toggleGroup(g)} aria-label={g.collapsed ? 'Openklappen' : 'Dichtklappen'}>
                {g.collapsed ? '▸' : '▾'} {g.services.length}
              </button>
            {/snippet}
            {#if !g.collapsed || (drag?.kind === 'service')}
              <div class="tiles pad">
                {#each g.services as s, i (s.id)}
                  <ServiceTile
                    service={s}
                    status={status[s.id]}
                    widget={widgets[s.id]}
                    updates={updates.by_service[s.id]}
                    {editing}
                    onedit={(svc) => (modal = { kind: 'service', service: svc })}
                    ondetail={(svc) => (modal = { kind: 'detail', service: svc })}
                    dragging={drag?.kind === 'service' && drag.id === s.id}
                    dropBefore={over?.groupId === g.id && over.index === i && drag?.kind === 'service'}
                    ondragstart={(e) => startDrag(e, 'service', s.id)}
                    ondragover={(e) => overService(e, g.id, i)}
                    ondrop={drop}
                  />
                {/each}
                {#if editing}
                  <button
                    class="add"
                    class:drop={over?.groupId === g.id && over.index === g.services.length && drag?.kind === 'service'}
                    onclick={() => (modal = { kind: 'service', service: null, groupId: g.id })}
                  >+ service</button>
                {:else if g.services.length === 0}
                  <p class="hint none">Leeg</p>
                {/if}
              </div>
            {/if}
          </Card>
        </div>
      {:else}
        <p class="hint">Deze pagina heeft nog geen groepen. Zet <b>bewerken</b> aan om er een toe te voegen.</p>
      {/each}
    </div>
  {/if}
</main>

{#if modal?.kind === 'service'}
  <ServiceForm
    service={modal.service}
    groupId={modal.groupId}
    groups={groupOptions}
    services={allServices}
    onclose={() => (modal = null)}
    onsaved={() => { load(); setTimeout(loadWidgets, 300) }}
  />
{:else if modal?.kind === 'page'}
  <NameForm
    title={modal.page ? `edit ${modal.page.name}` : 'page --new'}
    initial={modal.page}
    onsave={savePage(modal.page)}
    ondelete={modal.page ? deletePage(modal.page) : null}
    onclose={() => (modal = null)}
  />
{:else if modal?.kind === 'group'}
  <NameForm
    title={modal.group ? `edit ${modal.group.name}` : 'group --new'}
    initial={modal.group}
    onsave={saveGroup(modal.group)}
    ondelete={modal.group ? deleteGroup(modal.group) : null}
    onclose={() => (modal = null)}
  />
{:else if modal?.kind === 'detail'}
  <ServiceDetail
    service={modal.service}
    groups={groupOptions}
    onchanged={load}
    onterminal={(hostId) => { modal = null; openTerminal(hostId) }}
    onclose={() => (modal = null)}
    onedit={(svc) => (modal = { kind: 'service', service: svc })}
  />
{:else if modal?.kind === 'import'}
  <ImportDialog pages={layout.pages} onclose={() => (modal = null)} ondone={load} />
{:else if modal?.kind === 'capacity'}
  <Capacity onclose={() => (modal = null)} />
{:else if modal?.kind === 'history'}
  <History tab={modal.tab} onclose={() => (modal = null)} />
{:else if modal?.kind === 'network'}
  <Network onclose={() => (modal = null)} onchanged={(d) => (net = d)} />
{:else if modal?.kind === 'updates'}
  <Updates onclose={() => (modal = null)} onchanged={loadUpdates} />
{:else if modal?.kind === 'security'}
  <Security onclose={() => (modal = null)} />
{:else if modal?.kind === 'revisions'}
  <Revisions onclose={() => (modal = null)} ondone={load} />
{/if}

{#if termUsed}
  <!-- xterm.js is groot: pas laden als je de terminal voor het eerst opent. -->
  {#await import('./Terminal.svelte') then { default: Terminal }}
    <Terminal open={termOpen} request={termRequest} services={allServices} onclose={() => (termOpen = false)} />
  {/await}
{/if}
{#if logsUsed}
  {#await import('./Logs.svelte') then { default: Logs }}
    <Logs open={logsOpen} initialHost={logsHost} onclose={() => (logsOpen = false)} />
  {/await}
{/if}
<ReauthDialog />

<style>
  .wrap { max-width: 1240px; margin: 0 auto; padding: min(4vh, 32px) 14px 50px }
  .clock { color: var(--text); margin-right: 4px }
  .n { margin-left: 5px; color: var(--text-h); font-size: 11px; font-weight: 500 }
  .upd .n { color: var(--mid) }
  .menu { display: contents }
  /* De kopkaart boven de groepen houden: het menu en de meldingen klappen eroverheen open
     (backdrop-filter maakt van elke kaart een eigen stapel). */
  .wrap > :global(.card:first-child) { z-index: 5 }
  .burger { display: none }
  .ml { display: none }
  .nd { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin: 0 0 1px 6px; vertical-align: middle }
  .nd.g { background: var(--ok) }
  .nd.w { background: var(--mid) }
  .nd.e { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .down { color: var(--err) }
  .maint { color: var(--mid) }
  .head { display: flex; gap: 18px; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; padding-bottom: 12px }
  .hello .hint { margin: 6px 0 0 }
  .search { max-width: 340px }
  .tabs { display: flex; gap: 6px; flex-wrap: wrap; padding: 0 24px 16px }
  .tabs .drop { outline: 2px dashed var(--ok) }
  .tools { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; padding: 12px 24px; border-top: 1px solid var(--line) }
  .tools a { text-decoration: none }
  .tip { color: var(--dim); font-size: 11.5px; margin-left: 6px }
  .banner { margin: 14px 4px 0 }
  .groups {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 380px), 1fr));
    gap: 18px; align-items: start; margin-top: 18px
  }
  .gwrap { border-radius: var(--radius); transition: opacity .2s }
  .gwrap.dragging { opacity: .35 }
  .gwrap.drop { box-shadow: -4px 0 0 0 var(--ok) }
  .handle { cursor: grab; color: var(--muted); padding: 0 4px; user-select: none }
  .fold { color: var(--muted); padding: 3px 8px }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(165px, 1fr)); gap: 8px }
  .pad { padding: 12px }
  .add {
    min-height: 58px; border-radius: 10px; border: 1px dashed var(--line-2); background: none; color: var(--muted);
    cursor: pointer; font-size: 12.5px
  }
  .add:hover { color: var(--text-h); border-color: var(--btn-h) }
  .add.drop { border-color: var(--ok); color: var(--ok) }
  .none { margin: 0; padding: 6px }
  :global(.results), :global(.empty) { margin-top: 18px }
  .acts { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 12px 12px 0 }
  .act { display: inline-flex; gap: 8px; align-items: baseline; padding: 6px 10px; border-radius: 9px; cursor: pointer;
         background: var(--fill); border: 1px solid var(--line-2); color: var(--text); font-size: 12.5px }
  .act:hover { background: var(--fill-h); color: #fff }
  .act.danger:hover { border-color: var(--err); color: var(--err) }
  .act:disabled { opacity: .5; cursor: progress }
  .act .src { color: var(--muted); font-size: 11px }
  .act b { font-weight: 500; color: var(--text-h) }
  .qmsg { font-size: 12px; color: var(--ok); margin-left: 4px }
  .qmsg.bad { color: var(--err) }
  @media (max-width: 760px) {
    .burger { display: inline-block; padding: 3px 9px }
    .menu { display: none }
    .menu.open {
      display: grid; grid-template-columns: 1fr 1fr; gap: 6px; position: fixed; z-index: 70;
      top: calc(62px + env(safe-area-inset-top)); right: 12px; width: min(300px, calc(100vw - 24px)); padding: 10px;
      background: rgba(18, 18, 18, .97); border: 1px solid var(--line-2); border-radius: 12px;
      box-shadow: 0 12px 40px rgba(0, 0, 0, .6)
    }
    .menu.open :global(.mini) { padding: 9px 10px; text-align: left; font-size: 13px }
    .menu.open .ml { display: inline; margin-left: 7px; color: var(--muted); font-size: 12px }
  }
  @media (max-width: 560px) {
    .tiles { grid-template-columns: repeat(auto-fill, minmax(138px, 1fr)) }
    .groups { gap: 12px; margin-top: 12px }
    .head { padding: 18px 16px 12px }
    .tabs, .tools { padding-left: 16px; padding-right: 16px }
    .search { max-width: none }
    .clock { display: none }
  }
</style>
