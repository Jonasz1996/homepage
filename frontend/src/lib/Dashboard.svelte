<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import Card from './Card.svelte'
  import ImportDialog from './ImportDialog.svelte'
  import NameForm from './NameForm.svelte'
  import Notifications from './Notifications.svelte'
  import Revisions from './Revisions.svelte'
  import ServiceForm from './ServiceForm.svelte'
  import ServiceTile from './ServiceTile.svelte'

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

  // Slepen: wat er gesleept wordt en waar het zou landen.
  let drag = $state(null) // { kind: 'service' | 'group' | 'page', id }
  let over = $state(null) // service: { groupId, index } · group: { groupId } of { pageId } · page: { pageId }

  let page = $derived(layout.pages.find((p) => p.id === pageId) || layout.pages[0])
  let groupOptions = $derived(
    layout.pages.flatMap((p) => p.groups.map((g) => ({ id: g.id, label: `${p.name} / ${g.name}` })))
  )
  let results = $derived.by(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    return layout.pages
      .flatMap((p) => p.groups.flatMap((g) => g.services))
      .filter((s) => [s.name, s.description, s.url].some((v) => v && v.toLowerCase().includes(q)))
      .slice(0, 40)
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
    if (e.key === 'Enter' && results[0]?.url) window.open(results[0].url, '_blank', 'noopener')
  }

  onMount(() => {
    load()
    const t = setInterval(() => (now = new Date()), 15000)
    return () => clearInterval(t)
  })
</script>

<svelte:window onkeydown={keydown} />

<main class="wrap" ondragend={endDrag}>
  <Card title="homepage" glow>
    {#snippet right()}
      <span class="clock">{clock}</span>
      <Notifications />
      <button class="mini" class:on={editing} onclick={() => (editing = !editing)}>{editing ? '✓ klaar' : '✎ bewerken'}</button>
      <button class="mini x" onclick={logout} title="Uitloggen">⏻</button>
    {/snippet}
    <div class="body head">
      <div class="hello">
        <h1>{greeting}, {user.username}</h1>
        <p class="hint">{date}<span class="cur"></span></p>
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
      <div class="tiles pad">
        {#each results as s (s.id)}
          <ServiceTile service={s} {editing} onedit={(svc) => (modal = { kind: 'service', service: svc })} />
        {:else}
          <p class="hint">Niets gevonden.</p>
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
              <button class="mini fold" onclick={() => toggleGroup(g)} aria-label={g.collapsed ? 'Openklappen' : 'Dichtklappen'}>
                {g.collapsed ? '▸' : '▾'} {g.services.length}
              </button>
            {/snippet}
            {#if !g.collapsed || (drag?.kind === 'service')}
              <div class="tiles pad">
                {#each g.services as s, i (s.id)}
                  <ServiceTile
                    service={s}
                    {editing}
                    onedit={(svc) => (modal = { kind: 'service', service: svc })}
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
    onclose={() => (modal = null)}
    onsaved={load}
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
{:else if modal?.kind === 'import'}
  <ImportDialog pages={layout.pages} onclose={() => (modal = null)} ondone={load} />
{:else if modal?.kind === 'revisions'}
  <Revisions onclose={() => (modal = null)} ondone={load} />
{/if}

<style>
  .wrap { max-width: 1240px; margin: 0 auto; padding: min(4vh, 32px) 14px 50px }
  .clock { color: var(--text); margin-right: 4px }
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
  @media (max-width: 560px) {
    .head { padding: 18px 16px 12px }
    .tabs, .tools { padding-left: 16px; padding-right: 16px }
    .search { max-width: none }
    .clock { display: none }
  }
</style>
