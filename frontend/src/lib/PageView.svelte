<script module>
  import { api, withReauth } from './api.js'
  import { dash } from './dash.svelte.js'
  import { askText } from './dialog.svelte.js'
  import { boom } from './fx.js'

  // De tabbladen (pagina's) met hun groepen en tegels: slepen in de bewerkmodus, dichtklappen per toestel, en een
  // bolletje per tabblad en groep zodat je een tegel die down is ook ziet als hij op een ander tabblad of in een
  // dichtgeklapte groep staat. De tabbladen staan in de kopkaart, de groepen eronder: twee keer dit onderdeel
  // (part = 'tabs' en 'groups'), met één gedeelde toestand.
  function readNum(k) {
    try { return Number(localStorage.getItem('hp:' + k)) || null } catch { return null }
  }
  function write(k, v) {
    try { localStorage.setItem('hp:' + k, v) } catch { /* privé-venster */ }
  }
  function readFolds() {
    try { return JSON.parse(localStorage.getItem('hp:fold') || '{}') || {} } catch { return {} }
  }

  // down: rood; twijfel, check loopt niet meer of Zabbix rood: oranje. Onderhoud en pauze tellen niet.
  function problem(s) {
    const st = dash.status[s.id]
    if (st?.maintenance_until) return null
    const zb = dash.zbx[s.id]?.level === 'err'
    if (!st || st.paused || s.check?.paused) return zb ? 'warn' : null
    if (st.status === 'down') return 'err'
    if (st.stale || (st.status === 'up' && st.fail_count > 0) || zb) return 'warn'
    return null
  }
  function count(services) {
    let err = 0, warn = 0
    for (const s of services) {
      const p = problem(s)
      if (p === 'err') err++
      else if (p === 'warn') warn++
    }
    return { err, warn }
  }
  const label = (c) => [c.err && `${c.err} down`, c.warn && `${c.warn} twijfel`].filter(Boolean).join(', ')

  class View {
    pageId = $state(readNum('page'))
    form = $state(null) // { kind: 'page' | 'group', page?, group? }
    error = $state('')
    drag = $state(null) // { kind: 'service' | 'group' | 'page', id }
    over = $state(null) // service: { groupId, index } · group: { groupId } of { pageId } · page: { pageId }
    // Dichtklappen per toestel: wat de server zegt (bij het aanmaken gekozen) geldt tot je op dit toestel zelf klapt.
    folds = $state(readFolds())

    page = $derived(dash.pages.find((p) => p.id === this.pageId) || dash.pages[0])
    pageCounts = $derived(Object.fromEntries(dash.pages.map((p) => [p.id, count(p.groups.flatMap((g) => g.services))])))
    problemGroups = $derived(dash.pages.flatMap((p) => p.groups
      .map((g) => ({ page: p, group: g, services: g.services.filter((s) => problem(s)) }))
      .filter((x) => x.services.length)))
    problemCount = $derived(this.problemGroups.reduce((a, x) => a + x.services.length, 0))
  }
  const v = new View()

  /** Een nieuwe pagina (ook vanuit het lege dashboard). */
  export function newPage() {
    v.form = { kind: 'page' }
  }

  /** Slepen voorbij: ook als je buiten een groep loslaat. */
  export function endDrag() {
    v.drag = null
    v.over = null
  }

  function selectPage(p) {
    v.pageId = p.id
    write('page', String(p.id))
  }
  const folded = (g) => v.folds[g.id] ?? !!g.collapsed
  function toggleGroup(g) {
    v.folds = { ...v.folds, [g.id]: !folded(g) }
    write('fold', JSON.stringify(v.folds))
  }

  async function act(fn) {
    v.error = ''
    try {
      await fn()
    } catch (e) {
      // Blijft staan tot de volgende actie of tot je het wegklikt: het herladen hieronder wist het niet meer.
      v.error = e.message
    }
    await dash.loadLayout()
  }

  const savePage = (p) => async (data) => {
    if (p) await api(`/pages/${p.id}`, { method: 'PATCH', body: data })
    else selectPage({ id: (await api('/pages', { method: 'POST', body: data })).id })
    await dash.loadLayout()
  }
  // Met lopende checks erin vraagt verwijderen een recente 2FA (zoals pauzeren).
  const deletePage = (p) => async () => {
    await withReauth(() => api(`/pages/${p.id}`, { method: 'DELETE' }))
    boom(undefined, 1.6)
    await dash.loadLayout()
  }
  const saveGroup = (g) => async (data) => {
    const body = { ...data, page_id: g?.page_id ?? v.page.id, collapsed: g?.collapsed ?? false }
    if (g) await api(`/groups/${g.id}`, { method: 'PATCH', body })
    else await api('/groups', { method: 'POST', body })
    await dash.loadLayout()
  }
  const deleteGroup = (g) => async () => {
    await withReauth(() => api(`/groups/${g.id}`, { method: 'DELETE' }))
    boom(undefined, 1.4)
    await dash.loadLayout()
  }
  async function groupMaintenance(g) {
    const val = await askText(`Hoeveel minuten onderhoud voor alle services in '${g.name}'? (0 = stoppen)`,
                              { value: '60', inputmode: 'numeric', ok: 'Onderhoud' })
    if (val === null) return
    // Beginnen of verlengen vraagt je 2FA (onderhoud zet de meldingen uit), stoppen niet.
    await act(() => withReauth(() => api(`/groups/${g.id}/maintenance`, { method: 'POST', body: { minutes: Math.max(0, parseInt(val, 10) || 0) } })))
    await dash.refresh(['status'])
  }

  // --- Slepen ----------------------------------------------------------------------

  function startDrag(e, kind, id) {
    v.drag = { kind, id }
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', `${kind}:${id}`)
  }
  function overService(e, groupId, index) {
    if (v.drag?.kind !== 'service') return
    e.preventDefault()
    e.stopPropagation()
    v.over = { groupId, index }
  }
  function overGroup(e, g) {
    if (v.drag?.kind === 'group') {
      e.preventDefault()
      v.over = { groupId: g.id }
    } else if (v.drag?.kind === 'service') {
      e.preventDefault()
      v.over = { groupId: g.id, index: g.services.length }
    }
  }
  function overTab(e, p) {
    if (v.drag?.kind === 'group' || v.drag?.kind === 'page') {
      e.preventDefault()
      v.over = { pageId: p.id }
    }
  }
  function findGroup(serviceId) {
    for (const p of dash.pages) for (const g of p.groups) if (g.services.some((s) => s.id === serviceId)) return g
  }

  async function drop(e) {
    e.preventDefault()
    const d = v.drag
    const o = v.over
    endDrag()
    if (!d || !o) return
    const pages = dash.layout.pages
    const body = {}
    if (d.kind === 'service' && o.groupId) {
      const src = findGroup(d.id)
      const dst = v.page.groups.find((g) => g.id === o.groupId)
      if (!src || !dst) return
      const from = src.services.findIndex((s) => s.id === d.id)
      let to = o.index
      if (src === dst && from < to) to--
      if (src === dst && from === to) return
      const [svc] = src.services.splice(from, 1)
      dst.services.splice(to, 0, svc)
      body.services = { [src.id]: src.services.map((s) => s.id), [dst.id]: dst.services.map((s) => s.id) }
    } else if (d.kind === 'group') {
      const srcPage = pages.find((p) => p.groups.some((g) => g.id === d.id))
      const from = srcPage.groups.findIndex((g) => g.id === d.id)
      const [grp] = srcPage.groups.splice(from, 1)
      if (o.pageId) {
        const dstPage = pages.find((p) => p.id === o.pageId)
        dstPage.groups.push(grp)
        body.groups = { [srcPage.id]: srcPage.groups.map((g) => g.id), [dstPage.id]: dstPage.groups.map((g) => g.id) }
      } else {
        const to = srcPage.groups.findIndex((g) => g.id === o.groupId)
        srcPage.groups.splice(to < 0 ? srcPage.groups.length : to, 0, grp)
        body.groups = { [srcPage.id]: srcPage.groups.map((g) => g.id) }
      }
    } else if (d.kind === 'page' && o.pageId && o.pageId !== d.id) {
      const from = pages.findIndex((p) => p.id === d.id)
      const [pg] = pages.splice(from, 1)
      pages.splice(pages.findIndex((p) => p.id === o.pageId), 0, pg)
      body.pages = pages.map((p) => p.id)
    } else {
      return
    }
    // Een tegel naar een groep slepen met gepland onderhoud (nu of later), legt zijn check (of wat eronder hangt)
    // stil: dat vraagt je 2FA.
    await act(() => withReauth(() => api('/layout/order', { method: 'PUT', body })))
  }

  const tile = (s) => ({
    service: s, status: dash.status[s.id], widget: dash.widgets[s.id], updates: dash.updates.by_service[s.id],
    zbx: dash.zbx[s.id], editing: dash.editing,
    onedit: (svc) => dash.open('service', { service: svc }),
    ondetail: (svc) => dash.open('detail', { service: svc }),
  })
</script>

<script>
  import Card from './Card.svelte'
  import NameForm from './NameForm.svelte'
  import ServiceTile from './ServiceTile.svelte'

  let { part } = $props()
  let page = $derived(v.page)
  let drag = $derived(v.drag)
  let over = $derived(v.over)
</script>

{#snippet chip(c)}
  {#if c.err || c.warn}<span class="chip" class:e={c.err} title={label(c)}><i></i>{c.err || c.warn}</span>{/if}
{/snippet}

{#if part === 'tabs' && dash.pages.length > 0}
  <nav class="tabs" aria-label="Pagina's">
    {#each dash.pages as p (p.id)}
      <button
        class="mini"
        class:on={!dash.problemsOnly && page?.id === p.id}
        class:drop={over?.pageId === p.id}
        draggable={dash.editing}
        ondragstart={(e) => startDrag(e, 'page', p.id)}
        ondragover={(e) => overTab(e, p)}
        ondrop={drop}
        onclick={() => { dash.problemsOnly = false; selectPage(p) }}
        title={label(v.pageCounts[p.id]) || undefined}
      >{p.name}{@render chip(v.pageCounts[p.id])}</button>
    {/each}
    {#if dash.editing}
      <button class="mini ok" onclick={() => (v.form = { kind: 'page' })}>+ pagina</button>
    {/if}
    <span class="sp"></span>
    <button class="mini prob" class:on={dash.problemsOnly} class:e={v.problemCount} onclick={() => (dash.problemsOnly = !dash.problemsOnly)}
            aria-pressed={dash.problemsOnly} title="Alleen de tegels die down zijn, twijfelen of niet meer gecheckt worden, van alle pagina's">
      alleen problemen{#if v.problemCount}<b>{v.problemCount}</b>{/if}</button>
  </nav>
{/if}
{#if part === 'tabs' && dash.editing}
  <div class="tools">
    {#if page}
      <button class="mini" onclick={() => (v.form = { kind: 'group' })}>+ groep</button>
      <button class="mini" onclick={() => (v.form = { kind: 'page', page })}>✎ pagina</button>
    {/if}
    <button class="mini" onclick={() => dash.open('import')}>import</button>
    <a class="mini" href="/api/export" download>export</a>
    <button class="mini" onclick={() => dash.open('revisions')}>versies</button>
    <span class="tip">Sleep tegels, groepen (aan ⠿) en tabbladen om ze te verplaatsen.</span>
  </div>
{/if}
{#if part === 'groups'}
{#if v.error}<p class="err banner">{v.error} <button class="mini x" onclick={() => (v.error = '')} aria-label="Melding sluiten">✕</button></p>{/if}
{#if dash.layoutError}<p class="err banner">{dash.layoutError}</p>{/if}

{#if dash.problemsOnly}
  <div class="groups">
    {#each v.problemGroups as x (x.group.id)}
      <Card prompt="~#" title={`ls ${x.page.name.toLowerCase()}/${x.group.name.toLowerCase()}/`}>
        <div class="tiles pad">
          {#each x.services as s (s.id)}<ServiceTile {...tile(s)} />{/each}
        </div>
      </Card>
    {:else}
      <p class="hint">Geen problemen: elke tegel met een check is bereikbaar.</p>
    {/each}
  </div>
{:else if page}
  <div class="groups">
    {#each page.groups as g (g.id)}
      {@const c = count(g.services)}
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
            {#if dash.editing}
              <span class="handle" draggable="true" ondragstart={(e) => startDrag(e, 'group', g.id)} title="Sleep groep" role="button" tabindex="-1">⠿</span>
              <button class="mini" onclick={() => dash.open('service', { service: null, groupId: g.id })} aria-label="Service toevoegen aan {g.name}">+</button>
              <button class="mini" onclick={() => (v.form = { kind: 'group', group: g })} aria-label="Groep {g.name} bewerken">✎</button>
              <button class="mini" onclick={() => groupMaintenance(g)} title="Onderhoud voor de hele groep" aria-label="Onderhoud voor groep {g.name}">⏸</button>
            {/if}
            {#if folded(g) && (c.err || c.warn)}
              <button class="chipb" onclick={() => toggleGroup(g)} title="{label(c)}: openklappen">{@render chip(c)}</button>
            {/if}
            <button class="mini fold" onclick={() => toggleGroup(g)} aria-label={folded(g) ? 'Openklappen' : 'Dichtklappen'}>
              {folded(g) ? '▸' : '▾'} {g.services.length}
            </button>
          {/snippet}
          {#if !folded(g) || (drag?.kind === 'service')}
            <div class="tiles pad">
              {#each g.services as s, i (s.id)}
                <ServiceTile
                  {...tile(s)}
                  dragging={drag?.kind === 'service' && drag.id === s.id}
                  dropBefore={over?.groupId === g.id && over.index === i && drag?.kind === 'service'}
                  ondragstart={(e) => startDrag(e, 'service', s.id)}
                  ondragover={(e) => overService(e, g.id, i)}
                  ondrop={drop}
                />
              {/each}
              {#if dash.editing}
                <button
                  class="add"
                  class:drop={over?.groupId === g.id && over.index === g.services.length && drag?.kind === 'service'}
                  onclick={() => dash.open('service', { service: null, groupId: g.id })}
                >+ service</button>
              {:else if g.services.length === 0}
                <p class="hint none">Leeg</p>
              {/if}
            </div>
          {/if}
        </Card>
      </div>
    {:else}
      <p class="hint">Deze pagina heeft nog geen groepen. Zet <b>Beheer → Dashboard bewerken</b> aan om er een toe te voegen.</p>
    {/each}
  </div>
{/if}

{/if}

{#if part === 'forms' && v.form?.kind === 'page'}
  <NameForm
    title={v.form.page ? `edit ${v.form.page.name}` : 'page --new'}
    initial={v.form.page}
    onsave={savePage(v.form.page)}
    ondelete={v.form.page ? deletePage(v.form.page) : null}
    onclose={() => (v.form = null)}
  />
{:else if part === 'forms' && v.form?.kind === 'group'}
  <NameForm
    title={v.form.group ? `edit ${v.form.group.name}` : 'group --new'}
    initial={v.form.group}
    onsave={saveGroup(v.form.group)}
    ondelete={v.form.group ? deleteGroup(v.form.group) : null}
    onclose={() => (v.form = null)}
  />
{/if}

<style>
  .tabs { display: flex; gap: 6px; flex-wrap: wrap; padding: 0 24px 16px; align-items: center }
  .tabs .drop { outline: 2px dashed var(--ok) }
  .sp { flex: 1 }
  .prob b { margin-left: 6px; color: var(--mid); font-weight: 500 }
  .prob.e b { color: var(--err) }
  .chip { display: inline-flex; align-items: center; gap: 4px; margin-left: 7px; font-size: 11px; color: var(--mid) }
  .chip i { width: 7px; height: 7px; border-radius: 50%; background: var(--mid) }
  .chip.e { color: var(--err) }
  .chip.e i { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .chipb { all: unset; cursor: pointer; padding: 2px 4px; border-radius: 6px }
  .chipb:hover, .chipb:focus-visible { background: var(--fill-h) }
  .tools { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; padding: 12px 24px; border-top: 1px solid var(--line) }
  .tools a { text-decoration: none }
  .tip { color: var(--muted); font-size: 12px; margin-left: 6px }
  .banner { margin: 14px 4px 0; display: flex; gap: 10px; align-items: center }
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
  @media (max-width: 560px) {
    .tiles { grid-template-columns: repeat(auto-fill, minmax(138px, 1fr)) }
    .groups { gap: 12px; margin-top: 12px }
    .tabs, .tools { padding-left: 16px; padding-right: 16px }
  }
</style>
