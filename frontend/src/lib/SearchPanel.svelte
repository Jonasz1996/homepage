<script>
  import { api, withReauth } from './api.js'
  import { dash } from './dash.svelte.js'
  import { ask } from './dialog.svelte.js'
  import { flash, RED, storm } from './fx.js'
  import { WINDOWS } from './windows.js'
  import Card from './Card.svelte'
  import ServiceTile from './ServiceTile.svelte'

  // Ctrl+K: tegels, snelle acties, vensters van het dashboard, en alles wat de server vindt (notities, cronjobs,
  // SSH-hosts, apparaten, configuratie, logregels, IP/MAC).
  let { query = $bindable(''), onlogs } = $props()

  let results = $derived.by(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    return dash.services
      .filter((s) => found.service_ids.includes(s.id) || [s.name, s.description, s.url, s.notes].some((v) => v && v.toLowerCase().includes(q)))
      .slice(0, 40)
  })

  const NONE = { groups: [], service_ids: [] }
  let found = $state.raw(NONE)
  let searchGen = 0
  let searchTimer
  $effect(() => {
    const q = query.trim()
    clearTimeout(searchTimer)
    const my = ++searchGen
    if (q.length < 2) { found = NONE; return }
    searchTimer = setTimeout(async () => {
      try {
        const r = await api(`/search?q=${encodeURIComponent(q)}`)
        if (my === searchGen) found = r
      } catch { /* de zoekbalk werkt verder op wat het dashboard zelf weet */ }
    }, 250)
  })
  let foundGroups = $derived(query.trim().length >= 2 ? found.groups : [])

  function openFound(kind, it) {
    const k = it.kind || kind
    if (k === 'note') {
      const svc = dash.services.find((s) => s.id === it.service_id)
      if (svc) dash.open('detail', { service: svc })
    } else if (k === 'cron') dash.open('cron', { job: it.job_id })
    else if (k === 'host') dash.open('terminal', { hostId: it.host_id })
    else if (k === 'device') dash.open('network', { tab: 'apparaten', q: it.mac })
    else if (k === 'config') dash.open('configs', { item: it.item })
    else if (k === 'log') onlogs(it.host, found.ip || found.mac || query.trim())
    else if (k === 'npm' && it.url) window.open(it.url, '_blank', 'noopener')
  }

  // Commando's van het dashboard zelf: elk venster (met zijn oude korte naam, zodat "hw" of "df" nog werkt) en een
  // paar tabbladen die je vaak zoekt.
  const COMMANDS = [
    { label: 'aandacht: alles wat nu mis is', run: () => dash.open('attention') },
    { label: 'meldingen: gebeurtenissen (de bel)', run: () => dash.open('notifications') },
    ...WINDOWS.filter((w) => w.menu).map((w) => ({
      label: `${w.label.toLowerCase()}${w.code ? ` (${w.code})` : ''}: ${w.hint.toLowerCase()}`,
      run: () => dash.open(w.id, w.id === 'logs' ? { keep: true } : {}),
    })),
    { label: 'van buitenaf: wat mag er via cloudflare (terminal, updates, acties)', run: () => dash.open('security', { tab: 'outside' }) },
    { label: 'veiligheidscheck: 2fa, tokens, sessies, ssh-sleutel', run: () => dash.open('health', { tab: 'beveiliging' }) },
    { label: 'firewall: welke poorten het dashboard gebruikt', run: () => dash.open('network', { tab: 'firewall' }) },
    { label: 'publiek: welke namen van buitenaf bereikbaar zijn, met of zonder login', run: () => dash.open('network', { tab: 'publiek' }) },
    { label: 'weekrapport', run: () => dash.open('history', { tab: 'report' }) },
    { label: 'apparaten op het netwerk, poortscan', run: () => dash.open('network', { tab: 'apparaten' }) },
    { label: 'netwerkkaart: wat valt er mee uit', run: () => dash.open('network', { tab: 'kaart' }) },
    { label: 'cluster: quorum, versies, qdevice, ha, replicatie', run: () => dash.open('health', { tab: 'cluster' }) },
    { label: "back-updekking: welke vm/ct op hoeveel pbs'en, pbs-sync", run: () => dash.open('health', { tab: 'backups' }) },
    { label: 'bewerken aan/uit', run: () => (dash.editing = !dash.editing) },
    { label: 'alleen problemen: tegels die down zijn of twijfelen', run: () => (dash.problemsOnly = !dash.problemsOnly) },
    { label: 'effecten aan/uit (achtergrond, gloed, vuur, bliksem, ...)', run: () => { dash.setFx(!dash.fx); if (dash.fx) storm() } },
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
    if (a.confirm && !(await ask(`${a.service}: ${what}?`, { ok: 'Uitvoeren', danger: !!a.danger }))) return
    quickBusy = true
    try {
      const r = await withReauth(() => (a.endpoint
        ? api(a.endpoint, { method: 'POST' })
        : api(`/services/${a.service_id}/integration/action`, { method: 'POST', body: { action: a.id, params: a.params } })))
      quickMsg = `✓ ${a.service}: ${r.message}`
      storm()
      quickAt = 0
      setTimeout(() => { dash.refresh(['widgets']); if (query.trim()) loadQuick() }, 1500)
    } catch (e) {
      quickMsg = `✕ ${a.service}: ${e.message}`
      flash(RED)
    } finally {
      quickBusy = false
    }
  }

  /** Enter in de zoekbalk: de eerste tegel, actie of vondst. */
  export function first() {
    if (results[0]?.url) window.open(results[0].url, '_blank', 'noopener')
    else if (actionResults[0]) runQuick(actionResults[0])
    else if (foundGroups[0]) openFound(foundGroups[0].kind, foundGroups[0].items[0])
  }
</script>

{#snippet foundGroup(g)}
  <div class="fgrp">
    <span class="lbl">{g.label}{g.more ? ` · nog ${g.more}` : ''}</span>
    {#each g.items as it, i (i)}
      <button class="frow" onclick={() => openFound(g.kind, it)}>
        <span class="ft" class:e={it.severity <= 3 || it.status === 'fout'} class:w={it.severity === 4 || it.status === 'gemist'}>{it.title}</span>
        {#if it.sub}<small>{it.sub}</small>{/if}
      </button>
    {/each}
  </div>
{/snippet}

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
  {#each foundGroups.filter((g) => g.kind === 'lookup') as g (g.kind)}{@render foundGroup(g)}{/each}
  <div class="tiles pad">
    {#each results as s (s.id)}
      <ServiceTile service={s} status={dash.status[s.id]} widget={dash.widgets[s.id]} updates={dash.updates.by_service[s.id]}
                   zbx={dash.zbx[s.id]} editing={dash.editing} onedit={(svc) => dash.open('service', { service: svc })}
                   ondetail={(svc) => dash.open('detail', { service: svc })} />
    {:else}
      {#if !actionResults.length && !foundGroups.length}<p class="hint">Niets gevonden.</p>{/if}
    {/each}
  </div>
  {#each foundGroups.filter((g) => g.kind !== 'lookup') as g (g.kind)}{@render foundGroup(g)}{/each}
</Card>

<style>
  :global(.results) { margin-top: 18px }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(165px, 1fr)); gap: 8px }
  .pad { padding: 12px }
  .acts { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 12px 12px 0 }
  .act { display: inline-flex; gap: 8px; align-items: baseline; padding: 6px 10px; border-radius: 9px; cursor: pointer;
         background: var(--fill); border: 1px solid var(--line-2); color: var(--text); font-size: 12.5px; text-align: left }
  .act:hover { background: var(--fill-h); color: #fff }
  .act.danger:hover { border-color: var(--err); color: var(--err) }
  .act:disabled { opacity: .5; cursor: progress }
  .act .src { color: var(--muted); font-size: 11.5px }
  .act b { font-weight: 500; color: var(--text-h) }
  .qmsg { font-size: 12px; color: var(--ok); margin-left: 4px }
  .qmsg.bad { color: var(--err) }
  .fgrp { padding: 10px 12px 0; display: flex; flex-direction: column }
  .frow { all: unset; cursor: pointer; display: flex; gap: 10px; align-items: baseline; padding: 5px 8px; border-radius: 8px;
          border-top: 1px solid var(--line); min-width: 0 }
  .frow:hover, .frow:focus-visible { background: var(--fill-h) }
  .ft { color: var(--text-h); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 55% }
  .ft.e { color: var(--err) }
  .ft.w { color: var(--mid) }
  .frow small { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0 }
  @media (max-width: 640px) {
    .frow { flex-direction: column; gap: 1px }
    .ft { max-width: 100% }
    .frow small { max-width: 100% }
  }
  @media (max-width: 560px) {
    .tiles { grid-template-columns: repeat(auto-fill, minmax(138px, 1fr)) }
  }
</style>
