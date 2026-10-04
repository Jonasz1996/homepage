<script>
  import { onMount, untrack } from 'svelte'
  import { api, poll } from './api.js'
  import CronAgenda from './CronAgenda.svelte'
  import CronGraph from './CronGraph.svelte'
  import CronJob from './CronJob.svelte'
  import CronLive from './CronLive.svelte'
  import { KIND, STATUS, STATUS_HINT, dur, full, rel } from './cronfmt.js'

  // Alles wat er gepland staat op je machines: cron, timers, Proxmox- en PBS-jobs. Met de laatste runs,
  // een agenda (wat loopt wanneer, en wat botst), de verbanden tussen machines en live meekijken.
  let { open = false, initial = null, onclose, onterminal } = $props()

  let data = $state(null)
  let error = $state('')
  let tab = $state('jobs')
  let target = $state(null)
  let q = $state('')
  let filter = $state('')
  let system = $state(false)
  let detail = $state(null)
  let now = $state(Date.now())

  async function load() {
    try {
      data = await api('/cron')
      error = ''
    } catch (e) { error = e.message }
  }

  async function scan() {
    try {
      await api('/cron/scan', { method: 'POST' })
      await load()
    } catch (e) { error = e.message }
  }

  $effect(() => {
    if (open) untrack(load)
  })
  $effect(() => {
    if (initial) untrack(() => { if (initial.filter) filter = initial.filter; if (initial.job) detail = initial.job; tab = 'jobs' })
  })

  onMount(() => {
    const a = poll(() => open && load(), 30000)
    const b = poll(() => open && data?.running && load(), 3000)
    const c = poll(() => (now = Date.now()), 20000)
    return () => { a(); b(); c() }
  })

  const word = (s) => s.toLowerCase()
  let jobs = $derived.by(() => {
    const words = word(q).split(/\s+/).filter(Boolean)
    return (data?.jobs || []).filter((j) => {
      if (j.removed_at) return filter === 'weg'
      if (filter === 'weg') return false
      if (target && j.target !== target) return false
      if (j.system && !system && filter !== 'systeem') return false
      if (filter === 'probleem' && !['fout', 'gemist'].includes(j.last_status)) return false
      if (filter === 'bewaakt' && !j.monitored) return false
      if (filter === 'systeem' && !j.system) return false
      const text = word(`${j.name} ${j.command} ${j.target_name} ${j.kind} ${j.when} ${j.targets.map((t) => t.label).join(' ')}`)
      return words.every((w) => text.includes(w))
    })
  })
  let groups = $derived.by(() => {
    const out = new Map()
    for (const j of jobs) {
      if (!out.has(j.target)) out.set(j.target, { name: j.target_name, items: [] })
      out.get(j.target).items.push(j)
    }
    return [...out.entries()]
  })
  let hosts = $derived((data?.targets || []).filter((t) => !t.error))
  let broken = $derived((data?.targets || []).filter((t) => t.error))
</script>

<div class="ov" class:hidden={!open}>
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# crontab -l --alle-machines</span>
      <div class="right">
        <span class="when">{data?.running ? 'scannen…' : data?.scanned_at ? `gescand ${rel(data.scanned_at, now)}` : 'nog niet gescand'}</span>
        <button class="mini" disabled={data?.running} onclick={scan}>⟳ nu scannen</button>
        <button class="mini x" onclick={onclose} aria-label="Cron sluiten">✕</button>
      </div>
    </div>

    <div class="tabs">
      {#each [['jobs', 'jobs'], ['agenda', 'agenda'], ['graph', 'verbanden'], ['live', 'live']] as [k, label]}
        <button class="mini" class:on={tab === k} onclick={() => (tab = k)}>{label}</button>
      {/each}
      {#if data}
        <span class="sum">
          <b>{data.summary.jobs}</b> jobs
          {#if data.summary.fout}<button class="lnk e" onclick={() => { tab = 'jobs'; filter = 'probleem' }}>· {data.summary.fout} mislukt</button>{/if}
          {#if data.summary.gemist}<button class="lnk w" onclick={() => { tab = 'jobs'; filter = 'probleem' }}>· {data.summary.gemist} niet gelopen</button>{/if}
          {#if data.summary.monitored}<span class="m">· {data.summary.monitored} bewaakt</span>{/if}
        </span>
      {/if}
    </div>

    {#if error}<p class="err pad">{error}</p>{/if}

    {#if tab === 'jobs'}
      <div class="cols">
        <aside>
          <button class="hb" class:on={!target} onclick={() => (target = null)}><b>alle machines</b>
            <small>{hosts.length} gescand</small></button>
          {#each hosts as t (t.key)}
            <button class="hb" class:on={target === t.key} class:ct={t.vmid != null} onclick={() => (target = target === t.key ? null : t.key)}>
              <b>{t.vmid != null ? '└ ' : ''}{t.name}</b>
              <small>
                {t.counts.jobs} job{t.counts.jobs === 1 ? '' : 's'}{#if t.counts.system}&nbsp;· {t.counts.system} systeem{/if}
                {#if t.counts.fout}&nbsp;·&nbsp;<span class="e">{t.counts.fout} mislukt</span>{/if}
                {#if t.counts.gemist}&nbsp;·&nbsp;<span class="w">{t.counts.gemist} gemist</span>{/if}
                {#if t.cluster}&nbsp;· cluster{/if}
              </small>
            </button>
          {/each}
          {#if broken.length}
            <span class="lbl">niet gescand</span>
            {#each broken as t (t.key)}
              <div class="bad" title={t.error}><b>{t.name}</b><small>{t.error}</small></div>
            {/each}
          {/if}
          {#if data?.pending?.length}
            <span class="lbl">nog geen hostsleutel</span>
            <p class="hint tiny">{data.pending.length} host{data.pending.length === 1 ? '' : 's'} nog nooit geopend in de terminal:
              {data.pending.slice(0, 8).map((p) => p.name).join(', ')}{data.pending.length > 8 ? ', …' : ''}.
              Containers op een node scant de node zelf al mee.</p>
          {/if}
          {#if data && !data.targets.length}
            <p class="hint tiny">Nog niets gescand. Voeg je nodes toe in de terminal (⟳ pve), open ze één keer om de
              hostsleutel te bevestigen en zet de standaard login (root). Daarna: ⟳ nu scannen.</p>
          {/if}
        </aside>
        <section>
          <div class="filters">
            <select class="msel" bind:value={target} aria-label="Machine">
              <option value={null}>alle machines</option>
              {#each hosts as t (t.key)}<option value={t.key}>{t.name}</option>{/each}
            </select>
            <input class="q" bind:value={q} placeholder="zoeken: naam, commando, machine, doel…" />
            {#each [['', 'alles'], ['probleem', 'problemen'], ['bewaakt', 'bewaakt'], ['systeem', 'systeem'], ['weg', 'verdwenen']] as [k, label]}
              <button class="mini" class:on={filter === k} onclick={() => (filter = k)}>{label}</button>
            {/each}
            <label class="chk"><input type="checkbox" bind:checked={system} /> systeemjobs tonen</label>
          </div>
          <div class="list">
            {#each groups as [key, g] (key)}
              <span class="gh">{g.name}</span>
              {#each g.items as j (j.id)}
                <button class="job" class:off={!j.enabled} onclick={() => (detail = j.id)}>
                  <i class="dot s-{j.last_status || 'none'}" title={STATUS[j.last_status] || 'nog niet gelopen'}></i>
                  <span class="nm">
                    <b>{j.name}</b>
                    <span class="k">{KIND[j.kind] || j.kind}</span>
                    {#if j.monitored}<span class="tag">bewaakt</span>{/if}
                    {#if j.muted}<span class="tag dim" title="Geen meldingen">stil</span>{/if}
                    {#if !j.enabled}<span class="tag dim">uit</span>{/if}
                    {#if j.system}<span class="tag dim">systeem</span>{/if}
                    <code>{j.command}</code>
                  </span>
                  <span class="sch"><span>{j.when}</span><small>{j.next_run_at ? `volgende ${rel(j.next_run_at, now)}` : ''}</small></span>
                  <span class="last">
                    <span class="s-{j.last_status || 'none'}" title={STATUS_HINT[j.last_status] || ''}>{STATUS[j.last_status] || '—'}</span>
                    <small>{j.last_run_at ? rel(j.last_run_at, now) : ''}{j.last_duration ? ` · ${dur(j.last_duration)}` : ''}{j.runs_24h > 1 ? ` · ${j.runs_24h}× / 24 u` : ''}</small>
                  </span>
                  <span class="strip" aria-hidden="true">
                    {#each j.recent as r}<i class="s-{r.s}" title="{full(r.t)} · {STATUS[r.s] || r.s}{r.d ? ` · ${dur(r.d)}` : ''}"></i>{/each}
                  </span>
                  <span class="tg">
                    {#each j.targets.slice(0, 3) as t}<span class="to" title="{t.via}">{t.dir === 'in' ? '←' : '→'} {t.label}</span>{/each}
                  </span>
                </button>
              {/each}
            {:else}
              <p class="hint pad">{data ? 'Geen jobs gevonden.' : 'laden…'}</p>
            {/each}
          </div>
        </section>
      </div>
    {:else if tab === 'agenda'}
      <CronAgenda {open} onjob={(id) => (detail = id)} />
    {:else if tab === 'graph'}
      <CronGraph {open} onjob={(id) => (detail = id)} />
    {:else}
      <CronLive targets={hosts.filter((t) => t.key.startsWith('ssh:'))} jobs={data?.jobs || []} />
    {/if}
  </div>
</div>

{#if detail}
  <CronJob id={detail} onclose={() => (detail = null)} onchanged={load} {onterminal} />
{/if}

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .when { color: var(--dim); font-size: 12px }
  .tabs { display: flex; gap: 6px; align-items: center; padding: 10px 12px 0; flex-wrap: wrap }
  .sum { margin-left: auto; font-size: 12.5px; color: var(--muted) }
  .sum b { color: var(--text-h); font-weight: 500 }
  .lnk { background: none; border: 0; padding: 0; font: inherit; cursor: pointer }
  .e, .lnk.e { color: var(--err) }
  .w, .lnk.w { color: var(--mid) }
  .m { color: var(--ok) }
  .pad { padding: 0 12px }
  .cols { flex: 1; display: flex; min-height: 0; margin-top: 8px; border-top: 1px solid var(--line) }
  aside { width: 230px; flex: none; border-right: 1px solid var(--line); padding: 10px; overflow: auto; display: flex; flex-direction: column; gap: 3px }
  .hb { text-align: left; background: none; border: 1px solid transparent; border-radius: 8px; padding: 5px 8px; color: var(--text); cursor: pointer; font: inherit }
  .hb:hover { background: var(--fill) }
  .hb.on { background: var(--fill-h); border-color: var(--line-2) }
  .hb.ct { padding-left: 14px }
  .hb b, .bad b { display: block; font-weight: 500; font-size: 12.5px; color: var(--text-h); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .hb small, .bad small { color: var(--muted); font-size: 11px }
  .bad { padding: 5px 8px; opacity: .8 }
  .bad small { color: var(--err); display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .tiny { font-size: 11.5px; margin: 4px 8px }
  section { flex: 1; min-width: 0; display: flex; flex-direction: column }
  .filters { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; padding: 10px 12px }
  .filters .q { flex: 1; min-width: 200px }
  .list { flex: 1; overflow: auto; padding: 0 8px 20px }
  .gh { display: block; margin: 12px 6px 4px; font-size: 11.5px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted) }
  .job { width: 100%; display: grid; grid-template-columns: 12px minmax(220px, 2.2fr) minmax(150px, 1.2fr) minmax(120px, 1fr) 120px minmax(0, 1.2fr);
         gap: 12px; align-items: center; text-align: left; background: none; border: 1px solid transparent; border-radius: 9px;
         padding: 7px 8px; color: var(--text); font: inherit; font-size: 12.5px; cursor: pointer }
  .job:hover { background: var(--fill); border-color: var(--line) }
  .job.off { opacity: .55 }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--dim) }
  .nm { min-width: 0; display: flex; flex-wrap: wrap; gap: 3px 6px; align-items: baseline }
  .nm b { font-weight: 500; color: var(--text-h) }
  .nm code { flex-basis: 100%; color: var(--dim); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .k { color: var(--muted); font-size: 11px }
  .tag { font-size: 10.5px; padding: 0 6px; border-radius: 6px; background: rgba(143, 214, 164, .14); color: var(--ok) }
  .tag.dim { background: var(--fill-h); color: var(--muted) }
  .sch, .last { display: flex; flex-direction: column; min-width: 0 }
  .sch small, .last small { color: var(--dim); font-size: 11px }
  .strip { display: flex; gap: 2px; align-items: center }
  .strip i { width: 6px; height: 14px; border-radius: 2px; background: var(--dim) }
  .tg { display: flex; flex-wrap: wrap; gap: 4px; min-width: 0 }
  .to { font-size: 11px; padding: 1px 7px; border-radius: 6px; border: 1px solid var(--line-2); color: #a9c7ff; max-width: 100%;
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .s-ok { color: var(--ok) } i.s-ok { background: var(--ok) }
  .s-fout { color: var(--err) } i.s-fout { background: var(--err) }
  .s-gemist { color: var(--mid) } i.s-gemist { background: var(--mid) }
  .s-gestart { color: #9fc3a9 } i.s-gestart { background: #5f7f68 }
  .s-bezig { color: #a9c7ff } i.s-bezig { background: #a9c7ff; animation: pulse 1.2s infinite }
  .s-gestopt, .s-none { color: var(--dim) }
  @keyframes pulse { 50% { opacity: .35 } }
  .msel { display: none; width: auto }
  @media (max-width: 900px) {
    aside { display: none }
    .msel { display: block }
    .job { grid-template-columns: 12px 1fr auto; }
    .job .strip, .job .tg, .job .sch { display: none }
  }
  @media (max-width: 600px) { .ov { padding: 0 } }
</style>
