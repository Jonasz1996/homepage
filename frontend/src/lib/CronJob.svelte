<script>
  import { onMount, tick } from 'svelte'
  import { api, requestReauth, withReauth } from './api.js'
  import Modal from './Modal.svelte'
  import { KIND, STATUS, STATUS_HINT, dur, full, rel, wsUrl } from './cronfmt.js'

  // Eén job: schema in gewone taal, de volgende keren, runs met uitvoer, nu uitvoeren met live uitvoer,
  // bewaken (wrapper) en meldingen aan/uit.
  let { id, onclose, onchanged, onterminal } = $props()

  let job = $state(null)
  let error = $state('')
  let busy = $state(false)
  let alias = $state('')
  let openRun = $state(null)
  let showScript = $state(false)
  let live = $state(null) // { out, running, code, s }
  let liveEl = $state()
  let ws

  async function load() {
    try {
      job = await api(`/cron/jobs/${id}`)
      alias = job.alias || ''
      error = ''
    } catch (e) { error = e.message }
  }
  onMount(() => { load(); return () => ws?.close() })

  async function patch(body) {
    try {
      await api(`/cron/jobs/${id}`, { method: 'PATCH', body })
      await load()
      onchanged?.()
    } catch (e) { error = e.message }
  }

  async function monitor(on) {
    busy = true
    error = ''
    try {
      await withReauth(() => api(`/cron/jobs/${id}/monitor`, { method: 'POST', body: { on } }))
      await load()
      onchanged?.()
    } catch (e) { error = e.message } finally { busy = false }
  }

  const dec = new TextDecoder()
  function runNow(retried = false) {
    if (!confirm(`${job.name} nu uitvoeren op ${job.target_name}?\n\n${job.command.slice(0, 300)}`)) return
    start(retried)
  }
  function start(retried) {
    live = { out: '', running: true, code: null, s: null }
    ws = new WebSocket(wsUrl(`/cron/ws/run/${id}`))
    ws.binaryType = 'arraybuffer'
    ws.onmessage = async (e) => {
      if (typeof e.data !== 'string') {
        live.out = (live.out + dec.decode(new Uint8Array(e.data), { stream: true })).slice(-200000)
        await tick()
        if (liveEl) liveEl.scrollTop = liveEl.scrollHeight
        return
      }
      const m = JSON.parse(e.data)
      if (m.t === 'status') live.out += `$ ${m.m}\n`
      else if (m.t === 'exit') { live.running = false; live.code = m.code; live.s = m.s; load(); onchanged?.() }
      else if (m.t === 'error') {
        live.running = false
        if (m.m === 'reauth_required' && !retried) {
          try { await requestReauth(); start(true) } catch { live.out += 'Geannuleerd.\n' }
        } else live.out += `\n${m.m}\n`
      }
    }
    ws.onclose = () => { if (live) live.running = false }
  }
  const stop = () => ws?.readyState === 1 && ws.send(JSON.stringify({ t: 'stop' }))

  // In de tijdzone van de machine, zoals het schema zelf.
  const tz = (ts) => {
    const o = { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }
    try { return new Date(ts).toLocaleString('nl-BE', { ...o, timeZone: job.tz || undefined }) } catch { return new Date(ts).toLocaleString('nl-BE', o) }
  }
</script>

<Modal title={job ? `job ${job.name}` : 'job'} {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if job}
    <div class="head">
      <i class="dot s-{job.last_status || 'none'}"></i>
      <div class="ttl">
        <input class="alias" bind:value={alias} placeholder={job.auto_name} maxlength="120"
               onkeydown={(e) => e.key === 'Enter' && patch({ alias })} onblur={() => alias !== (job.alias || '') && patch({ alias })} />
        <small>{KIND[job.kind] || job.kind} op <b>{job.target_name}</b>{job.user ? ` · als ${job.user}` : ''} · {job.source}</small>
      </div>
    </div>

    <div class="grid">
      <span class="k">wanneer</span><span><b>{job.when}</b> <code>{job.schedule}</code>{job.tz && job.tz !== 'UTC' ? ` · ${job.tz}` : ''}</span>
      <span class="k">volgende</span><span>{job.next.length ? job.next.map(tz).join(' · ') : job.next_run_at ? full(job.next_run_at) : '—'}</span>
      <span class="k">laatste keer</span>
      <span>
        <span class="s-{job.last_status || 'none'}">{STATUS[job.last_status] || 'nog niet gezien'}</span>
        {job.last_run_at ? ` · ${rel(job.last_run_at)}` : ''}{job.last_duration ? ` · ${dur(job.last_duration)}` : ''}
        {job.last_exit != null && job.last_exit !== 0 ? ` · exitcode ${job.last_exit}` : ''}
        {#if STATUS_HINT[job.last_status]}<small class="d">{STATUS_HINT[job.last_status]}</small>{/if}
      </span>
      {#if job.stats.runs}
        <span class="k">geschiedenis</span>
        <span>{job.stats.ok} van {job.stats.runs} gelukt{job.stats.avg_s ? ` · gemiddeld ${dur(job.stats.avg_s)}` : ''}{job.runs_24h ? ` · ${job.runs_24h}× in 24 u` : ''}</span>
      {/if}
      {#if job.description}<span class="k">wat</span><span>{job.description}</span>{/if}
      {#if job.targets.length}
        <span class="k">raakt</span>
        <span class="tg">{#each job.targets as t}<span class="to">{t.dir === 'in' ? '←' : '→'} {t.label} <small>({t.via})</small></span>{/each}</span>
      {/if}
    </div>

    <pre class="cmd">{job.command}</pre>
    {#if job.script_path}
      <button class="mini" onclick={() => (showScript = !showScript)}>{showScript ? '▾' : '▸'} script {job.script_path}</button>
      {#if showScript}<pre class="cmd script">{job.extra?.script}</pre>{/if}
    {/if}

    <div class="row acts">
      {#if job.can_run}
        <button class="btn" disabled={live?.running} onclick={() => runNow()}>▶ nu uitvoeren</button>
      {/if}
      {#if job.can_monitor}
        <button class="btn alt" disabled={busy} onclick={() => monitor(!job.monitored)}
                title="Laat de regel via /usr/local/bin/hp-cron lopen: exitcode, duur en uitvoer van elke run">
          {busy ? 'bezig…' : job.monitored ? 'bewaken uit' : 'bewaken aan'}</button>
      {/if}
      <button class="btn alt" onclick={() => patch({ muted: !job.muted })}>{job.muted ? 'meldingen aan' : 'meldingen uit'}</button>
      {#if job.host_id && job.vmid == null && onterminal}
        <button class="btn alt" onclick={() => onterminal(job.host_id)}>&gt;_ terminal</button>
      {/if}
    </div>
    {#if job.can_monitor && !job.monitored}
      <p class="hint small">Bewaken past alleen deze regel aan (kopie in /var/backups/hp-cron) zodat elke run zijn exitcode,
        duur en uitvoer meldt. Zonder bewaken ziet het dashboard alleen dát cron de job startte.
        {#if /\/dev\/null/.test(job.command)}Deze regel stuurt zijn uitvoer naar /dev/null: je ziet dan wel de exitcode, niet de uitvoer.{/if}</p>
    {/if}

    {#if live}
      <div class="live">
        <div class="lh">
          <span>{live.running ? 'loopt…' : live.code === 0 ? `✓ klaar in ${dur(live.s)}` : live.code != null ? `✕ exitcode ${live.code} na ${dur(live.s)}` : 'gestopt'}</span>
          {#if live.running}<button class="mini x" onclick={stop}>stoppen</button>{:else}<button class="mini" onclick={() => (live = null)}>sluiten</button>{/if}
        </div>
        <pre bind:this={liveEl}>{live.out}</pre>
      </div>
    {/if}

    <span class="lbl">runs</span>
    {#each job.runs as r (r.id)}
      <button class="run" onclick={() => (openRun = openRun === r.id ? null : r.id)} disabled={!r.output}>
        <i class="dot s-{r.status}"></i>
        <span>{full(r.started_at)}</span>
        <span class="s-{r.status}">{STATUS[r.status] || r.status}{r.exit_code ? ` (${r.exit_code})` : ''}</span>
        <span class="d">{r.duration != null ? dur(r.duration) : ''}</span>
        <span class="d">{r.trigger === 'manueel' ? 'zelf gestart' : ''}</span>
        <span class="ar">{r.output ? (openRun === r.id ? '▾' : '▸') : ''}</span>
      </button>
      {#if openRun === r.id}<pre class="out">{r.output}</pre>{/if}
    {:else}
      <p class="hint small">Nog geen runs gezien.</p>
    {/each}
  {:else if !error}
    <p class="hint">laden…</p>
  {/if}
</Modal>

<style>
  .head { display: flex; gap: 10px; align-items: center; margin-bottom: 10px }
  .ttl { flex: 1; min-width: 0 }
  .alias { width: 100%; font-size: 16px; background: transparent; border: 1px solid transparent; padding: 3px 6px; margin-left: -6px }
  .alias:hover, .alias:focus { border-color: var(--line-2); background: var(--fill) }
  .ttl small { color: var(--muted); font-size: 12px }
  .ttl b { color: var(--text); font-weight: 500 }
  .grid { display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; font-size: 13px; align-items: baseline }
  .grid .k { color: var(--muted); font-size: 12px }
  .grid code { color: var(--dim); font-size: 11.5px; margin-left: 6px }
  .grid b { font-weight: 500; color: var(--text-h) }
  .d { color: var(--dim); display: block; font-size: 11.5px }
  .tg { display: flex; flex-wrap: wrap; gap: 5px }
  .to { font-size: 12px; padding: 1px 8px; border-radius: 6px; border: 1px solid var(--line-2); color: #a9c7ff }
  .to small { color: var(--dim) }
  .cmd { margin: 12px 0 8px; padding: 10px 12px; background: #0c0c0c; border: 1px solid var(--line); border-radius: 8px;
         white-space: pre-wrap; word-break: break-all; font-size: 12px; color: var(--text) }
  .script { max-height: 300px; overflow: auto; color: #bbb }
  .acts { margin: 12px 0 4px }
  .small { font-size: 12px; margin-top: 6px }
  .live { margin: 10px 0; border: 1px solid var(--line-2); border-radius: 8px; overflow: hidden }
  .lh { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; font-size: 12.5px; background: var(--fill) }
  .live pre { margin: 0; padding: 10px 12px; max-height: 340px; overflow: auto; background: #0c0c0c; font-size: 12px;
              white-space: pre-wrap; word-break: break-all }
  .run { width: 100%; display: grid; grid-template-columns: 12px 140px 1fr 80px 90px 14px; gap: 10px; align-items: center;
         text-align: left; background: none; border: 0; border-radius: 7px; padding: 5px 6px; color: var(--text); font: inherit;
         font-size: 12.5px; cursor: pointer }
  .run:hover:not(:disabled) { background: var(--fill) }
  .run:disabled { cursor: default }
  .run .d { display: inline }
  .ar { color: var(--dim) }
  .out { margin: 2px 0 8px 22px; padding: 8px 10px; background: #0c0c0c; border-radius: 7px; font-size: 11.5px; max-height: 260px;
         overflow: auto; white-space: pre-wrap; word-break: break-all }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--dim); display: inline-block; flex: none }
  .s-ok { color: var(--ok) } .dot.s-ok { background: var(--ok) }
  .s-fout { color: var(--err) } .dot.s-fout { background: var(--err) }
  .s-gemist { color: var(--mid) } .dot.s-gemist { background: var(--mid) }
  .s-gestart { color: #9fc3a9 } .dot.s-gestart { background: #5f7f68 }
  .s-bezig { color: #a9c7ff } .dot.s-bezig { background: #a9c7ff }
  @media (max-width: 600px) { .run { grid-template-columns: 12px 1fr auto } .run .d, .run .ar { display: none } }
</style>
