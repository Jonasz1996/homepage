<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import { KIND, dur, hm, rel } from './cronfmt.js'

  // Wanneer loopt wat: per machine een tijdlijn, zware jobs (back-ups, syncs, verify, gc) gemarkeerd,
  // en een lijst van jobs die tegelijk op dezelfde opslag of machine inhakken.
  let { open, onjob } = $props()

  let hours = $state(24)
  let system = $state(false)
  let data = $state(null)
  let error = $state('')
  let hover = $state(null)

  async function load() {
    try {
      data = await api(`/cron/agenda?hours=${hours}&system=${system}`)
      error = ''
    } catch (e) { error = e.message }
  }
  $effect(() => {
    hours; system
    if (open) untrack(load)
  })

  let t0 = $derived(data ? new Date(data.start).getTime() : 0)
  let span = $derived(data ? new Date(data.end).getTime() - t0 : 1)
  const x = (ts) => Math.max(0, Math.min(100, ((new Date(ts).getTime() - t0) / span) * 100))
  const w = (a, b) => Math.max(0.35, x(b) - x(a))
  let ticks = $derived.by(() => {
    if (!data) return []
    const step = hours <= 24 ? 3 : hours <= 48 ? 6 : 24
    const out = []
    const d = new Date(t0)
    d.setMinutes(0, 0, 0)
    while (d.getTime() <= t0 + span) {
      if (d.getTime() >= t0 && d.getHours() % step === 0) out.push(new Date(d))
      d.setHours(d.getHours() + 1)
    }
    return out
  })
  let maxBusy = $derived(Math.max(1, ...(data?.busy || [0])))
  const label = (d) => (d.getHours() === 0 || hours > 48
    ? d.toLocaleDateString('nl-BE', { weekday: 'short', day: 'numeric' }) + (d.getHours() ? ` ${d.getHours()}u` : '')
    : `${String(d.getHours()).padStart(2, '0')}:00`)
</script>

<div class="wrap">
  <div class="filters">
    {#each [[24, '24 uur'], [48, '2 dagen'], [168, 'week']] as [h, l]}
      <button class="mini" class:on={hours === h} onclick={() => (hours = h)}>{l}</button>
    {/each}
    <label class="chk"><input type="checkbox" bind:checked={system} /> systeemjobs</label>
    <span class="legend"><i class="lg heavy"></i> zwaar (back-up, sync, verify, gc) <i class="lg"></i> licht</span>
  </div>
  {#if error}<p class="err">{error}</p>{/if}
  {#if data}
    {#if data.conflicts.length}
      <div class="conf">
        <b>⚠ {data.conflicts.length} botsing{data.conflicts.length === 1 ? '' : 'en'}</b>
        {#each data.conflicts.slice(0, 8) as c}
          <div>
            {rel(c.at)}:
            <button class="lnk" onclick={() => onjob(c.a)}>{c.a_name}</button> en
            <button class="lnk" onclick={() => onjob(c.b)}>{c.b_name}</button>
            lopen {dur(c.overlap_s)} tegelijk op <b>{c.on_label}</b>
          </div>
        {/each}
        <small>Schuif één van beide op, dan concurreren ze niet om dezelfde schijf of hetzelfde netwerk.</small>
      </div>
    {/if}

    <div class="grid">
      <div class="lab"></div>
      <div class="axis">
        <svg class="busy" viewBox="0 0 {data.busy.length} 10" preserveAspectRatio="none" aria-hidden="true">
          {#each data.busy as b, i}<rect x={i + 0.08} width="0.84" y={10 - (b / maxBusy) * 10} height={(b / maxBusy) * 10} />{/each}
        </svg>
        {#each ticks as t}<span class="tick" style="left:{x(t)}%">{label(t)}</span>{/each}
      </div>
      {#each data.rows as row (row.target)}
        <div class="lab" title={row.name}>{row.name}
          {#if row.dense.length}<small title={row.dense.map((d) => `${d.name}: ${d.when}`).join('\n')}>+ {row.dense.length} vaak (elke paar min)</small>{/if}
        </div>
        <div class="track">
          {#each ticks as t}<i class="gl" style="left:{x(t)}%"></i>{/each}
          <i class="now" style="left:{x(data.now)}%"></i>
          {#each row.items as it, k (k)}
            <button class="it k-{it.kind}" class:heavy={it.heavy} class:bad={it.status === 'fout' || it.status === 'gemist'}
                    style="left:{x(it.start)}%; width:{w(it.start, it.end)}%"
                    onmouseenter={() => (hover = it)} onmouseleave={() => (hover = null)} onclick={() => onjob(it.job)}
                    aria-label="{it.name} om {hm(it.start)}"></button>
          {/each}
        </div>
      {:else}
        <p class="hint">Niets gepland in deze periode.</p>
      {/each}
    </div>
    <p class="hint tip">{#if hover}<b>{hover.name}</b> · {KIND[hover.kind] || hover.kind} · {hm(hover.start)}–{hm(hover.end)} ({rel(hover.start)}){:else}Wijs een blokje aan; klik voor de details. De lengte is de gemiddelde duur van de vorige runs.{/if}</p>
  {:else if !error}
    <p class="hint">laden…</p>
  {/if}
</div>

<style>
  .wrap { flex: 1; overflow: auto; padding: 10px 14px 20px; border-top: 1px solid var(--line); margin-top: 8px }
  .filters { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 10px }
  .legend { margin-left: auto; font-size: 11.5px; color: var(--muted); display: flex; gap: 6px; align-items: center }
  .lg { width: 14px; height: 8px; border-radius: 2px; background: #7d9cc4; display: inline-block }
  .lg.heavy { background: var(--mid) }
  .conf { border: 1px solid rgba(230, 181, 107, .35); background: rgba(230, 181, 107, .08); border-radius: 10px; padding: 10px 12px;
          font-size: 12.5px; display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px }
  .conf b { color: var(--mid); font-weight: 500 }
  .conf small { color: var(--muted) }
  .lnk { background: none; border: 0; padding: 0; font: inherit; color: #a9c7ff; cursor: pointer; text-decoration: underline dotted }
  .grid { display: grid; grid-template-columns: 170px 1fr; gap: 4px 10px; align-items: center }
  .lab { font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .lab small { display: block; color: var(--dim); font-size: 10.5px }
  .axis { position: relative; height: 34px }
  .busy { position: absolute; left: 0; right: 0; top: 0; width: 100%; height: 14px }
  .busy rect { fill: rgba(230, 181, 107, .45) }
  .tick { position: absolute; bottom: 0; transform: translateX(-50%); font-size: 10.5px; color: var(--dim); white-space: nowrap }
  .track { position: relative; height: 22px; background: var(--fill); border-radius: 5px }
  .gl { position: absolute; top: 0; bottom: 0; width: 1px; background: rgba(255, 255, 255, .06) }
  .now { position: absolute; top: -3px; bottom: -3px; width: 2px; background: var(--ok); opacity: .7 }
  .it { position: absolute; top: 4px; height: 14px; min-width: 3px; border: 0; padding: 0; border-radius: 3px; background: #7d9cc4;
        opacity: .85; cursor: pointer }
  .it.heavy { background: var(--mid) }
  .it.bad { outline: 1.5px solid var(--err) }
  .it:hover { opacity: 1; filter: brightness(1.25); z-index: 2 }
  .tip { min-height: 1.4em; margin-top: 10px; font-size: 12px }
  @media (max-width: 700px) { .grid { grid-template-columns: 90px 1fr } }
</style>
