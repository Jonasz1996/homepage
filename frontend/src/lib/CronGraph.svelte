<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import { STATUS } from './cronfmt.js'

  // Verbanden: welke job brengt data van welke machine naar welke andere (back-ups naar PBS, rsync naar de NAS,
  // replicatie tussen nodes, PBS-syncs). Links de bronnen, rechts de doelen.
  let { open, onjob } = $props()

  let data = $state(null)
  let error = $state('')
  let sel = $state(null)

  async function load() {
    try {
      data = await api('/cron/graph')
      error = ''
    } catch (e) { error = e.message }
  }
  $effect(() => { if (open) untrack(load) })

  const COL = 290, ROW = 74, BW = 210, BH = 44

  let layout = $derived.by(() => {
    if (!data) return null
    const depth = Object.fromEntries(data.nodes.map((n) => [n.id, 0]))
    for (let i = 0; i < data.nodes.length; i++) {
      let moved = false
      for (const e of data.edges) {
        const d = depth[e.from] + 1
        if (d <= 3 && depth[e.to] < d) { depth[e.to] = d; moved = true }
      }
      if (!moved) break
    }
    const cols = []
    for (const n of data.nodes) (cols[depth[n.id]] ||= []).push(n)
    const pos = {}
    cols.forEach((list, c) => {
      list.sort((a, b) => (a.kind === 'external') - (b.kind === 'external') || a.label.localeCompare(b.label))
      list.forEach((n, r) => (pos[n.id] = { x: 20 + c * COL, y: 30 + r * ROW, n }))
    })
    const pairs = new Map()
    for (const e of data.edges) {
      const k = `${e.from}|${e.to}`
      if (!pairs.has(k)) pairs.set(k, { from: e.from, to: e.to, items: [] })
      pairs.get(k).items.push(e)
    }
    // Meerdere pijlen naar dezelfde machine: labels onder elkaar.
    const seen = {}
    for (const p of pairs.values()) p.idx = (seen[p.to] = (seen[p.to] ?? -1) + 1)
    const rows = Math.max(1, ...cols.map((l) => l?.length || 0))
    return { pos, pairs: [...pairs.values()], w: Math.max(1, cols.length) * COL, h: rows * ROW + 40 }
  })

  function path(p) {
    const a = layout.pos[p.from], b = layout.pos[p.to]
    if (!a || !b) return ''
    const x1 = a.x + BW, y1 = a.y + BH / 2, x2 = b.x, y2 = b.y + BH / 2
    if (x2 > x1) {
      const m = (x1 + x2) / 2
      return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`
    }
    // Terug of in dezelfde kolom: een boog boven langs.
    const top = Math.min(a.y, b.y) - 18
    return `M${a.x + BW / 2},${a.y} C${a.x + BW / 2},${top} ${b.x + BW / 2},${top} ${b.x + BW / 2},${b.y}`
  }
  // Label vlak voor de pijlpunt: daar lopen de lijnen het minst door elkaar.
  const mid = (p) => {
    const a = layout.pos[p.from], b = layout.pos[p.to]
    if (b.x > a.x + BW) return { x: b.x - 10, y: b.y + BH / 2 - 7 - p.idx * 13, end: true }
    return { x: (a.x + b.x) / 2 + BW / 2, y: Math.min(a.y, b.y) - 10, end: false }
  }
  const tone = (items) => (items.some((e) => e.status === 'fout' || e.status === 'gemist') ? 'bad'
    : items.every((e) => e.status === 'ok') ? 'ok' : 'mid')
  const short = (s, n = 26) => (s.length > n ? s.slice(0, n - 1) + '…' : s)
  let name = $derived(Object.fromEntries((data?.machines || []).map((m) => [m.id, m.label])))
</script>

<div class="wrap">
  {#if error}<p class="err">{error}</p>{/if}
  {#if layout}
    {#if !data.edges.length}
      <p class="hint">Nog geen verbanden gevonden. Ze komen uit Proxmox-back-ups en -replicatie, PBS-syncs en commando's
        als rsync, rclone, scp, borg, restic en proxmox-backup-client (ook in de scripts die een job aanroept).</p>
    {:else}
      <div class="canvas">
        <svg viewBox="0 0 {layout.w} {layout.h}" style="min-width:{Math.min(layout.w, 1400)}px" role="img" aria-label="Verbanden tussen machines">
          <defs>
            <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="context-stroke" />
            </marker>
          </defs>
          {#each layout.pairs as p (p.from + p.to)}
            {@const m = mid(p)}
            <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
            <g class="edge {tone(p.items)}" class:sel={sel === p} onclick={() => (sel = sel === p ? null : p)}>
              <path d={path(p)} marker-end="url(#ar)" />
              <path class="hit" d={path(p)} />
              <text x={m.x} y={m.y} text-anchor={m.end ? 'end' : 'middle'}>{short(p.items[0].via)}{p.items.length > 1 ? ` +${p.items.length - 1}` : ''}</text>
            </g>
          {/each}
          {#each Object.values(layout.pos) as { x, y, n } (n.id)}
            <g class="node {n.kind}">
              <rect {x} {y} width={BW} height={BH} rx="9" />
              <text x={x + 12} y={y + 18} class="t">{short(n.label, 28)}</text>
              <text x={x + 12} y={y + 34} class="s">{n.kind === 'external' ? (n.type === 'ping' ? 'heartbeat' : 'buiten het dashboard') : n.kind === 'ct' ? `container op ${n.node}` : n.kind === 'cluster' ? 'Proxmox-cluster' : 'machine'}</text>
              {#each (data.badges[n.id] || []).slice(0, 3) as b, i}
                <text x={x + 12} y={y + BH + 13 + i * 12} class="b">{short(`${b.name} · ${b.when}`, 34)}</text>
              {/each}
            </g>
          {/each}
        </svg>
      </div>
      <p class="hint small">Klik op een pijl voor de jobs erachter. Groen: laatste run gelukt, rood: mislukt of niet gelopen.</p>
    {/if}

    <span class="lbl">wat gaat waarheen</span>
    <div class="tbl">
      {#each (sel ? sel.items : data.edges) as e, i (i)}
        <button class="ln" onclick={() => onjob(e.job)}>
          <span class="f">{name[e.from] || e.from}</span>
          <span class="ar">→</span>
          <span class="f">{name[e.to] || e.to}</span>
          <span><b>{e.name}</b> <small>{e.via}{e.label ? ` · ${e.label}` : ''}</small></span>
          <span class="w">{e.when}{e.enabled ? '' : ' (uit)'}</span>
          <span class="s-{e.status || 'none'}">{STATUS[e.status] || '—'}</span>
        </button>
      {/each}
      {#if sel}<button class="mini" onclick={() => (sel = null)}>alle verbanden tonen</button>{/if}
    </div>
  {:else if !error}
    <p class="hint">laden…</p>
  {/if}
</div>

<style>
  .wrap { flex: 1; overflow: auto; padding: 10px 14px 20px; border-top: 1px solid var(--line); margin-top: 8px }
  .canvas { overflow: auto; border: 1px solid var(--line); border-radius: 10px; background: rgba(0, 0, 0, .25); padding: 6px }
  svg { width: 100%; height: auto; display: block }
  .node rect { fill: rgba(30, 30, 30, .95); stroke: var(--line-2) }
  .node.cluster rect { stroke: #a9c7ff }
  .node.external rect { stroke-dasharray: 4 3; fill: rgba(20, 20, 20, .7) }
  .node .t { fill: var(--text-h); font-size: 12.5px; font-family: var(--mono) }
  .node .s { fill: var(--dim); font-size: 10.5px; font-family: var(--mono) }
  .node .b { fill: var(--muted); font-size: 10px; font-family: var(--mono) }
  .edge { cursor: pointer }
  .edge path { fill: none; stroke: #7d9cc4; stroke-width: 1.6 }
  .edge .hit { stroke: transparent; stroke-width: 12 }
  .edge.ok path:not(.hit) { stroke: var(--ok) }
  .edge.bad path:not(.hit) { stroke: var(--err) }
  .edge.sel path:not(.hit), .edge:hover path:not(.hit) { stroke-width: 3 }
  .edge text { fill: var(--muted); font-size: 10.5px; font-family: var(--mono); paint-order: stroke; stroke: #111; stroke-width: 3px }
  .small { font-size: 12px }
  .tbl { display: flex; flex-direction: column; gap: 2px }
  .ln { display: grid; grid-template-columns: minmax(100px, 1fr) 16px minmax(100px, 1fr) minmax(200px, 2fr) minmax(120px, 1fr) 90px; gap: 10px;
        align-items: baseline; text-align: left; background: none; border: 0; border-radius: 7px; padding: 5px 6px; color: var(--text);
        font: inherit; font-size: 12.5px; cursor: pointer }
  .ln:hover { background: var(--fill) }
  .ln b { font-weight: 500; color: var(--text-h) }
  .ln small, .w { color: var(--dim); font-size: 11.5px }
  .f { color: #a9c7ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .ar { color: var(--dim) }
  .s-ok { color: var(--ok) } .s-fout { color: var(--err) } .s-gemist { color: var(--mid) } .s-gestart { color: #9fc3a9 } .s-none { color: var(--dim) }
  @media (max-width: 700px) { .ln { grid-template-columns: 1fr 16px 1fr; } .ln > span:nth-child(n + 4) { grid-column: 1 / -1 } }
</style>
