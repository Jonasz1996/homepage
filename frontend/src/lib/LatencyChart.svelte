<script>
  // Latency over tijd: gemiddelde als lijn, min-max als band, tijdvakken met fouten als rode strook onderaan.
  let { points = [], bucketSeconds = 60 } = $props()

  let width = $state(700)
  let hover = $state(null)
  const H = 220
  const pad = { l: 48, r: 12, t: 12, b: 40 }

  let data = $derived(points.map((p) => ({ ...p, ts: new Date(p.t).getTime() })))
  let t0 = $derived(data.length ? data[0].ts : 0)
  let t1 = $derived(data.length ? data[data.length - 1].ts + bucketSeconds * 1000 : 1)
  let yMax = $derived.by(() => {
    const m = Math.max(1, ...data.map((p) => p.max ?? p.avg ?? 0))
    const step = 10 ** Math.floor(Math.log10(m))
    return Math.ceil(m / step) * step
  })
  let x = $derived((ts) => pad.l + ((ts - t0) / (t1 - t0 || 1)) * (width - pad.l - pad.r))
  let y = $derived((v) => pad.t + (1 - v / yMax) * (H - pad.t - pad.b - 14))
  let plotBottom = H - pad.b - 14

  // Lijn onderbreken waar geen meting is (bv. service down).
  let segments = $derived.by(() => {
    const segs = []
    let cur = []
    for (const p of data) {
      if (p.avg == null) {
        if (cur.length) segs.push(cur)
        cur = []
      } else cur.push(p)
    }
    if (cur.length) segs.push(cur)
    return segs
  })
  const mid = (p) => p.ts + (bucketSeconds * 1000) / 2
  let line = $derived(segments.map((s) => s.map((p, i) => `${i ? 'L' : 'M'}${x(mid(p)).toFixed(1)},${y(p.avg).toFixed(1)}`).join('')))
  let band = $derived(segments.map((s) =>
    s.map((p, i) => `${i ? 'L' : 'M'}${x(mid(p)).toFixed(1)},${y(p.max).toFixed(1)}`).join('') +
    [...s].reverse().map((p) => `L${x(mid(p)).toFixed(1)},${y(p.min).toFixed(1)}`).join('') + 'Z'))

  const fmtTime = (ts) => {
    const d = new Date(ts)
    return bucketSeconds >= 86400
      ? d.toLocaleDateString('nl-BE', { day: 'numeric', month: 'short' })
      : bucketSeconds >= 3600
        ? d.toLocaleString('nl-BE', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
        : d.toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })
  }
  const fmtMs = (v) => (v == null ? '—' : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`)

  function move(e) {
    if (!data.length) return
    const r = e.currentTarget.getBoundingClientRect()
    const px = ((e.clientX - r.left) / r.width) * width
    let best = null
    for (const p of data) if (!best || Math.abs(x(mid(p)) - px) < Math.abs(x(mid(best)) - px)) best = p
    hover = best
  }
</script>

<div class="chart" bind:clientWidth={width}>
  {#if data.length === 0}
    <p class="empty">Nog geen metingen in deze periode.</p>
  {:else}
    <svg viewBox="0 0 {width} {H}" width={width} height={H} role="img" aria-label="Latency in milliseconden over tijd"
         onpointermove={move} onpointerleave={() => (hover = null)}>
      {#each [0, 0.5, 1] as f}
        <line x1={pad.l} x2={width - pad.r} y1={y(yMax * f)} y2={y(yMax * f)} class="grid" />
        <text x={pad.l - 8} y={y(yMax * f) + 4} text-anchor="end" class="tick">{Math.round(yMax * f)} ms</text>
      {/each}
      {#each band as d}<path {d} class="band" />{/each}
      {#each line as d}<path {d} class="line" />{/each}
      <!-- Uptime-strook: groen = alles gelukt, rood = fouten in dat tijdvak -->
      {#each data as p}
        <rect x={x(p.ts) + 0.5} y={plotBottom + 6} width={Math.max(1, x(p.ts + bucketSeconds * 1000) - x(p.ts) - 1)} height="8" rx="1"
              class:bad={p.up < 1} class:part={p.up > 0 && p.up < 1} class="up" />
      {/each}
      <text x={pad.l - 8} y={plotBottom + 14} text-anchor="end" class="tick">up</text>
      <text x={pad.l} y={H - 8} class="tick">{fmtTime(t0)}</text>
      <text x={width - pad.r} y={H - 8} text-anchor="end" class="tick">{fmtTime(t1)}</text>
      {#if hover}
        <line x1={x(mid(hover))} x2={x(mid(hover))} y1={pad.t} y2={plotBottom + 14} class="cross" />
        {#if hover.avg != null}<circle cx={x(mid(hover))} cy={y(hover.avg)} r="4" class="dot" />{/if}
      {/if}
    </svg>
    {#if hover}
      <div class="tip" style="left:{Math.min(x(mid(hover)) + 12, width - 190)}px">
        <b>{fmtTime(hover.ts)}</b>
        <span>gem. {fmtMs(hover.avg)}</span>
        <span>min {fmtMs(hover.min)} · max {fmtMs(hover.max)}</span>
        <span class:bad={hover.up < 1}>{Math.round((hover.up ?? 0) * 1000) / 10}% gelukt</span>
      </div>
    {/if}
  {/if}
</div>

<style>
  .chart { position: relative; width: 100% }
  svg { display: block; touch-action: none }
  .grid { stroke: rgba(255, 255, 255, .07) }
  .tick { fill: var(--muted); font-size: 11px }
  .band { fill: rgba(255, 255, 255, .08) }
  .line { fill: none; stroke: var(--text-h); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round }
  .up { fill: var(--ok); opacity: .55 }
  .up.part { opacity: .9; fill: var(--mid) }
  .up.bad:not(.part) { fill: var(--err); opacity: 1 }
  .cross { stroke: rgba(255, 255, 255, .35); stroke-dasharray: 3 3 }
  .dot { fill: var(--text-h); stroke: #111; stroke-width: 2 }
  .tip {
    position: absolute; top: 8px; width: 180px; padding: 8px 10px; border-radius: 8px; pointer-events: none;
    background: rgba(10, 10, 10, .92); border: 1px solid var(--line-2); font-size: 11.5px;
    display: flex; flex-direction: column; gap: 2px; color: var(--text)
  }
  .tip b { color: var(--text-h); font-weight: 600 }
  .tip .bad { color: var(--err) }
  .empty { color: var(--muted); font-size: 13px; padding: 30px 0; text-align: center }
</style>
