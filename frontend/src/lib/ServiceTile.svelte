<script>
  import { value } from './format.js'
  import { iconIsMono, iconUrl } from './icons.js'

  let { service, status = null, widget = null, editing = false, onedit, ondetail, dragging = false, dropBefore = false, ...events } = $props()

  let src = $derived(iconUrl(service.icon))
  // Pas tonen als het icoon echt geladen is; anders de eerste letter.
  let loadedSrc = $state(null)
  let loaded = $derived(!!src && loadedSrc === src)

  function probe(img) {
    if (img.complete && img.naturalWidth > 0) loadedSrc = img.getAttribute('src')
  }
  let host = $derived.by(() => {
    try { return service.url ? new URL(service.url).host : '' } catch { return '' }
  })

  // Sparkline van de laatste checks: lijn door de latency, gaten waar een check mislukte.
  let spark = $derived.by(() => {
    const pts = status?.spark || []
    if (pts.length < 2) return ''
    const max = Math.max(1, ...pts.filter((v) => v != null))
    let d = ''
    let pen = false
    pts.forEach((v, i) => {
      if (v == null) { pen = false; return }
      const px = (i / (pts.length - 1)) * 100
      const py = 13 - (v / max) * 11
      d += `${pen ? 'L' : 'M'}${px.toFixed(1)},${py.toFixed(1)}`
      pen = true
    })
    return d
  })
  let health = $derived(status?.status || (service.check?.type ? 'unknown' : null))
  const stateLabel = { up: 'bereikbaar', down: 'down', unknown: 'nog geen check' }
  let ms = $derived(status?.latency_ms == null ? '' : status.latency_ms < 10 ? status.latency_ms.toFixed(1) : Math.round(status.latency_ms))

  function detail(e) {
    e.preventDefault()
    e.stopPropagation()
    ondetail(service)
  }

  function click(e) {
    if (editing) {
      e.preventDefault()
      onedit(service)
    }
  }
</script>

<a
  class="tile"
  class:editing
  class:dragging
  class:drop-before={dropBefore}
  class:up={health === 'up'}
  class:down={health === 'down'}
  href={service.url || undefined}
  target="_blank"
  rel="noopener noreferrer"
  draggable={editing}
  title={[service.description || host || service.name, health && stateLabel[health], status?.last_error].filter(Boolean).join(' · ')}
  onclick={click}
  {...events}
>
  <span class="ic">
    {#if src}
      {#key src}
        <img {src} alt="" class:mono={iconIsMono(service.icon)} class:hidden={!loaded}
             use:probe onload={(e) => (loadedSrc = e.currentTarget.getAttribute('src'))} />
      {/key}
    {/if}
    {#if !loaded}<span class="letter">{service.name.slice(0, 1).toUpperCase()}</span>{/if}
  </span>
  <span class="txt">
    <span class="name">{service.name}</span>
    <span class="desc">
      {#if health === 'down'}<span class="downtxt">down</span>{:else if ms !== ''}<span class="ms">{ms} ms</span>{/if}
      {service.description || host}
    </span>
    {#if widget?.fields?.length}
      <span class="wf">
        {#each widget.fields as f}<span class="f lv-{f.level || 'none'}"><i>{f.label}</i> {value(f.value)}</span>{/each}
      </span>
    {:else if widget?.error}
      <span class="wf"><span class="f lv-err" title={widget.error}>⚠ {widget.error}</span></span>
    {/if}
  </span>
  {#if spark}
    <svg class="spark" viewBox="0 0 100 14" preserveAspectRatio="none" aria-hidden="true"><path d={spark} /></svg>
  {/if}
  {#if editing}
    <span class="edit" aria-hidden="true">✎</span>
  {:else}
    <button class="info" onclick={detail} aria-label="Details van {service.name}" title="Details">▤</button>
  {/if}
</a>

<style>
  .tile {
    position: relative; display: flex; gap: 10px; align-items: center; padding: 10px 12px; min-height: 58px;
    border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .06); border-left: 3px solid #555;
    text-decoration: none; color: var(--text); transition: background .2s, border-color .2s, transform .1s;
  }
  .tile:hover { background: var(--fill-h); border-color: rgba(255, 255, 255, .18); border-left-color: #999 }
  .tile:active { transform: scale(.98) }
  .tile.editing { cursor: grab; border-style: dashed; border-left-style: solid }
  .tile.dragging { opacity: .35 }
  .tile.drop-before { box-shadow: -4px 0 0 0 var(--ok) }
  .ic { width: 32px; height: 32px; flex: none; display: grid; place-items: center }
  .ic img { max-width: 32px; max-height: 32px }
  .ic img.mono { filter: invert(.85) }
  .ic img.hidden { display: none }
  .letter {
    width: 32px; height: 32px; border-radius: 8px; display: grid; place-items: center;
    background: rgba(255, 255, 255, .1); color: var(--text-h); font-weight: 700
  }
  .txt { display: flex; flex-direction: column; min-width: 0 }
  .name { font-size: 13.5px; color: var(--text-h); white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .desc { font-size: 11.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .wf { display: flex; gap: 4px 10px; flex-wrap: wrap; margin-top: 3px; font-size: 11px; color: var(--text); overflow: hidden; max-height: 30px }
  .wf .f { white-space: nowrap }
  .wf i { font-style: normal; color: var(--dim) }
  .wf .lv-warn { color: var(--mid) }
  .wf .lv-err { color: var(--err); overflow: hidden; text-overflow: ellipsis; max-width: 100% }
  .edit { position: absolute; top: 6px; right: 8px; font-size: 11px; color: var(--muted) }
  .tile.up { border-left-color: var(--ok) }
  .tile.down { border-left-color: var(--err); background: rgba(229, 139, 139, .08) }
  .ms { color: var(--text); margin-right: 4px }
  .downtxt { color: var(--err); margin-right: 4px; text-transform: uppercase; font-size: 10.5px; letter-spacing: .06em }
  .spark { position: absolute; left: 56px; right: 12px; bottom: 3px; width: calc(100% - 68px); height: 12px; pointer-events: none }
  .spark path { fill: none; stroke: rgba(255, 255, 255, .22); stroke-width: 1.2; vector-effect: non-scaling-stroke }
  .info {
    position: absolute; top: 4px; right: 4px; border: 0; background: none; color: var(--dim); cursor: pointer;
    font-size: 12px; padding: 2px 5px; border-radius: 5px; opacity: 0; transition: opacity .15s
  }
  .tile:hover .info, .info:focus-visible { opacity: 1 }
  .info:hover { color: var(--text-h); background: rgba(255, 255, 255, .1) }
  @media (hover: none) { .info { opacity: 1 } }
</style>
