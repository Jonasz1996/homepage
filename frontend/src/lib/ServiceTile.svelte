<script>
  import { iconIsMono, iconUrl } from './icons.js'

  let { service, editing = false, onedit, dragging = false, dropBefore = false, ...events } = $props()

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
  href={service.url || undefined}
  target="_blank"
  rel="noopener noreferrer"
  draggable={editing}
  title={service.description || host || service.name}
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
    <span class="desc">{service.description || host}</span>
  </span>
  {#if editing}<span class="edit" aria-hidden="true">✎</span>{/if}
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
  .edit { position: absolute; top: 6px; right: 8px; font-size: 11px; color: var(--muted) }
</style>
