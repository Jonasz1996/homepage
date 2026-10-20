<script>
  import { AREA } from './attention.js'
  import { dash } from './dash.svelte.js'

  // De strook bovenaan: de rode en oranje punten uit Aandacht; ✕ verbergt ze tot er iets verandert.
  let urgent = $derived(dash.att.items.filter((i) => i.level !== 'info'))
  let stripId = $derived(hash(urgent.map((i) => i.key + i.sig).join('|')))
  let hidden = $state(read())

  function read() {
    try { return localStorage.getItem('hp:att-hide') || '' } catch { return '' }
  }
  function hide() {
    hidden = stripId
    try { localStorage.setItem('hp:att-hide', stripId) } catch { /* privé-venster */ }
  }
  function hash(s) {
    let h = 0
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0
    return String(h >>> 0)
  }
</script>

{#if urgent.length && hidden !== stripId}
  <div class="attn" role="region" aria-label="Aandacht">
    {#each urgent.slice(0, 4) as i (i.key)}
      <button class="ai lv-{i.level}" onclick={() => dash.openFix(i.fix)}>
        <i></i><b>{i.title}</b><span class="area">{AREA[i.area] || i.area}</span>{#if i.text}<small>{i.text}</small>{/if}
      </button>
    {/each}
    <div class="aend">
      <button class="mini" onclick={() => dash.open('attention')}>{urgent.length > 3 ? `alle ${urgent.length} bekijken` : 'aandacht'}</button>
      <button class="mini x" onclick={hide} title="Verbergen tot er iets verandert" aria-label="Verbergen">✕</button>
    </div>
  </div>
{/if}

<style>
  .attn { display: flex; flex-direction: column; gap: 4px; padding: 0 24px 14px }
  .ai { all: unset; cursor: pointer; display: flex; gap: 8px; align-items: baseline; padding: 6px 10px; border-radius: 9px;
        border: 1px solid var(--line); border-left: 3px solid var(--mid); background: var(--fill); min-width: 0; font-size: 12.5px }
  .ai:hover, .ai:focus-visible { background: var(--fill-h) }
  .ai.lv-err { border-left-color: var(--err) }
  .ai i { width: 7px; height: 7px; border-radius: 50%; background: var(--mid); flex-shrink: 0; align-self: center }
  .ai.lv-err i { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .ai b { color: var(--text-h); font-weight: 500; white-space: nowrap }
  .ai .area { font-size: 11px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: var(--muted) }
  .ai small { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0 }
  .aend { display: flex; gap: 6px; justify-content: flex-end }
  @media (max-width: 560px) {
    .attn { padding-left: 16px; padding-right: 16px }
    .ai { flex-wrap: wrap }
    .ai:nth-child(n+4) { display: none }
    .ai b { white-space: normal }
  }
</style>
