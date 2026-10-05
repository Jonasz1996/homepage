<script>
  // Het antwoord van een API als boom. Klik op een waarde om er een veld van te maken; bij een lijst kan je
  // het aantal tonen of er een tabel van maken. Paden zijn met punten: records.0.title.
  let { data, onpick, used = new Set() } = $props()

  // Tot twee niveaus diep open; wat je aanklikt, klapt om.
  let flip = $state(new Set())
  const join = (p, k) => (p === '' ? String(k) : `${p}.${k}`)
  const isObj = (v) => v !== null && typeof v === 'object'
  const shut = (p, depth) => (depth >= 2) !== flip.has(p)
  function toggle(p) {
    const s = new Set(flip)
    s.has(p) ? s.delete(p) : s.add(p)
    flip = s
  }
  const entries = (v) => (Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v))
  const show = (v) => (typeof v === 'string' ? `"${v.length > 80 ? v.slice(0, 80) + '…' : v}"` : JSON.stringify(v))
</script>

{#snippet node(k, v, p, depth)}
  {#if isObj(v)}
    {@const arr = Array.isArray(v)}
    {@const closed = shut(p, depth)}
    <div class="n">
      <div class="h">
        <button class="k" onclick={() => toggle(p)} aria-expanded={!closed}>{closed ? '▸' : '▾'} {k}</button>
        <span class="t">{arr ? `[${v.length}]` : `{${Object.keys(v).length}}`}</span>
        {#if arr}
          <button class="pk" class:on={used.has('#' + p)} onclick={() => onpick(p, v, 'count')} title="Het aantal items als veld">#&nbsp;aantal</button>
          <button class="pk" class:on={used.has('▦' + p)} onclick={() => onpick(p, v, 'table')} title="Deze lijst als tabel in het mini dashboard">▦&nbsp;tabel</button>
        {/if}
      </div>
      {#if !closed}
        <div class="ch">
          {#each entries(v) as [ck, cv] (ck)}{@render node(ck, cv, join(p, ck), depth + 1)}{/each}
          {#if !entries(v).length}<span class="t">leeg</span>{/if}
        </div>
      {/if}
    </div>
  {:else}
    <button class="leaf" class:on={used.has(p)} onclick={() => onpick(p, v, 'value')} title={p}>
      <span class="k">{k}</span><span class="v {v === null ? 'null' : typeof v}">{show(v)}</span>
    </button>
  {/if}
{/snippet}

<div class="tree">
  {#if isObj(data)}{@render node('antwoord', data, '', 0)}{:else}<pre>{String(data)}</pre>{/if}
</div>

<style>
  .tree { font-family: var(--mono, monospace); font-size: 12px; line-height: 1.55 }
  .ch { padding-left: 14px; border-left: 1px solid var(--line); margin-left: 5px }
  .h { display: flex; gap: 6px; align-items: center; flex-wrap: wrap }
  .k, .leaf, .pk { all: unset; cursor: pointer }
  .k { color: var(--text-h) }
  .t { color: var(--dim); font-size: 11px }
  .pk { font-size: 10.5px; padding: 0 6px; border-radius: 6px; border: 1px solid var(--line-2); color: var(--muted) }
  .pk:hover, .pk.on { color: var(--text-h); border-color: var(--accent, #7aa2ff) }
  .leaf { display: flex; gap: 8px; padding: 0 4px; border-radius: 5px; max-width: 100%; overflow: hidden }
  .leaf:hover { background: var(--fill-h) }
  .leaf.on { background: rgba(122, 162, 255, .16) }
  .leaf .k { color: var(--muted); flex: none }
  .v { white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .v.string { color: #b5e8a8 }
  .v.number { color: #ffd38a }
  .v.boolean, .v.null { color: #f0a8ff }
  pre { white-space: pre-wrap; margin: 0 }
</style>
