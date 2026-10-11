<script>
  // Tabbladen van een venster: één rij knoppen met een teller of bolletje per tabblad.
  // items: [{ key, label, count?, level?: 'err' | 'warn' | 'ok', dot?: 'err' | 'warn' | 'ok', title? }]
  // badge: eigen inhoud na het label (krijgt het item); extra: wat rechts in de rij staat (knoppen, filters).
  // pad: binnenmarge zoals in de grote vensters.
  let { items, value = $bindable(), onselect = null, badge = null, extra = null, pad = false, label = 'Tabbladen' } = $props()

  function pick(t) {
    value = t.key
    onselect?.(t.key)
  }
</script>

<div class="tabs" class:pad role="tablist" aria-label={label}>
  {#each items as t (t.key)}
    <button class="mini" class:on={value === t.key} role="tab" aria-selected={value === t.key} title={t.title}
            onclick={() => pick(t)}>{t.label}{#if t.count}<b class="n {t.level || ''}">{t.count}</b>{/if}{#if t.dot}<i class="dot {t.dot}"></i>{/if}{#if badge}{@render badge(t)}{/if}</button>
  {/each}
  {#if extra}<span class="sp"></span>{@render extra()}{/if}
</div>

<style>
  .tabs { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 12px }
  .tabs.pad { padding: 10px 12px 0; margin-bottom: 0 }
  .sp { flex: 1 }
  .n { margin-left: 5px; color: var(--text-h); font-size: 11px; font-weight: 500 }
  .n.err { color: var(--err) }
  .n.warn { color: var(--mid) }
  .n.ok { color: var(--ok) }
  .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin: 0 0 1px 6px; vertical-align: middle; background: var(--muted) }
  .dot.ok { background: var(--ok) }
  .dot.warn { background: var(--mid) }
  .dot.err { background: var(--err) }
</style>
