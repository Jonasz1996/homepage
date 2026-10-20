<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'

  // Eigen meldingencentrum: een klein teller-icoon in de titelbalk, uitklapbaar paneel.
  let open = $state(false)
  let data = $state({ unread: 0, items: [] })

  const fmt = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })

  async function load() {
    try { data = await api('/notifications') } catch { /* stil falen, volgende poging komt */ }
  }

  async function toggle() {
    open = !open
    if (open) await load()
  }

  async function readAll() {
    await api('/notifications/read-all', { method: 'POST' })
    await load()
  }

  async function clearRead() {
    await api('/notifications', { method: 'DELETE' })
    await load()
  }

  onMount(() => {
    load()
    return poll(load, 30000)
  })
</script>

<span class="wrapn">
  <button class="mini bell" class:has={data.unread > 0} onclick={toggle} aria-label="Meldingen" aria-expanded={open}>
    ◉{#if data.unread > 0}<b>{data.unread}</b>{/if}
  </button>
  {#if open}
    <div class="panel card">
      <div class="head">
        <span>meldingen</span>
        <button class="mini" onclick={readAll}>alles gelezen</button>
        <button class="mini x" onclick={clearRead}>wis gelezen</button>
      </div>
      <div class="items">
        {#each data.items as n (n.id)}
          <div class="n {n.level}" class:unread={!n.read}>
            <div class="t"><span class="lvl">{n.level}</span>{n.title}</div>
            {#if n.body}<div class="b">{n.body}</div>{/if}
            <div class="ts">{fmt(n.ts)} · {n.source}</div>
          </div>
        {:else}
          <p class="empty">Geen meldingen.</p>
        {/each}
      </div>
    </div>
  {/if}
</span>

<style>
  .wrapn { position: relative }
  .bell { padding: 3px 8px; color: var(--dim) }
  .bell.has { color: var(--mid) }
  .bell b { margin-left: 4px; color: var(--text-h); font-size: 11px }
  .panel {
    position: fixed; top: 64px; right: max(14px, calc((100vw - 1240px) / 2 + 14px)); width: min(380px, calc(100vw - 28px));
    z-index: 70; white-space: normal; padding: 10px; color: var(--text); text-align: left
  }
  .head { display: flex; gap: 6px; align-items: center; margin-bottom: 8px; font-size: 12px; color: var(--muted) }
  .head span { flex: 1 }
  .items { max-height: 60vh; overflow: auto }
  .n {
    padding: 8px 10px; margin-bottom: 6px; border-radius: 8px; background: var(--fill);
    border: 1px solid rgba(255, 255, 255, .06); border-left: 3px solid #666; font-size: 12.5px; opacity: .6
  }
  .n.unread { opacity: 1 }
  .n.ok { border-left-color: var(--ok) }
  .n.warn { border-left-color: var(--mid) }
  .n.err { border-left-color: var(--err) }
  .lvl { font-size: 10.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); margin-right: 8px }
  .n.warn .lvl { color: var(--mid) }
  .n.err .lvl { color: var(--err) }
  .n.ok .lvl { color: var(--ok) }
  .b { white-space: pre-line; color: #bbb; margin-top: 3px }
  .ts { color: var(--dim); font-size: 11px; margin-top: 4px }
  .empty { color: var(--muted); font-size: 12.5px; margin: 6px }
</style>
