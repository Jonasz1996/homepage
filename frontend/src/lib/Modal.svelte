<script>
  import Card from './Card.svelte'

  let { title, onclose, children, wide = false } = $props()

  function key(e) {
    if (e.key === 'Escape') onclose()
  }
</script>

<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="ov" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="box" class:wide role="dialog" aria-modal="true">
    <Card {title} glow>
      {#snippet right()}<button class="mini x" onclick={onclose} aria-label="Sluiten">✕</button>{/snippet}
      <div class="body">{@render children()}</div>
    </Card>
  </div>
</div>

<style>
  .ov {
    position: fixed; inset: 0; z-index: 65; display: flex; align-items: flex-start; justify-content: center;
    padding: 6vh 14px; background: rgba(0, 0, 0, .6); overflow: auto;
  }
  .box { width: 100%; max-width: 640px }
  .box.wide { max-width: 860px }
</style>
