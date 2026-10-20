<script module>
  // Alleen het bovenste venster reageert op Escape (bv. de 2FA-vraag boven een ander venster).
  const stack = []
</script>

<script>
  import { onMount, tick } from 'svelte'
  import Card from './Card.svelte'

  let { title, onclose, children, wide = false } = $props()
  const me = {}
  let box = $state()

  onMount(() => {
    stack.push(me)
    const before = document.activeElement
    tick().then(() => {
      if (box && !box.contains(document.activeElement)) box.querySelector('input, select, textarea, button:not(.x)')?.focus({ preventScroll: true })
    })
    return () => {
      stack.splice(stack.indexOf(me), 1)
      if (before && document.contains(before)) before.focus?.({ preventScroll: true })
    }
  })

  function key(e) {
    if (e.key === 'Escape' && stack.at(-1) === me) onclose()
  }
</script>


<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="ov" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="box" class:wide role="dialog" aria-modal="true" aria-label={title} bind:this={box}>
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
  .box { width: 100%; max-width: 640px; transition: transform .15s ease-out }
  .box.wide { max-width: 860px }
  /* Op de gsm schermvullend, met ruimte voor de notch en de navigatiebalk. */
  @media (max-width: 600px) {
    .ov { padding: env(safe-area-inset-top) 0 0; align-items: stretch }
    .box, .box.wide { max-width: none; min-height: 100% }
    .box :global(.card) { border-radius: 0; min-height: 100%; padding-bottom: env(safe-area-inset-bottom) }
    .box :global(.body) { padding-left: 14px; padding-right: 14px }
  }
</style>
