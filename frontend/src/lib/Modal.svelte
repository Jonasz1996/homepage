<script module>
  // Alleen het bovenste venster reageert op Escape (bv. de 2FA-vraag boven een ander venster).
  const stack = []
</script>

<script>
  import { onMount, tick } from 'svelte'
  import Card from './Card.svelte'
  import { layer } from './nav.js'

  // small: een korte vraag (bevestigen, één veld); op de gsm dan niet schermvullend.
  let { title, onclose, children, wide = false, small = false } = $props()
  const me = {}
  let box = $state()
  let ov = $state()

  onMount(() => {
    stack.push(me)
    // De terugknop van de gsm sluit dit venster.
    const release = layer(() => onclose())
    const before = document.activeElement
    tick().then(() => {
      if (box && !box.contains(document.activeElement)) box.querySelector('input, select, textarea, button:not(.x)')?.focus({ preventScroll: true })
    })
    return () => {
      stack.splice(stack.indexOf(me), 1)
      release()
      if (before && document.contains(before)) before.focus?.({ preventScroll: true })
    }
  })

  function key(e) {
    if (e.key !== 'Escape' || stack.at(-1) !== me) return
    // Ook niet als er een groot venster boven dit venster ligt (bv. de terminal, geopend vanuit een cronjob): elk
    // venster bedekt het hele scherm, dus wat linksboven ligt, ligt bovenaan.
    const top = document.elementFromPoint(0, 0)?.closest('.ov')
    if (top && top !== ov) return
    onclose()
  }
</script>


<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="ov" class:small bind:this={ov} onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="box" class:wide class:small role="dialog" aria-modal="true" aria-label={title} bind:this={box}>
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
  .box.small { max-width: 460px; margin-top: 8vh }
  /* Op de gsm schermvullend, met ruimte voor de notch en de navigatiebalk. Een korte vraag blijft een kaart. */
  @media (max-width: 600px) {
    .ov:not(.small) { padding: env(safe-area-inset-top) 0 0; align-items: stretch }
    .box:not(.small) { max-width: none; min-height: 100% }
    .box:not(.small) :global(.card) { border-radius: 0; min-height: 100%; padding-bottom: env(safe-area-inset-bottom) }
    .box :global(.body) { padding-left: 14px; padding-right: 14px }
    .ov.small { padding: calc(env(safe-area-inset-top) + 12px) 12px 12px }
    .box.small { margin-top: 12vh }
  }
</style>
