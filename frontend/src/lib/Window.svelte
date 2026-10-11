<script>
  import { layer } from './nav.js'

  // Groot venster over het hele scherm (terminal, logs, cron, gezondheid, API-beheer). Blijft geladen als het dicht is
  // (open = false), zodat bv. terminalsessies doorlopen. label: de leesbare naam ("Cron"), ook voor "Cron sluiten".
  // actions: knoppen rechts in de titelbalk; ✕ staat er altijd naast, ook als die knoppen op de gsm niet passen.
  let { open = true, title, label, prompt = 'root@jbogaert:~#', onclose, actions = null, children } = $props()

  // De terugknop van de gsm sluit het venster.
  $effect(() => {
    if (!open) return
    return layer(() => onclose())
  })
</script>

<div class="ov" class:hidden={!open}>
  <div class="win card glow" role="dialog" aria-modal="true" aria-label={label}>
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">{prompt} {title}</span>
      {#if actions}<div class="right acts">{@render actions()}</div>{/if}
      <button class="mini x" onclick={onclose} aria-label="{label} sluiten">✕</button>
    </div>
    {@render children()}
  </div>
</div>

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-width: 0; min-height: 0; overflow: hidden }
  .bar .x { flex: none }
  /* Te veel knoppen voor de breedte: dan krimpt de rij en schuiven ze, en blijft ✕ staan. .bar .acts wint van de
     globale .bar .right { flex: none }, die de rij anders op volle breedte houdt en ✕ uit beeld duwt. */
  .bar .acts { flex: 0 1 auto; min-width: 0; overflow-x: auto; scrollbar-width: none }
  .acts::-webkit-scrollbar { display: none }
  /* De knoppen zelf houden hun breedte (.mini heeft overflow: hidden en zou anders afgekapt worden). */
  .acts > :global(*) { flex-shrink: 0 }
  /* Op de gsm schermvullend, met ✕ onder de statusbalk en boven de navigatiebalk. */
  @media (max-width: 600px) {
    .ov { padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left) }
    .win { border-radius: 0 }
    .bar { border-radius: 0 }
    .bar .title { display: none }
    /* Zonder titel duwt niets meer naar rechts: dat doen de knoppen, of zonder knoppen ✕ zelf. */
    .acts, .title + .x { margin-left: auto }
  }
</style>
