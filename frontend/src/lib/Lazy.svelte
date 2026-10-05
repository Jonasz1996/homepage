<script>
  // Laadt een venster pas als je het opent: de eerste lading van het dashboard blijft klein.
  let { load, ...rest } = $props()
</script>

{#await load() then m}
  <m.default {...rest} />
{:catch}
  <div class="lazyerr" role="alert">
    Er is een nieuwe versie van de homepage. <button class="mini" onclick={() => location.reload()}>herladen</button>
  </div>
{/await}

<style>
  .lazyerr { position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%); z-index: 90; padding: 10px 14px;
             border-radius: 10px; background: var(--fill, #222); border: 1px solid var(--line-2, #444); font-size: 13px;
             display: flex; gap: 10px; align-items: center }
</style>
