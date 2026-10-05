<script>
  import { onMount } from 'svelte'
  import { api, OUTSIDE, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Verschijnt als iets van buitenaf uit staat (de server antwoordde "buiten:<functie>"): voor één uur aanzetten,
  // of naar de instellingen.
  let { onsettings } = $props()
  let feature = $state(null)
  let done = $state('')
  let error = $state('')

  onMount(() => {
    const h = (e) => { feature = e.detail.feature; done = ''; error = '' }
    window.addEventListener('hp:outside', h)
    return () => window.removeEventListener('hp:outside', h)
  })

  async function hour() {
    error = ''
    try {
      const r = await withReauth(() => api(`/outside/features/${feature}`, { method: 'PUT', body: { mode: 'uur' } }))
      const f = r.features.find((x) => x.key === feature)
      done = `Staat aan tot ${new Date(f.until).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })}. Probeer het opnieuw.`
    } catch (e) { error = e.message }
  }
</script>

{#if feature}
  <Modal title="van buitenaf" onclose={() => (feature = null)}>
    <p>Je bent van buitenaf verbonden (via Cloudflare of een publiek IP). Dan staat <b>{OUTSIDE[feature] || feature}</b> uit,
      zodat wie je login zou overnemen er niets mee kan. Kijken kan wel.</p>
    {#if done}
      <p class="ok">✓ {done}</p>
    {:else}
      <p class="hint">Heb je het nu echt nodig? Zet het voor één uur aan met je 2FA-code. Je krijgt er een melding van.</p>
    {/if}
    <p class="err">{error}</p>
    <div class="row">
      {#if !done}<button class="btn" onclick={hour}>Eén uur aanzetten</button>{/if}
      <button class="btn alt" onclick={() => { feature = null; onsettings() }}>Instellingen</button>
      <button class="btn alt" onclick={() => (feature = null)}>{done ? 'Sluiten' : 'Niet nu'}</button>
    </div>
  </Modal>
{/if}
