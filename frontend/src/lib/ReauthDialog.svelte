<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Vraagt de 2FA-code voor een gevoelige actie (terminal openen, sleutel toevoegen, ...).
  let pending = $state(null)
  let code = $state('')
  let error = $state('')
  // Vraagt intussen nog iets een code (twee uploads tegelijk): één code beantwoordt ze allemaal.
  let more = []

  onMount(() => {
    const h = (e) => {
      if (pending) { more.push(e.detail); return }
      pending = e.detail
      code = ''
      error = ''
    }
    window.addEventListener('hp:reauth', h)
    return () => window.removeEventListener('hp:reauth', h)
  })

  async function submit(e) {
    e.preventDefault()
    try {
      await api('/auth/reauth', { method: 'POST', body: { code } })
      const all = [pending, ...more.splice(0)]
      pending = null
      all.forEach((p) => p.resolve())
    } catch (err) {
      error = err.message
    }
  }
  function cancel() {
    const all = [pending, ...more.splice(0)]
    pending = null
    all.forEach((p) => p.reject(new Error('Geannuleerd')))
  }
</script>

{#if pending}
  <Modal title="sudo -v" onclose={cancel}>
    <form onsubmit={submit}>
      <p class="hint">Bevestig met je 2FA-code. Daarna vraagt het dashboard 15 minuten niets meer.</p>
      <label class="lbl" for="ra-code">Code</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="ra-code" bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus />
      <p class="err">{error}</p>
      <div class="row">
        <button class="btn">Bevestigen</button>
        <button type="button" class="btn alt" onclick={cancel}>Annuleren</button>
      </div>
    </form>
  </Modal>
{/if}
