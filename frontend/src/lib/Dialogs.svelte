<script>
  import { answer, dialogs } from './dialog.svelte.js'
  import Modal from './Modal.svelte'

  // Eén plek voor alle vragen van ask() en askText(), boven elk ander venster.
  let values = $state({})

  function submit(e, d) {
    e.preventDefault()
    answer(d, d.kind === 'text' ? (values[d.id] ?? d.value) : true)
  }
  const cancel = (d) => answer(d, d.kind === 'text' ? null : false)
  // Bij iets dat niet terug kan (rood), staat de focus op Annuleren: een Enter te veel verwijdert dan niets.
  const safeFocus = (node, on) => { if (on) queueMicrotask(() => node.focus({ preventScroll: true })) }
</script>

{#each dialogs.list as d (d.id)}
  <Modal title={d.title || (d.kind === 'text' ? 'read -p' : 'bevestigen')} small onclose={() => cancel(d)}>
    <form onsubmit={(e) => submit(e, d)}>
      <p class="q">{d.text}</p>
      {#if d.kind === 'text'}
        <input value={values[d.id] ?? d.value} oninput={(e) => (values[d.id] = e.currentTarget.value)}
               type={d.type || 'text'} inputmode={d.inputmode} placeholder={d.placeholder} aria-label={d.text} />
      {/if}
      <div class="row">
        <button class="btn" class:danger={d.danger}>{d.ok || 'OK'}</button>
        <button type="button" class="btn alt" onclick={() => cancel(d)} use:safeFocus={d.danger && d.kind !== 'text'}>Annuleren</button>
      </div>
    </form>
  </Modal>
{/each}

<style>
  .q { margin: 0 0 14px; white-space: pre-line; line-height: 1.55; color: var(--text) }
  input { margin-bottom: 14px }
  .btn.danger { background: #a84a4a }
  .btn.danger:hover { background: #c05656 }
</style>
