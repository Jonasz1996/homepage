<script>
  import Modal from './Modal.svelte'
  import { CHANGELOG } from './changelog.js'

  // Wat is er nieuw: na een update alleen wat je nog niet zag, via Ctrl+K alles.
  let { entries = CHANGELOG, version = null, onclose } = $props()
  const when = (iso) => {
    const d = new Date(iso)
    return isNaN(d) ? '' : d.toLocaleString('nl-BE', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
  }
</script>

<Modal title="wat is er nieuw" wide {onclose}>
  {#if version}
    <p class="ver">
      Geïnstalleerd: <b>{version.versie}</b>{#if version.kanaal}{' · '}{version.kanaal}{/if}{#if version.datum}{' · sinds '}{when(version.datum)}{/if}
    </p>
  {/if}
  {#each entries as e (e.nr)}
    <section class="e">
      <h3>{e.titel} <small>{e.datum}</small></h3>
      <ul>{#each e.items as it}<li>{it}</li>{/each}</ul>
      {#if e.instellen.length}
        <div class="todo">
          <span class="lbl">zelf instellen</span>
          <ul>{#each e.instellen as it}<li>{it}</li>{/each}</ul>
        </div>
      {/if}
    </section>
  {/each}
  <p class="hint">Werkt iets niet meer na een update? Typ <code>homepage-terugzetten</code> in de container: dat zet de vorige
    versie terug, met de database van vlak voor de update.</p>
  <div class="row"><button class="btn" onclick={onclose}>Gezien</button></div>
</Modal>

<style>
  .ver { color: var(--muted); font-size: 12.5px; margin: 0 0 10px }
  .ver b { color: var(--text-h); font-weight: 500 }
  .e { border-top: 1px solid var(--line); padding: 10px 0 4px }
  h3 { margin: 0 0 6px; font-size: 14px; color: var(--text-h); font-weight: 500 }
  h3 small { color: var(--dim); font-weight: 400; margin-left: 6px; font-size: 11.5px }
  ul { margin: 0; padding-left: 18px; font-size: 12.5px; line-height: 1.55 }
  .todo { margin: 8px 0 4px; border: 1px solid rgba(255, 196, 0, .35); border-radius: 8px; padding: 6px 10px; background: rgba(255, 196, 0, .05) }
  .todo .lbl { color: var(--mid); display: block; margin: 0 0 2px }
  .hint { color: var(--muted); font-size: 12px; margin-top: 12px }
  .row { display: flex; justify-content: flex-end }
</style>
