<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import { markdown } from './markdown.js'

  // Eigen notities bij een service: poorten, hoe herstellen, waar de config staat, ...
  let { service, onchanged } = $props()

  let notes = $state(untrack(() => service.notes || ''))
  let draft = $state('')
  let editing = $state(false)
  let error = $state('')

  function edit() {
    draft = notes
    editing = true
  }

  async function save() {
    try {
      const r = await api(`/services/${service.id}/notes`, { method: 'PUT', body: { notes: draft } })
      notes = r.notes || ''
      editing = false
      error = ''
      onchanged?.()
    } catch (e) {
      error = e.message
    }
  }

  function key(e) {
    if (e.key === 's' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      save()
    } else if (e.key === 'Escape') {
      e.stopPropagation()
      editing = false
    }
  }
</script>

<div class="notes">
  <div class="nh">
    <span class="lbl">Notities</span>
    {#if !editing}
      <button class="mini" onclick={edit}>{notes ? '✎' : '+ notitie'}</button>
    {/if}
  </div>
  {#if editing}
    <!-- svelte-ignore a11y_autofocus -->
    <textarea bind:value={draft} onkeydown={key} rows="8" maxlength="20000" autofocus
              placeholder={'## Herstel\n- config staat in /opt/...\n- `systemctl restart ...`\n\nMarkdown werkt: **vet**, `code`, lijstjes, links.'}></textarea>
    <p class="err">{error}</p>
    <div class="row">
      <button class="btn" onclick={save}>Opslaan</button>
      <button class="btn alt" onclick={() => (editing = false)}>Annuleren</button>
      <span class="hint tip">Ctrl+S bewaart. Notities zijn doorzoekbaar met Ctrl+K.</span>
    </div>
  {:else if notes}
    <div class="md">{@html markdown(notes)}</div>
  {/if}
</div>

<style>
  .notes { margin: 0 0 14px }
  .nh { display: flex; align-items: center; gap: 8px }
  .nh .lbl { margin: 0 }
  .tip { margin: 0 }
  .md { padding: 10px 14px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08);
        font-size: 13px; line-height: 1.6; margin-top: 6px; overflow-wrap: anywhere }
  .md :global(h3), .md :global(h4), .md :global(h5), .md :global(h6) { margin: 10px 0 4px; color: var(--text-h); font-size: 13.5px }
  .md :global(:first-child) { margin-top: 0 }
  .md :global(p) { margin: 6px 0 }
  .md :global(ul), .md :global(ol) { margin: 6px 0; padding-left: 22px }
  .md :global(li.task) { list-style: '☐  ' }
  .md :global(li.task.done) { list-style: '☑  '; color: var(--muted) }
  .md :global(code) { background: rgba(255, 255, 255, .08); padding: 1px 5px; border-radius: 5px }
  .md :global(pre) { margin: 8px 0 }
  .md :global(pre code) { background: none; padding: 0 }
  .md :global(a) { color: #a9c7ff }
</style>
