<script>
  import { copyText } from './copy.js'

  // Een commando om over te nemen in een shell, met een knop om het te kopiëren.
  let { cmd } = $props()
  let done = $state(false)
  async function copy() {
    done = await copyText(cmd)
    if (done) setTimeout(() => (done = false), 1500)
  }
</script>

<div class="cmd"><code>{cmd}</code><button class="mini" onclick={copy}>{done ? '✓' : 'kopieer'}</button></div>

<style>
  .cmd { display: flex; gap: 8px; align-items: flex-start; margin: 4px 0 }
  code { flex: 1; min-width: 0; font-size: 12px; padding: 5px 8px; border-radius: 6px; background: rgba(0, 0, 0, .3);
         border: 1px solid var(--line); white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text-h) }
  .mini { flex-shrink: 0 }
</style>
