<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Meldingsregels: een logregel die overeenkomt, verschijnt in het meldingencentrum.
  let { hosts = [], onclose } = $props()

  const SEV = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
  const blank = () => ({ name: '', pattern: '', host: '', max_severity: 7, level: 'warn', cooldown_minutes: 10, enabled: true })

  let rules = $state([])
  let form = $state(null)
  let error = $state('')

  async function load() {
    rules = await api('/logs/rules')
  }
  onMount(load)

  async function save(e) {
    e.preventDefault()
    error = ''
    const body = { ...form, pattern: form.pattern || null, host: form.host || null, cooldown_minutes: Number(form.cooldown_minutes) || 0 }
    try {
      if (form.id) await api(`/logs/rules/${form.id}`, { method: 'PATCH', body })
      else await api('/logs/rules', { method: 'POST', body })
      form = null
      await load()
    } catch (err) {
      error = err.message
    }
  }

  async function toggle(r) {
    await api(`/logs/rules/${r.id}`, { method: 'PATCH', body: { ...r, enabled: !r.enabled } })
    await load()
  }

  async function del(r) {
    if (!confirm(`Regel '${r.name}' verwijderen?`)) return
    await api(`/logs/rules/${r.id}`, { method: 'DELETE' })
    await load()
  }
</script>

<Modal title="grep -E … | notify" {onclose} wide>
  <table class="tbl">
    <thead><tr><th>naam</th><th>patroon</th><th>machine</th><th>vanaf</th><th></th></tr></thead>
    <tbody>
      {#each rules as r (r.id)}
        <tr class:off={!r.enabled}>
          <td>{r.name}</td>
          <td><code>{r.pattern || '(alles)'}</code></td>
          <td>{r.host || 'alle'}</td>
          <td>{SEV[r.max_severity]}</td>
          <td class="acts">
            <button class="mini" onclick={() => toggle(r)}>{r.enabled ? 'uit' : 'aan'}</button>
            <button class="mini" onclick={() => (form = { ...r, pattern: r.pattern || '', host: r.host || '' })}>✎</button>
            <button class="mini x" onclick={() => del(r)}>✕</button>
          </td>
        </tr>
      {:else}
        <tr><td colspan="5" class="m">Nog geen regels.</td></tr>
      {/each}
    </tbody>
  </table>

  {#if form}
    <form onsubmit={save} class="f">
      <div class="grid">
        <div>
          <label class="lbl" for="lr-name">Naam</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input id="lr-name" bind:value={form.name} required maxlength="80" autofocus placeholder="SSH-aanvallen" />
        </div>
        <div>
          <label class="lbl" for="lr-pat">Patroon (regex, hoofdletterongevoelig)</label>
          <input id="lr-pat" bind:value={form.pattern} maxlength="500" placeholder="Failed password|Invalid user" />
        </div>
        <div>
          <label class="lbl" for="lr-host">Machine</label>
          <input id="lr-host" bind:value={form.host} list="lr-hosts" placeholder="alle" />
          <datalist id="lr-hosts">{#each hosts as h}<option value={h}></option>{/each}</datalist>
        </div>
        <div>
          <label class="lbl" for="lr-sev">Vanaf ernst</label>
          <select id="lr-sev" bind:value={form.max_severity}>
            {#each SEV as s, i}<option value={i}>{s}{i === 7 ? ' (alles)' : ' en erger'}</option>{/each}
          </select>
        </div>
        <div>
          <label class="lbl" for="lr-lvl">Melding als</label>
          <select id="lr-lvl" bind:value={form.level}>
            <option value="info">info</option><option value="warn">waarschuwing</option><option value="err">fout</option>
          </select>
        </div>
        <div>
          <label class="lbl" for="lr-cd">Niet vaker dan elke … minuten (per machine)</label>
          <input id="lr-cd" bind:value={form.cooldown_minutes} inputmode="numeric" />
        </div>
      </div>
      <p class="err">{error}</p>
      <div class="row">
        <button class="btn">Opslaan</button>
        <button type="button" class="btn alt" onclick={() => (form = null)}>Annuleren</button>
      </div>
    </form>
  {:else}
    <button class="mini add" onclick={() => (form = blank())}>+ regel</button>
  {/if}
</Modal>

<style>
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05) }
  .tbl tr.off td { opacity: .45 }
  .tbl code { color: #d6e6ff }
  .acts { text-align: right; white-space: nowrap }
  .m { color: var(--dim) }
  .add { margin-top: 12px }
  .f { margin-top: 14px; border-top: 1px solid var(--line); padding-top: 10px }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px }
  @media (max-width: 560px) { .grid { grid-template-columns: 1fr } }
</style>
