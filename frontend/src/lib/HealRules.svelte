<script>
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'

  // Zelfherstel voor één service: "als hij N checks na elkaar down is, voer deze actie uit", met een limiet per uur.
  let { service } = $props()

  let rules = $state([])
  let actions = $state(null)
  let hosts = $state([])
  let adding = $state(false)
  let msg = $state('')
  let form = $state({ after: 3, max_per_hour: 2, pick: '', op: 'systemctl', host_id: null, name: '' })

  async function load() {
    try { rules = await api(`/heal?service_id=${service.id}`) } catch (e) { msg = e.message }
  }
  untrack(load)

  async function startAdd() {
    adding = true
    msg = ''
    if (!actions) {
      try {
        const [a, h] = await Promise.all([api('/actions'), api('/ssh/hosts')])
        // Alleen acties die iets herstarten of starten; de naam van deze service eerst.
        const n = service.name.toLowerCase()
        actions = a.filter((x) => !x.endpoint && /reboot|restart|start|herstart/i.test(`${x.id} ${x.label}`))
          .sort((x, y) => (String(y.target).toLowerCase().includes(n) - String(x.target).toLowerCase().includes(n)))
        hosts = h
      } catch (e) { msg = e.message; actions = [] }
    }
  }

  function action() {
    if (form.pick === 'ssh') return { kind: 'ssh', host_id: Number(form.host_id), op: form.op, name: form.name.trim() }
    const a = actions[Number(form.pick)]
    return { kind: 'integration', service_id: a.service_id, action: a.id, params: a.params || {},
             label: `${a.label} ${a.target || ''}`.trim() }
  }

  async function save() {
    msg = ''
    try {
      await withReauth(() => api('/heal', { method: 'POST', body: { service_id: service.id, after: Number(form.after),
                                                                   max_per_hour: Number(form.max_per_hour), action: action() } }))
      adding = false
      await load()
    } catch (e) { msg = e.message }
  }

  async function toggle(r) {
    try {
      await withReauth(() => api(`/heal/${r.id}`, { method: 'PUT', body: { service_id: r.service_id, enabled: !r.enabled, after: r.after,
                                                                         max_per_hour: r.max_per_hour, action: r.action } }))
      await load()
    } catch (e) { msg = e.message }
  }

  async function test(r) {
    if (!confirm(`Nu uitvoeren: ${r.describe}?`)) return
    try { msg = '✓ ' + (await withReauth(() => api(`/heal/${r.id}/test`, { method: 'POST' }))).message } catch (e) { msg = '✕ ' + e.message }
  }

  async function remove(r) {
    if (!confirm(`Regel "${r.describe}" verwijderen?`)) return
    try { await withReauth(() => api(`/heal/${r.id}`, { method: 'DELETE' })); await load() } catch (e) { msg = e.message }
  }

  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  let valid = $derived(form.pick === 'ssh' ? form.host_id && /^[A-Za-z0-9@._:-]+$/.test(form.name.trim()) : form.pick !== '')
</script>

<div class="heal">
  <span class="lbl">Zelfherstel</span>
  {#each rules as r (r.id)}
    <div class="rule" class:off={!r.enabled}>
      <span class="what">als <b>{r.after}×</b> down → <b>{r.describe}</b> <small>(max. {r.max_per_hour}× per uur)</small></span>
      {#if r.last_at}<small class="res" class:e={r.last_result?.startsWith('mislukt') || r.last_result?.startsWith('limiet')}>
        laatst {when(r.last_at)}: {r.last_result}</small>{/if}
      <span class="btns">
        <button class="mini" onclick={() => toggle(r)}>{r.enabled ? 'uitzetten' : 'aanzetten'}</button>
        <button class="mini" onclick={() => test(r)}>nu testen</button>
        <button class="mini" onclick={() => remove(r)} aria-label="Regel verwijderen">✕</button>
      </span>
    </div>
  {/each}
  {#if adding}
    <div class="form">
      <label>als down na <input type="number" min="1" max="60" bind:value={form.after} /> checks</label>
      <select bind:value={form.pick} aria-label="Actie">
        <option value="">— kies een actie —</option>
        {#each actions || [] as a, i}<option value={String(i)}>{a.service}: {a.label} {a.target || ''}</option>{/each}
        <option value="ssh">via SSH: dienst of container herstarten…</option>
      </select>
      {#if form.pick === 'ssh'}
        <div class="row">
          <select bind:value={form.host_id} aria-label="Host">
            <option value={null}>— host —</option>
            {#each hosts as h}<option value={h.id}>{h.name}</option>{/each}
          </select>
          <select bind:value={form.op} aria-label="Soort"><option value="systemctl">systemctl restart</option><option value="docker">docker restart</option></select>
          <input bind:value={form.name} placeholder={form.op === 'docker' ? 'containernaam' : 'dienst, bv. plexmediaserver'} />
        </div>
      {/if}
      <label>hoogstens <input type="number" min="1" max="6" bind:value={form.max_per_hour} /> keer per uur, minstens 10 min ertussen</label>
      <div class="row">
        <button class="btn" disabled={!valid} onclick={save}>regel bewaren</button>
        <button class="mini" onclick={() => (adding = false)}>annuleren</button>
      </div>
    </div>
  {:else}
    <button class="mini add" onclick={startAdd}>+ regel</button>
    {#if !rules.length}<small class="m">bv. "als {service.name} 3× down is, herstart zijn container". Je krijgt altijd een melding van wat er gebeurde.</small>{/if}
  {/if}
  {#if msg}<p class="msg" class:e={msg.startsWith('✕')}>{msg}</p>{/if}
</div>

<style>
  .heal { margin-top: 14px }
  .lbl { display: block; margin-bottom: 4px }
  .rule { display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; padding: 6px 8px; border-radius: 9px; background: var(--fill); margin-bottom: 4px; font-size: 12.5px }
  .rule.off { opacity: .55 }
  .what { flex: 1; min-width: 200px }
  .what b { font-weight: 500; color: var(--text-h) }
  .what small, .m { color: var(--muted); font-size: 11.5px }
  .res { flex-basis: 100%; color: var(--muted); font-size: 11.5px }
  .btns { display: flex; gap: 4px }
  .e { color: var(--err) !important }
  .form { display: flex; flex-direction: column; gap: 8px; padding: 10px; border: 1px solid var(--line); border-radius: 10px; font-size: 12.5px }
  .form label { display: flex; gap: 6px; align-items: center; color: var(--muted) }
  .form label input { width: 64px }
  .row { display: flex; gap: 6px; flex-wrap: wrap; align-items: center }
  .row input { flex: 1; min-width: 160px }
  .add { margin-right: 8px }
  .msg { font-size: 12px; color: var(--ok); margin: 6px 0 0 }
</style>
