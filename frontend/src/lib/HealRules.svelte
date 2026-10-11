<script>
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import ProefPlan from './ProefPlan.svelte'

  // Zelfherstel voor één service: "als hij N checks na elkaar down is, voer deze actie uit", met een limiet per uur.
  // "proef" toont wat een regel zou doen (welke machine, welke call of welk commando), zonder iets uit te voeren.
  // Een regel op "alleen proef" gaat automatisch af zoals altijd, maar zet alleen op de tijdlijn wat hij zou doen.
  let { service } = $props()

  let rules = $state([])
  let actions = $state(null)
  let hosts = $state([])
  let adding = $state(false)
  let msg = $state('')
  let form = $state({ after: 3, max_per_hour: 2, pick: '', op: 'systemctl', host_id: null, name: '', dry_run: false })
  // De laatste proef: { key: id van de regel of 'form', plan }.
  let proef = $state(null)
  let busy = $state(null)

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

  const body = () => ({ service_id: service.id, after: Number(form.after), max_per_hour: Number(form.max_per_hour),
                        dry_run: form.dry_run, action: action() })

  async function save() {
    msg = ''
    try {
      await withReauth(() => api('/heal', { method: 'POST', body: body() }))
      adding = false
      proef = null
      await load()
    } catch (e) { msg = e.message }
  }

  // Proef: alleen kijken, er gebeurt niets. Daarom geen bevestiging en geen 2FA.
  async function tryOut(key, call) {
    msg = ''
    proef = null
    busy = key
    try { proef = { key, plan: await call() } } catch (e) { msg = '✕ ' + e.message } finally { busy = null }
  }
  const tryRule = (r) => tryOut(r.id, () => api(`/heal/${r.id}/proef`, { method: 'POST' }))
  const tryForm = () => tryOut('form', () => api('/heal/proef', { method: 'POST', body: body() }))

  // Een wijziging stuurt altijd de hele regel, ook alleen proef: anders wordt een proefregel ongemerkt echt.
  const put = (r, changes) => withReauth(() => api(`/heal/${r.id}`, { method: 'PUT', body: {
    service_id: r.service_id, enabled: r.enabled, after: r.after, max_per_hour: r.max_per_hour, dry_run: r.dry_run,
    action: r.action, ...changes } }))

  async function toggle(r) {
    try { await put(r, { enabled: !r.enabled }); await load() } catch (e) { msg = e.message }
  }

  async function toggleProef(r) {
    if (r.dry_run && !confirm(`Regel "${r.describe}" echt laten uitvoeren als ${service.name} down is?`)) return
    try { await put(r, { dry_run: !r.dry_run }); await load() } catch (e) { msg = e.message }
  }

  async function test(r) {
    if (!confirm(`Nu echt uitvoeren: ${r.describe}?\nDit herstart echt, ook bij een regel op alleen proef. Met "proef" zie je eerst wat er zou gebeuren.`)) return
    try { msg = '✓ ' + (await withReauth(() => api(`/heal/${r.id}/test`, { method: 'POST' }))).message } catch (e) { msg = '✕ ' + e.message }
  }

  async function remove(r) {
    if (!confirm(`Regel "${r.describe}" verwijderen?`)) return
    try { await withReauth(() => api(`/heal/${r.id}`, { method: 'DELETE' })); await load() } catch (e) { msg = e.message }
  }

  function cancel() {
    adding = false
    if (proef?.key === 'form') proef = null
  }

  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  // Rood: mislukt, of de limiet van een echte regel. Wat een proefregel deed of liet, blijft neutraal.
  const bad = (t) => !!t && (t.startsWith('mislukt') || (t.startsWith('limiet') && !t.includes('(proef)')))
  let valid = $derived(form.pick === 'ssh' ? form.host_id && /^[A-Za-z0-9@._:-]+$/.test(form.name.trim()) : form.pick !== '')
</script>

<div class="heal">
  <span class="lbl">Zelfherstel</span>
  {#each rules as r (r.id)}
    <div class="rule" class:off={!r.enabled}>
      <span class="what">
        {#if r.dry_run}<span class="tag" title="Alleen proef: gaat af zoals altijd, maar zet alleen op de tijdlijn wat hij zou doen">proef</span>{/if}
        als <b>{r.after}×</b> down → <b>{r.describe}</b> <small>(max. {r.max_per_hour}× per uur)</small>
      </span>
      {#if r.last_at}<small class="res" class:e={bad(r.last_result)}>
        laatst {when(r.last_at)}: {r.last_result}</small>{/if}
      <span class="btns">
        <button class="mini" onclick={() => toggle(r)}>{r.enabled ? 'uitzetten' : 'aanzetten'}</button>
        <button class="mini" onclick={() => toggleProef(r)}
                title={r.dry_run ? 'Vanaf nu echt uitvoeren als de service down is' : 'Automatisch alleen tonen wat de regel zou doen'}>
          {r.dry_run ? 'echt maken' : 'alleen proef'}</button>
        <button class="mini" disabled={busy === r.id} onclick={() => tryRule(r)}
                title="Toont wat de regel zou doen en of hij nu zou afgaan; voert niets uit">{busy === r.id ? 'kijken…' : 'proef'}</button>
        <button class="mini" onclick={() => test(r)} title="Voert de actie nu echt uit: herstart of start echt">nu testen (echt)</button>
        <button class="mini" onclick={() => remove(r)} aria-label="Regel verwijderen">✕</button>
      </span>
    </div>
    {#if proef?.key === r.id}<ProefPlan plan={proef.plan} onclose={() => (proef = null)} />{/if}
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
      <label>hoogstens <input type="number" min="1" max="5" bind:value={form.max_per_hour} /> keer per uur, minstens 10 min ertussen</label>
      <small class="m">Elke poging staat in 🔔 en op de tijdlijn. Op je gsm per storing alleen de eerste poging, en de eerste keer dat de limiet de regel pauzeert (zoals "Melden" van de tegel het toelaat).</small>
      <label class="chk"><input type="checkbox" bind:checked={form.dry_run} /> alleen proef: niets uitvoeren, alleen op de tijdlijn zetten wat de regel zou doen</label>
      <div class="row">
        <button class="btn" disabled={!valid} onclick={save}>regel bewaren</button>
        <button class="mini" disabled={!valid || busy === 'form'} onclick={tryForm}
                title="Toont wat deze regel zou doen; voert niets uit en bewaart niets">{busy === 'form' ? 'kijken…' : 'proef'}</button>
        <button class="mini" onclick={cancel}>annuleren</button>
      </div>
      {#if proef?.key === 'form'}<ProefPlan plan={proef.plan} onclose={() => (proef = null)} />{/if}
    </div>
  {:else}
    <button class="mini add" onclick={startAdd}>+ regel</button>
    {#if !rules.length}<small class="m">bv. "als {service.name} 3× down is, herstart zijn container". Je krijgt altijd een melding van wat er gebeurde. Met "proef" zie je eerst wat een regel zou doen.</small>{/if}
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
  .tag { margin-right: 4px; font-size: 10.5px; padding: 0 6px; border-radius: 6px; border: 1px solid var(--mid); color: var(--mid) }
  .res { flex-basis: 100%; color: var(--muted); font-size: 11.5px }
  .btns { display: flex; flex-wrap: wrap; gap: 4px }
  .e { color: var(--err) !important }
  .form { display: flex; flex-direction: column; gap: 8px; padding: 10px; border: 1px solid var(--line); border-radius: 10px; font-size: 12.5px }
  .form label { display: flex; gap: 6px; align-items: center; color: var(--muted) }
  .form label input { width: 64px }
  .form label.chk input { width: auto }
  .row { display: flex; gap: 6px; flex-wrap: wrap; align-items: center }
  .row input { flex: 1; min-width: 160px }
  .add { margin-right: 8px }
  .msg { font-size: 12px; color: var(--ok); margin: 6px 0 0 }
</style>
