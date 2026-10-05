<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'

  // Gepland onderhoud: vooraf vastleggen wanneer een service of groep in onderhoud gaat (eenmalig of herhalend).
  // Met `service` alleen de vensters van die service (en zijn groep); zonder alles, met een keuze van het doel.
  let { service = null, services = [], groups = [] } = $props()

  const DAYS = ['ma', 'di', 'wo', 'do', 'vr', 'za', 'zo']
  const DURATIONS = [[15, '15 min'], [30, '30 min'], [60, '1 u'], [120, '2 u'], [240, '4 u'], [480, '8 u'], [1440, '1 dag']]
  let items = $state([])
  let error = $state('')
  let form = $state(null)

  async function load() {
    try { items = await api('/maintenance/windows' + (service ? `?service_id=${service.id}` : '')); error = '' }
    catch (e) { error = e.message }
  }
  onMount(load)

  const pad = (n) => String(n).padStart(2, '0')
  function local(d) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  }
  function add() {
    const d = new Date(Date.now() + 3600000)
    d.setMinutes(0)
    form = { id: null, name: service ? `onderhoud ${service.name}` : '', target: service ? `s${service.id}` : '',
             repeat: 'once', when: local(d), time: '03:00', minutes: 60, weekdays: [6], enabled: true }
  }
  function edit(w) {
    const st = new Date(w.start)
    form = { id: w.id, name: w.name, target: w.service_id ? `s${w.service_id}` : `g${w.group_id}`, repeat: w.repeat,
             when: local(st), time: `${pad(st.getHours())}:${pad(st.getMinutes())}`, minutes: w.minutes,
             weekdays: [...w.weekdays], enabled: w.enabled }
  }
  async function save() {
    error = ''
    let start
    if (form.repeat === 'once') start = new Date(form.when)
    else {
      const [h, m] = form.time.split(':').map(Number)
      start = new Date()
      start.setHours(h, m, 0, 0)
    }
    const body = { name: form.name.trim(), repeat: form.repeat, start: start.toISOString(), minutes: Number(form.minutes),
                   weekdays: form.repeat === 'weekly' ? form.weekdays : [], enabled: form.enabled,
                   service_id: form.target.startsWith('s') ? Number(form.target.slice(1)) : null,
                   group_id: form.target.startsWith('g') ? Number(form.target.slice(1)) : null }
    try {
      await api('/maintenance/windows' + (form.id ? `/${form.id}` : ''), { method: form.id ? 'PUT' : 'POST', body })
      form = null
      await load()
    } catch (e) { error = e.message }
  }
  async function toggle(w) {
    try {
      await api(`/maintenance/windows/${w.id}`, { method: 'PUT', body: { name: w.name, repeat: w.repeat, start: w.start,
        minutes: w.minutes, weekdays: w.weekdays, enabled: !w.enabled, service_id: w.service_id, group_id: w.group_id } })
      await load()
    } catch (e) { error = e.message }
  }
  async function remove(w) {
    if (!confirm(`Gepland onderhoud "${w.name}" verwijderen?`)) return
    try { await api(`/maintenance/windows/${w.id}`, { method: 'DELETE' }); await load() } catch (e) { error = e.message }
  }
  function day(i) {
    form.weekdays = form.weekdays.includes(i) ? form.weekdays.filter((d) => d !== i) : [...form.weekdays, i]
  }
  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
</script>

<div class="mw">
  <div class="top">
    <span class="lbl">gepland onderhoud</span>
    {#if !form}<button class="mini" onclick={add}>+ plannen</button>{/if}
  </div>
  {#if error}<p class="err">{error}</p>{/if}
  {#each items as w (w.id)}
    <div class="row" class:off={!w.enabled}>
      <div class="what">
        <b>{w.name}</b>{#if !service || w.group_id}<small> · {w.group_id ? `groep ${w.target}` : w.target}</small>{/if}
        <small class="block">{w.text}
          {#if w.active_until}<span class="on"> · loopt nu, tot {new Date(w.active_until).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })}</span>
          {:else if w.next}<span> · volgende: {when(w.next)}</span>
          {:else if !w.enabled}<span> · uit</span>{/if}</small>
      </div>
      <button class="mini" onclick={() => toggle(w)}>{w.enabled ? 'uit' : 'aan'}</button>
      <button class="mini" onclick={() => edit(w)} aria-label="Bewerken">✎</button>
      <button class="mini x" onclick={() => remove(w)} aria-label="Verwijderen">✕</button>
    </div>
  {:else}
    {#if !form}<p class="hint small">Niets gepland. Plan onderhoud vooraf (bv. elke zondag 3:00 tot 4:00 tijdens de back-up),
      dan komen er geen valse meldingen en telt de uptime het niet mee.</p>{/if}
  {/each}

  {#if form}
    <div class="form">
      <input bind:value={form.name} placeholder="naam, bv. back-up PBS" maxlength="80" />
      {#if !service}
        <select bind:value={form.target} aria-label="Voor">
          <option value="">voor…</option>
          {#if groups.length}<optgroup label="groepen">{#each groups as g}<option value="g{g.id}">{g.label || g.name}</option>{/each}</optgroup>{/if}
          <optgroup label="services">{#each services as s}<option value="s{s.id}">{s.name}</option>{/each}</optgroup>
        </select>
      {:else if service.group_id}
        <select bind:value={form.target} aria-label="Voor">
          <option value="s{service.id}">alleen {service.name}</option>
          <option value="g{service.group_id}">de hele groep</option>
        </select>
      {/if}
      <div class="line">
        <select bind:value={form.repeat} aria-label="Herhalen">
          <option value="once">eenmalig</option><option value="daily">elke dag</option><option value="weekly">elke week</option>
        </select>
        {#if form.repeat === 'once'}<input type="datetime-local" bind:value={form.when} aria-label="Begin" />
        {:else}<input type="time" bind:value={form.time} aria-label="Uur" />{/if}
        <select bind:value={form.minutes} aria-label="Duur">{#each DURATIONS as [m, l]}<option value={m}>{l}</option>{/each}</select>
      </div>
      {#if form.repeat === 'weekly'}
        <div class="days">{#each DAYS as d, i}<button class="mini" class:on={form.weekdays.includes(i)} onclick={() => day(i)}>{d}</button>{/each}</div>
      {/if}
      <div class="line">
        <button class="mini" disabled={!form.name.trim() || !form.target} onclick={save}>bewaren</button>
        <button class="mini" onclick={() => (form = null)}>annuleren</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .mw { margin: 6px 0 4px }
  .top { display: flex; align-items: center; gap: 8px }
  .row { display: flex; gap: 6px; align-items: center; padding: 5px 0; border-top: 1px solid var(--line); font-size: 12.5px }
  .row.off { opacity: .55 }
  .what { flex: 1; min-width: 0 }
  .what b { color: var(--text-h); font-weight: 500 }
  .what small { color: var(--muted); font-size: 11.5px }
  .block { display: block }
  .on { color: var(--mid) }
  .form { display: flex; flex-direction: column; gap: 6px; margin-top: 6px; padding: 8px; border: 1px solid var(--line); border-radius: 10px }
  .line { display: flex; gap: 6px; flex-wrap: wrap; align-items: center }
  .line select, .line input { width: auto }
  .days { display: flex; gap: 4px; flex-wrap: wrap }
  .small { font-size: 12px; margin: 4px 0 }
</style>
