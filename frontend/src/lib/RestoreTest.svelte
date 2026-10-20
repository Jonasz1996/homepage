<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'

  // Hersteltest van back-ups: één keer per maand een CT uit PBS terugzetten, opstarten en weer weggooien.
  let data = $state(null)
  let opts = $state(null)
  let form = $state(null)
  let error = $state('')
  let busy = $state(false)

  async function load() {
    try { data = await api('/restoretest'); error = '' } catch (e) { error = e.message }
  }
  onMount(() => {
    load()
    return poll(() => data?.running && load(), 3000)
  })

  async function loadOptions(sid) {
    opts = null
    try { opts = await api('/restoretest/options' + (sid ? `?service_id=${sid}` : '')) } catch (e) { opts = { error: e.message } }
  }
  function edit() {
    form = { ...data.settings, only: [...(data.settings.only || [])] }
    loadOptions(form.service_id)
  }
  async function save() {
    busy = true
    try {
      const body = { ...form, service_id: form.service_id ? Number(form.service_id) : (opts?.service_id ?? null),
                     day: Number(form.day), hour: Number(form.hour), vmid_from: Number(form.vmid_from) }
      data = await withReauth(() => api('/restoretest/settings', { method: 'PUT', body }))
      form = null
    } catch (e) { error = e.message } finally { busy = false }
  }
  async function runNow() {
    if (!confirm('Nu een CT uit PBS terugzetten op een vrij ID (zonder netwerk), opstarten en weer verwijderen?')) return
    busy = true
    try {
      await withReauth(() => api('/restoretest/run', { method: 'POST' }))
      setTimeout(load, 800)
    } catch (e) { error = e.message } finally { busy = false }
  }
  function toggle(v) {
    form.only = form.only.includes(v) ? form.only.filter((x) => x !== v) : [...form.only, v]
  }
  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '—')
  const dur = (s) => (s == null ? '' : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`)
  let last = $derived(data?.history?.[0])
</script>

<div class="rt">
  <div class="top">
    <span class="lbl">hersteltest</span>
    {#if data}
      <small class="st">
        {#if data.running}<span class="w">bezig: {data.running.step}{data.running.vmid ? ` (CT ${data.running.vmid})` : ''}…</span>
        {:else if data.settings.enabled}elke maand op dag {data.settings.day} om {data.settings.hour}:00{data.next ? ` · volgende ${when(data.next)}` : ''}
        {:else}staat uit{/if}
      </small>
      <span class="sp"></span>
      {#if !form}
        <button class="mini" disabled={busy || !!data.running} onclick={runNow}>▶ nu testen</button>
        <button class="mini" onclick={edit}>instellingen</button>
      {/if}
    {/if}
  </div>
  {#if error}<p class="err">{error}</p>{/if}
  {#if data && !data.history.length && !form}
    <p class="hint small">Zet maandelijks een CT uit PBS terug op een vrij ID, zonder netwerk, kijkt of hij opstart en blijft draaien,
      en gooit hem daarna weg. Elke keer een andere CT (die het langst niet getest is). Het resultaat komt op de tijdlijn en
      in je meldingen.</p>
  {/if}

  {#if form}
    <div class="form">
      {#if opts?.error}<p class="err">{opts.error}</p>{/if}
      <label class="chk"><input type="checkbox" bind:checked={form.enabled} /> elke maand automatisch testen</label>
      {#if opts?.services?.length > 1}
        <label>Proxmox-tegel
          <select bind:value={form.service_id} onchange={() => loadOptions(form.service_id)}>
            {#each opts.services as s}<option value={s.id}>{s.name}</option>{/each}
          </select></label>
      {/if}
      <div class="line">
        <label>node <select bind:value={form.node}><option value="">eerste die online is</option>
          {#each opts?.nodes || [] as n}<option value={n}>{n}</option>{/each}</select></label>
        <label>PBS-opslag <select bind:value={form.pbs}><option value="">eerste</option>
          {#each opts?.pbs || [] as p}<option value={p}>{p}</option>{/each}</select></label>
        <label>terugzetten op <select bind:value={form.storage}><option value="">zoals in de back-up</option>
          {#each opts?.targets?.[form.node || opts?.nodes?.[0]] || [] as t}<option value={t}>{t}</option>{/each}</select></label>
      </div>
      <div class="line">
        <label>dag <input type="number" min="1" max="28" bind:value={form.day} /></label>
        <label>uur <input type="number" min="0" max="23" bind:value={form.hour} /></label>
        <label>vrij ID vanaf <input type="number" min="100" bind:value={form.vmid_from} /></label>
      </div>
      {#if opts?.guests?.length}
        <span class="small">Welke CT's (niets gekozen = allemaal):</span>
        <div class="cts">
          {#each opts.guests as g (g.vmid)}
            <button class="mini" class:on={form.only.includes(g.vmid)} onclick={() => toggle(g.vmid)}>{g.vmid} {g.name || ''}</button>
          {/each}
        </div>
      {/if}
      <p class="hint small">Het Proxmox-token heeft daarvoor meer nodig dan lezen: VM.Allocate, VM.Config.Disk, VM.Config.Network,
        VM.Config.Options, VM.PowerMgmt, Datastore.AllocateSpace op de doelopslag en Datastore.Audit op de PBS-opslag
        (zie README).</p>
      <div class="line">
        <button class="mini" disabled={busy} onclick={save}>bewaren</button>
        <button class="mini" onclick={() => (form = null)}>annuleren</button>
      </div>
    </div>
  {/if}

  {#if data?.history?.length}
    <table class="tbl">
      <tbody>
        {#each data.history as h (h.at)}
          <tr>
            <td class="m">{when(h.at)}</td>
            <td>{h.name || '—'}{h.source_vmid ? ` (${h.source_vmid})` : ''}</td>
            <td class="m">{h.backup_at ? `back-up ${when(h.backup_at)}` : ''}</td>
            <td class:g={h.ok} class:e={!h.ok}>{h.ok ? 'gelukt' : `mislukt bij ${h.step}`}{#if h.cleanup_error}<span class="w"> · niet opgeruimd</span>{/if}</td>
            <td class="m">{dur(h.seconds)}</td>
          </tr>
          {#if !h.ok && h.error}<tr><td colspan="5" class="e small">{h.error}</td></tr>{/if}
        {/each}
      </tbody>
    </table>
  {:else if last === undefined && data?.settings?.enabled}
    <p class="hint small">Nog niet getest.</p>
  {/if}
</div>

<style>
  .rt { margin: 8px 0 }
  .top { display: flex; gap: 8px; align-items: center; flex-wrap: wrap }
  .st { color: var(--muted); font-size: 11.5px }
  .sp { flex: 1 }
  .form { display: flex; flex-direction: column; gap: 8px; margin-top: 6px; padding: 8px; border: 1px solid var(--line); border-radius: 10px }
  .form label { display: flex; flex-direction: column; gap: 2px; font-size: 11.5px; color: var(--muted) }
  .form label.chk { flex-direction: row; gap: 6px; align-items: center; color: var(--text); font-size: 12.5px }
  .chk input { width: auto }
  .line { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end }
  .line input { width: 90px }
  .line select { width: auto; min-width: 120px }
  .cts { display: flex; flex-wrap: wrap; gap: 4px }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 6px }
  .tbl td { padding: 4px 6px; border-top: 1px solid var(--line) }
  .m { color: var(--muted); font-size: 11.5px }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .w { color: var(--mid) }
  .small { font-size: 12px; margin: 2px 0 }
  @media (max-width: 640px) { .tbl td:nth-child(3) { display: none } }
</style>
