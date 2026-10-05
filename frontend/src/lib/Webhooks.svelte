<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Webhooks: Proxmox, PBS, Uptime Kuma, Home Assistant en andere tools sturen hun meldingen naar het meldingencentrum.
  let { onclose, services = [] } = $props()

  const KINDS = { proxmox: 'Proxmox VE', pbs: 'Proxmox Backup Server', uptimekuma: 'Uptime Kuma',
                  homeassistant: 'Home Assistant', generic: 'ander (JSON of tekst)' }
  const BODY = '{"title": "{{ title }}", "message": "{{ escape message }}", "severity": "{{ severity }}"}'
  const HELP = {
    proxmox: [
      'Datacenter → Notifications → Add → Webhook (Proxmox VE 8.3 of nieuwer).',
      'Method POST, URL hieronder, header Content-Type = application/json, body:',
      BODY,
      'Voeg daarna onder Notification Matchers een matcher toe (of pas default-matcher aan) die naar dit doel stuurt.',
    ],
    pbs: [
      'Configuration → Notifications → Add → Webhook (PBS 3.3 of nieuwer).',
      'Method POST, URL hieronder, header Content-Type = application/json, body:',
      BODY,
      'Voeg daarna een matcher toe die naar dit doel stuurt.',
    ],
    uptimekuma: [
      'Settings → Notifications → Setup Notification → type Webhook.',
      'Post URL hieronder, Request Body "application/json". Zet de melding aan bij je monitors (of "Default enabled").',
    ],
    homeassistant: [
      'In configuration.yaml:',
      'rest_command:\n  homepage:\n    url: "URL"\n    method: POST\n    content_type: "application/json"\n    payload: \'{"title": "{{ title }}", "message": "{{ message }}", "severity": "{{ severity | default(\'\'info\'\') }}"}\'',
      'en in een automatisering: actie rest_command.homepage met title, message en severity (info, warning of error).',
    ],
    generic: [
      'POST naar de URL met JSON (title, message, severity: info / warning / error) of gewone tekst (eerste regel = titel):',
      'curl -X POST URL -H "Content-Type: application/json" -d \'{"title": "Back-up mislukt", "message": "...", "severity": "error"}\'',
    ],
  }

  let items = $state([])
  let error = $state('')
  let form = $state(null)
  let open = $state(null)
  let copied = $state(null)

  async function load() {
    try { items = await api('/webhooks'); error = '' } catch (e) { error = e.message }
  }
  onMount(load)

  const url = (w) => `${location.origin}/api/hooks/${w.token}`
  async function save() {
    try {
      const body = { name: form.name.trim(), kind: form.kind, service_id: form.service_id ? Number(form.service_id) : null,
                     enabled: form.enabled }
      const w = await api('/webhooks' + (form.id ? `/${form.id}` : ''), { method: form.id ? 'PATCH' : 'POST', body })
      form = null
      await load()
      open = w.id
    } catch (e) { error = e.message }
  }
  async function rotate(w) {
    if (!confirm(`Nieuw adres voor ${w.name}? Het oude werkt meteen niet meer; pas het aan in ${KINDS[w.kind]}.`)) return
    try { await api(`/webhooks/${w.id}/rotate`, { method: 'POST' }); await load() } catch (e) { error = e.message }
  }
  async function remove(w) {
    if (!confirm(`Webhook ${w.name} verwijderen?`)) return
    try { await api(`/webhooks/${w.id}`, { method: 'DELETE' }); await load() } catch (e) { error = e.message }
  }
  async function test(w) {
    try {
      const r = await fetch(`/api/hooks/${w.token}`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'testmelding', message: 'Als je dit ziet, werkt de webhook.', severity: 'info' }) })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      await load()
    } catch (e) { error = e.message }
  }
  async function copy(text, key) {
    try { await navigator.clipboard.writeText(text); copied = key; setTimeout(() => (copied = null), 1500) }
    catch { prompt('Kopieer:', text) }
  }
  const ago = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : 'nog nooit')
</script>

<Modal title="curl -X POST /api/hooks" {onclose} wide>
  <p class="hint">Elke tool krijgt een eigen geheim adres. Wat daar binnenkomt (een mislukte back-up, een schijffout, een
    monitor die down gaat) komt in je meldingencentrum, met de juiste ernst en eventueel gekoppeld aan een service.</p>
  {#if error}<p class="err">{error}</p>{/if}
  {#each items as w (w.id)}
    <div class="src" class:off={!w.enabled}>
      <div class="hh">
        <button class="link" onclick={() => (open = open === w.id ? null : w.id)}><b>{w.name}</b></button>
        <small>{KINDS[w.kind]} · {w.count} ontvangen · laatst {ago(w.last_at)}</small>
        <span class="sp"></span>
        <button class="mini" onclick={() => test(w)}>test</button>
        <button class="mini" onclick={() => (form = { ...w, service_id: w.service_id || '' })} aria-label="Bewerken">✎</button>
        <button class="mini x" onclick={() => remove(w)} aria-label="Verwijderen">✕</button>
      </div>
      {#if open === w.id}
        <div class="url"><code>{url(w)}</code>
          <button class="mini" onclick={() => copy(url(w), w.id)}>{copied === w.id ? '✓ gekopieerd' : 'kopiëren'}</button>
          <button class="mini" onclick={() => rotate(w)}>nieuw adres</button>
        </div>
        {#each HELP[w.kind] as h, i}
          {#if h.includes('{') || h.includes('\n')}
            <div class="code"><pre>{h.replace('URL', url(w))}</pre><button class="mini" onclick={() => copy(h.replace('URL', url(w)), `${w.id}-${i}`)}>{copied === `${w.id}-${i}` ? '✓' : 'kopiëren'}</button></div>
          {:else}<p class="small">{h}</p>{/if}
        {/each}
      {/if}
    </div>
  {:else}
    {#if !form}<p class="hint">Nog geen webhooks.</p>{/if}
  {/each}

  {#if form}
    <div class="form">
      <input bind:value={form.name} placeholder="naam, bv. Proxmox cluster" maxlength="80" />
      <select bind:value={form.kind} aria-label="Soort">{#each Object.entries(KINDS) as [k, l]}<option value={k}>{l}</option>{/each}</select>
      <select bind:value={form.service_id} aria-label="Service">
        <option value="">niet aan een service koppelen</option>
        {#each services as s}<option value={s.id}>{s.name}</option>{/each}
      </select>
      <label class="chk"><input type="checkbox" bind:checked={form.enabled} /> aan</label>
      <div class="line">
        <button class="mini" disabled={!form.name.trim()} onclick={save}>bewaren</button>
        <button class="mini" onclick={() => (form = null)}>annuleren</button>
      </div>
    </div>
  {:else}
    <button class="mini" onclick={() => (form = { id: null, name: '', kind: 'proxmox', service_id: '', enabled: true })}>+ webhook</button>
  {/if}
</Modal>

<style>
  .src { border-top: 1px solid var(--line); padding: 8px 0 }
  .src.off { opacity: .55 }
  .hh { display: flex; gap: 8px; align-items: center; flex-wrap: wrap }
  .hh b { color: var(--text-h); font-weight: 500 }
  .hh small { color: var(--muted); font-size: 11.5px }
  .sp { flex: 1 }
  .link { all: unset; cursor: pointer }
  .url { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin: 6px 0 }
  code { font-size: 11.5px; background: rgba(0, 0, 0, .35); padding: 4px 8px; border-radius: 6px; word-break: break-all; flex: 1; min-width: 200px }
  .code { display: flex; gap: 6px; align-items: flex-start }
  pre { flex: 1; margin: 4px 0; font-size: 11.5px; background: rgba(0, 0, 0, .35); padding: 6px 8px; border-radius: 6px; white-space: pre-wrap; word-break: break-all }
  .small { font-size: 12px; margin: 4px 0; color: var(--text) }
  .form { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; padding: 8px; border: 1px solid var(--line); border-radius: 10px }
  .line { display: flex; gap: 6px }
  .chk { display: flex; gap: 6px; align-items: center; font-size: 12.5px }
  .chk input { width: auto }
</style>
