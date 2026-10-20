<script>
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  let { host = null, keys = [], services = [], onclose, onsaved, onkeys } = $props()

  const h = untrack(() => host) || {}
  let name = $state(h.name || '')
  let addr = $state(h.host || '')
  let port = $state(h.port || 22)
  let username = $state(h.username || 'root')
  let key_id = $state(h.key_id ?? untrack(() => keys[0]?.id) ?? null)
  let password = $state('')
  let clearPassword = $state(false)
  let service_id = $state(h.service_id ?? null)
  let updates = $state(h.updates || '')
  let error = $state('')

  async function save(e) {
    e.preventDefault()
    error = ''
    const body = {
      name, host: addr, port: Number(port) || 22, username, key_id: key_id || null, service_id: service_id || null, updates,
      password: clearPassword ? '' : password || (host ? null : undefined),
    }
    try {
      if (host) await api(`/ssh/hosts/${host.id}`, { method: 'PATCH', body })
      else await api('/ssh/hosts', { method: 'POST', body })
      onsaved()
      onclose()
    } catch (err) {
      error = err.message
    }
  }

  async function del() {
    if (!confirm(`Host '${host.name}' verwijderen?`)) return
    await api(`/ssh/hosts/${host.id}`, { method: 'DELETE' })
    onsaved()
    onclose()
  }

  async function forget() {
    if (!confirm('Opgeslagen hostsleutel vergeten? Bij de volgende verbinding moet je hem opnieuw bevestigen.')) return
    try {
      await withReauth(() => api(`/ssh/hosts/${host.id}/forget-hostkey`, { method: 'POST' }))
      host.host_key_fingerprint = null
      onsaved()
    } catch (err) {
      error = err.message
    }
  }
</script>

<Modal title={host ? `edit ${host.name}` : 'ssh-host --new'} {onclose}>
  <form onsubmit={save}>
    <div class="grid">
      <div>
        <label class="lbl" for="hf-name">Naam</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="hf-name" bind:value={name} maxlength="80" required autofocus placeholder="pve50" />
      </div>
      <div>
        <label class="lbl" for="hf-user">Gebruiker</label>
        <input id="hf-user" bind:value={username} maxlength="64" required />
      </div>
      <div>
        <label class="lbl" for="hf-host">Host of IP</label>
        <input id="hf-host" bind:value={addr} maxlength="255" required placeholder="192.168.0.50" />
      </div>
      <div>
        <label class="lbl" for="hf-port">Poort</label>
        <input id="hf-port" bind:value={port} inputmode="numeric" />
      </div>
      <div class="full">
        <label class="lbl" for="hf-key">Sleutel</label>
        <div class="row nowrap">
          <select id="hf-key" bind:value={key_id}>
            <option value={null}>geen (wachtwoord)</option>
            {#each keys as k (k.id)}<option value={k.id}>{k.name}</option>{/each}
          </select>
          <button type="button" class="mini" onclick={onkeys}>sleutels…</button>
        </div>
      </div>
      <div class="full">
        <label class="lbl" for="hf-pw">Wachtwoord {host?.has_password ? '(ingesteld, leeg laten = behouden)' : '(optioneel)'}</label>
        <input id="hf-pw" type="password" bind:value={password} autocomplete="new-password" disabled={clearPassword} />
        {#if host?.has_password}
          <label class="chk"><input type="checkbox" bind:checked={clearPassword} /> wachtwoord wissen</label>
        {/if}
      </div>
      <div class="full">
        <label class="lbl" for="hf-svc">Koppelen aan service (terminal-knop in het mini dashboard)</label>
        <select id="hf-svc" bind:value={service_id}>
          <option value={null}>geen</option>
          {#each services as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </div>
      <div class="full">
        <label class="lbl" for="hf-upd">Updates opvolgen (apt of apk, elke 6 uur)</label>
        <select id="hf-upd" bind:value={updates}>
          <option value="">nee</option>
          <option value="host">deze machine</option>
          <option value="cts">deze machine en al zijn containers (Proxmox-node, via pct exec)</option>
        </select>
      </div>
    </div>
    {#if host?.host_key_fingerprint}
      <p class="help">Hostsleutel: <code>{host.host_key_fingerprint}</code> <button type="button" class="mini x" onclick={forget}>vergeten</button></p>
    {/if}
    <p class="err">{error}</p>
    <div class="row">
      <button class="btn">Opslaan</button>
      <button type="button" class="btn alt" onclick={onclose}>Annuleren</button>
      {#if host}<button type="button" class="btn alt danger right" onclick={del}>Verwijderen</button>{/if}
    </div>
  </form>
</Modal>

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px }
  .full { grid-column: 1 / -1 }
  .nowrap { flex-wrap: nowrap }
  .help { font-size: 12px; color: var(--muted) }
  .help code { color: var(--ok); word-break: break-all }
  .right { margin-left: auto }
  @media (max-width: 560px) { .grid { grid-template-columns: 1fr } }
</style>
