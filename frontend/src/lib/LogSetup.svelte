<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Machines hun logs laten doorsturen: automatisch via een SSH-host, of het script zelf plakken.
  let { onclose } = $props()

  let setup = $state(null)
  let hosts = $state([])
  let hostId = $state(null)
  let containers = $state(true)
  let result = $state(null)
  let error = $state('')
  let busy = $state(false)
  let copied = $state(false)

  onMount(async () => {
    try {
      ;[setup, hosts] = await Promise.all([api('/logs/setup'), api('/ssh/hosts')])
      hostId = hosts[0]?.id ?? null
    } catch (e) {
      error = e.message
    }
  })

  async function run() {
    busy = true
    error = ''
    result = null
    try {
      result = await withReauth(() => api('/logs/rollout', { method: 'POST', body: { host_id: hostId, containers } }))
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  async function copy() {
    try { await navigator.clipboard.writeText(setup.manual); copied = true } catch { copied = false }
  }
</script>

<Modal title="rsyslog --forward" {onclose} wide>
  {#if setup}
    <p class="hint">
      De ontvanger luistert op <b>{setup.target || '?'}:{setup.port}</b> (udp en tcp) en neemt alleen berichten aan van
      <code>{setup.allow}</code>.
    </p>
    {#if !setup.target}
      <p class="err">Zet <code>HOMEPAGE_SYSLOG_TARGET=&lt;IP van deze container&gt;</code> in /etc/homepage/homepage.env en herstart homepage-api.</p>
    {/if}

    <span class="lbl">Automatisch via SSH</span>
    {#if hosts.length}
      <div class="row">
        <select bind:value={hostId}>
          {#each hosts as h (h.id)}<option value={h.id}>{h.name} ({h.username}@{h.host})</option>{/each}
        </select>
        <label class="chk"><input type="checkbox" bind:checked={containers} /> ook alle draaiende containers (Proxmox-node)</label>
        <button class="btn" disabled={busy || !setup.target} onclick={run}>{busy ? 'bezig…' : 'Instellen'}</button>
      </div>
      <p class="help">Installeert rsyslog als het ontbreekt en zet <code>/etc/rsyslog.d/90-homepage.conf</code>. Werkt op Debian, Ubuntu, Alpine en Fedora.
        Voor VM's: voeg de VM toe als SSH-host en draai het daar.</p>
    {:else}
      <p class="hint">Voeg eerst een host toe in de terminal (<code>&gt;_</code>) en verbind één keer om de hostsleutel te bevestigen.</p>
    {/if}
    <p class="err">{error}</p>
    {#if result}
      <pre class:bad={result.exit_status !== 0}>{result.output || '(geen uitvoer)'}</pre>
    {/if}

    <span class="lbl">Of zelf plakken (als root)</span>
    <pre class="man">{setup.manual}</pre>
    <button class="mini" onclick={copy}>{copied ? '✓ gekopieerd' : 'kopieer script'}</button>
  {:else}
    <p class="hint">laden…</p>
  {/if}
</Modal>

<style>
  .row select { max-width: 320px; width: auto }
  .help { font-size: 12px; color: var(--muted) }
  pre { max-height: 260px; overflow: auto; font-size: 11.5px; background: rgba(0, 0, 0, .35); padding: 10px; border-radius: 8px; color: var(--text); white-space: pre-wrap }
  pre.bad { border: 1px solid var(--err) }
  pre.man { max-height: 160px }
  code { color: #d6e6ff }
</style>
