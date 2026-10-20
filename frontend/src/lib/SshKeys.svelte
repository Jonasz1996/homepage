<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  let { keys = [], hosts = [], onclose, onchanged } = $props()

  let name = $state('homepage')
  let mode = $state('new')
  let priv = $state('')
  let passphrase = $state('')
  let error = $state('')
  let copied = $state(null)

  async function add(e) {
    e.preventDefault()
    error = ''
    try {
      const body = { name, ...(mode === 'import' ? { private_key: priv, passphrase: passphrase || null } : {}) }
      await withReauth(() => api('/ssh/keys', { method: 'POST', body }))
      priv = ''
      passphrase = ''
      onchanged()
    } catch (err) {
      error = err.message
    }
  }

  async function del(k) {
    if (!confirm(`Sleutel '${k.name}' verwijderen? Hosts die hem gebruiken vallen terug op een wachtwoord.`)) return
    try {
      await withReauth(() => api(`/ssh/keys/${k.id}`, { method: 'DELETE' }))
      onchanged()
    } catch (err) {
      error = err.message
    }
  }

  // Vastzetten: from="<IP van het dashboard>" voor de sleutel in authorized_keys, zodat een gestolen sleutel
  // alleen nog vanaf het dashboard werkt.
  let pin = $state({ hosts: {}, checked_at: null })
  let pinBusy = $state('')
  let pinMsg = $state('')
  onMount(async () => { try { pin = await api('/ssh/pin') } catch { /* nog niet nagekeken */ } })
  async function pinCheck() {
    pinBusy = 'check'
    pinMsg = ''
    try { pin = await api('/ssh/pin/check', { method: 'POST' }) } catch (e) { pinMsg = e.message } finally { pinBusy = '' }
  }
  async function pinSet(ids, on) {
    if (!ids.length) return
    if (on && ids.length > 1 && !confirm(`De sleutel op ${ids.length} hosts vastzetten op het IP van het dashboard?`)) return
    pinBusy = on ? 'pin' : 'unpin'
    pinMsg = ''
    try {
      const r = await withReauth(() => api('/ssh/pin', { method: 'POST', body: { host_ids: ids, pin: on } }))
      pin = r
      const errs = Object.values(r.results).filter((x) => x.error || x.state === 'fout').length
      const changed = Object.values(r.results).filter((x) => x.changed).length
      pinMsg = `${changed} aangepast${errs ? `, ${errs} niet gelukt (zie lijst)` : ''}`
    } catch (e) { pinMsg = e.message } finally { pinBusy = '' }
  }
  const PIN = { vast: 'vast', los: 'elk IP', anders: 'ander IP', geen: '—', fout: 'fout' }
  let pinRows = $derived(hosts.map((h) => ({ h, r: pin.hosts?.[h.id] })))
  let loose = $derived(pinRows.filter(({ r }) => r && (r.state === 'los' || r.state === 'anders')).map(({ h }) => h.id))
  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '')

  async function copy(k) {
    try { await navigator.clipboard.writeText(k.public_key); copied = k.id } catch { copied = null }
  }
</script>

<Modal title="ssh-keygen" {onclose} wide>
  {#each keys as k (k.id)}
    <div class="key">
      <div class="kh"><b>{k.name}</b><small>{k.fingerprint}</small>
        <button class="mini" onclick={() => copy(k)}>{copied === k.id ? '✓ gekopieerd' : 'kopieer publieke sleutel'}</button>
        <button class="mini x" onclick={() => del(k)}>✕</button>
      </div>
      <code>{k.public_key}</code>
    </div>
  {:else}
    <p class="hint">Nog geen sleutels.</p>
  {/each}
  <p class="help">Zet de publieke sleutel op de server in <code>~/.ssh/authorized_keys</code>, bv. met
    <code>echo '…' &gt;&gt; ~/.ssh/authorized_keys</code>. De private sleutel verlaat de server nooit.</p>

  <section class="pin">
    <div class="ph">
      <b>vastzetten op het dashboard</b>
      <span class="hint">{pin.checked_at ? `nagekeken ${when(pin.checked_at)}` : 'nog niet nagekeken'}</span>
      <button class="mini" disabled={!!pinBusy} onclick={pinCheck}>{pinBusy === 'check' ? 'bezig…' : '⟳ nakijken'}</button>
      <button class="mini ok" disabled={!!pinBusy || !loose.length} onclick={() => pinSet(loose, true)}>
        {pinBusy === 'pin' ? 'bezig…' : `alles vastzetten${loose.length ? ` (${loose.length})` : ''}`}</button>
    </div>
    <p class="help">Zet <code>from="&lt;IP van het dashboard&gt;"</code> voor de sleutel in <code>authorized_keys</code> op elke host.
      Een gestolen sleutel werkt dan nergens anders. Het dashboard kijkt na of het er daarna nog in kan, en zet anders
      het oude bestand terug (kopie: <code>~/.ssh/authorized_keys.homepage-bak</code>). Op een Proxmox-node geldt het
      voor de hele cluster. <b>Gebruik je een geïmporteerde sleutel ook vanaf je pc, zet hem dan niet vast.</b></p>
    {#if pinMsg}<p class="hint">{pinMsg}</p>{/if}
    {#if hosts.length}
      <table>
        <tbody>
          {#each pinRows as { h, r } (h.id)}
            <tr>
              <td>{h.name}<small class="hh">{h.host}</small></td>
              <td><span class="st {r?.state || ''}">{r ? PIN[r.state] || r.state : '?'}</span></td>
              <td class="m">{r?.error || r?.text || ''}</td>
              <td class="nw">
                {#if r?.state === 'los' || r?.state === 'anders'}
                  <button class="mini" disabled={!!pinBusy} onclick={() => pinSet([h.id], true)}>vastzetten</button>
                {:else if r?.state === 'vast'}
                  <button class="mini" disabled={!!pinBusy} onclick={() => pinSet([h.id], false)}>losmaken</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <form onsubmit={add} class="add">
    <div class="row">
      <label class="chk"><input type="radio" bind:group={mode} value="new" /> nieuw ed25519-sleutelpaar</label>
      <label class="chk"><input type="radio" bind:group={mode} value="import" /> bestaande sleutel plakken</label>
    </div>
    <label class="lbl" for="sk-name">Naam</label>
    <input id="sk-name" bind:value={name} maxlength="80" required />
    {#if mode === 'import'}
      <label class="lbl" for="sk-priv">Private sleutel (OpenSSH of PEM)</label>
      <textarea id="sk-priv" bind:value={priv} required placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
      <label class="lbl" for="sk-pass">Wachtwoordzin (als de sleutel er een heeft)</label>
      <input id="sk-pass" type="password" bind:value={passphrase} autocomplete="off" />
    {/if}
    <p class="err">{error}</p>
    <button class="btn">{mode === 'new' ? 'Aanmaken' : 'Importeren'}</button>
  </form>
</Modal>

<style>
  .key { border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; margin-bottom: 8px }
  .kh { display: flex; gap: 10px; align-items: center; flex-wrap: wrap }
  .kh small { color: var(--muted); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis }
  .key code { display: block; margin-top: 6px; font-size: 11px; color: #d6e6ff; word-break: break-all }
  .help { font-size: 12px; color: var(--muted) }
  .add { margin-top: 14px; border-top: 1px solid var(--line); padding-top: 12px }
  .pin { margin-top: 14px; border-top: 1px solid var(--line); padding-top: 12px }
  .ph { display: flex; gap: 10px; align-items: center; flex-wrap: wrap }
  .ph b { color: var(--text-h); font-weight: 500 }
  .ph .hint { flex: 1 }
  .pin table { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .pin td { padding: 5px 6px; border-top: 1px solid var(--line); vertical-align: baseline }
  .pin td small { color: var(--dim) }
  .pin .hh { margin-left: 8px }
  .pin .m { color: var(--muted); font-size: 11.5px }
  .pin .nw { white-space: nowrap; text-align: right }
  .st { font-size: 11px; padding: 0 6px; border-radius: 6px; border: 1px solid var(--line-2); color: var(--muted); white-space: nowrap }
  .st.vast { color: var(--ok); border-color: rgba(120, 220, 150, .45) }
  .st.los, .st.anders { color: var(--mid); border-color: rgba(255, 190, 90, .45) }
  .st.fout { color: var(--err) }
  textarea { min-height: 110px; font-size: 11.5px }
</style>
