<script>
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  let { keys = [], onclose, onchanged } = $props()

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
  textarea { min-height: 110px; font-size: 11.5px }
</style>
