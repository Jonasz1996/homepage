<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Nodes, containers en VM's uit alle Proxmox-tegels: aanvinken en in één keer toevoegen.
  let { onclose, onimported } = $props()

  let data = $state(null)
  let error = $state('')
  let picked = $state({})
  let busy = $state(false)
  let result = $state('')

  onMount(async () => {
    try {
      data = await api('/ssh/discover', { method: 'POST' })
      for (const i of data.items) if (i.host && !i.known) picked[i.source] = true
    } catch (e) { error = e.message }
  })

  let folders = $derived.by(() => {
    const out = {}
    for (const i of data?.items || []) (out[i.folder] ||= []).push(i)
    return Object.entries(out)
  })
  let count = $derived(Object.values(picked).filter(Boolean).length)
  const KIND = { node: 'node', lxc: 'CT', qemu: 'VM' }

  function all(on) {
    for (const i of data.items) if (i.host && !i.known) picked[i.source] = on
  }

  async function run() {
    busy = true
    try {
      const items = data.items.filter((i) => picked[i.source] || i.known)
        .filter((i) => i.host)
        .map(({ source, name, host, folder, kind }) => ({ source, name, host, folder, kind }))
      const r = await api('/ssh/import', { method: 'POST', body: items })
      result = `✓ ${r.added} toegevoegd${r.updated ? `, ${r.updated} IP's bijgewerkt` : ''}`
      onimported?.()
      setTimeout(onclose, 900)
    } catch (e) { error = e.message } finally { busy = false }
  }
</script>

<Modal title="pvesh get /cluster/resources" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if !data}
    <p class="hint">Proxmox bevragen…</p>
  {:else}
    {#each data.errors as e}<p class="e">{e.service}: {e.error}</p>{/each}
    {#if data.errors.length}
      <p class="hint small">Token of url aanpassen: ✎ bewerken → klik op de Proxmox-tegel → url (bv. <code>https://192.168.0.50:8006</code>),
        insecure <code>true</code>, geheimen <code>username</code> = token-id (<code>homepage@pve!dashboard</code>) en
        <code>password</code> = het token-geheim. Bij een cluster volstaat één tegel.</p>
    {/if}
    {#if !data.items.length}
      <p class="hint">Niets gevonden. Voeg eerst een Proxmox-tegel toe (type <b>proxmox</b> met een API-token).</p>
    {/if}
    <div class="top">
      <button class="mini" onclick={() => all(true)}>alles</button>
      <button class="mini" onclick={() => all(false)}>niets</button>
      <span class="hint">Nieuwe hosts gebruiken de standaard login. Al bekende hosts krijgen hun IP bijgewerkt.</span>
    </div>
    <div class="list">
      {#each folders as [folder, items] (folder)}
        <span class="lbl">{folder}</span>
        {#each items as i (i.source)}
          <label class="it" class:off={!i.host} class:known={i.known}>
            <input type="checkbox" disabled={!i.host || i.known} checked={i.known || !!picked[i.source]}
                   onchange={(e) => (picked[i.source] = e.currentTarget.checked)} />
            <span class="k">{KIND[i.kind]}{i.vmid ? ` ${i.vmid}` : ''}</span>
            <b>{i.name}</b>
            <span class="ip">{i.host || '—'}</span>
            <small>{i.known ? 'staat al in de lijst' : i.why || (i.status !== 'running' && i.status !== 'online' ? i.status : '')}</small>
          </label>
        {/each}
      {/each}
    </div>
    <div class="row foot">
      <button class="btn" disabled={busy || (!count && !data.items.some((i) => i.known))} onclick={run}>
        {busy ? 'bezig…' : `${count} toevoegen`}
      </button>
      <button class="btn alt" onclick={onclose}>Annuleren</button>
      <span class="g">{result}</span>
    </div>
    <p class="hint small">Geen IP bij een VM? Installeer de QEMU guest agent (<code>apt install qemu-guest-agent</code>) en
      zet "QEMU Guest Agent" aan bij de VM. Het token heeft <code>VM.Audit</code> nodig, voor VM's ook
      <code>VM.GuestAgent.Audit</code> (Proxmox 9) of <code>VM.Monitor</code> (Proxmox 8).</p>
  {/if}
</Modal>

<style>
  .top { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 6px }
  .list { max-height: 55vh; overflow: auto; padding-right: 4px }
  .it { display: grid; grid-template-columns: 18px 64px minmax(120px, 1fr) 130px minmax(0, 1.3fr); gap: 8px; align-items: center;
        padding: 5px 6px; border-radius: 7px; font-size: 12.5px; cursor: pointer }
  .it:hover { background: var(--fill) }
  .it.off, .it.known { opacity: .55; cursor: default }
  .it b { font-weight: 500; color: var(--text-h); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .k { color: var(--muted); font-size: 11.5px }
  .ip { color: var(--ok) }
  .it small { color: var(--dim); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .foot { margin-top: 12px }
  .g { color: var(--ok); font-size: 12.5px }
  .e { color: var(--err); font-size: 12.5px }
  .small { font-size: 11.5px; margin-top: 10px }
  @media (max-width: 600px) { .it { grid-template-columns: 18px 44px 1fr 110px } .it small { display: none } }
</style>
