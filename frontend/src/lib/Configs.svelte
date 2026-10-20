<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Configuratiewijzigingen: elke nacht een kopie van OPNsense, NPM, Proxmox en gekozen bestanden, met een diff.
  let { onclose, initialItem = null } = $props()

  let data = $state(null)
  let error = $state('')
  let tab = $state('lijst')
  let sel = $state(null) // gekozen item
  let versions = $state([])
  let cur = $state(null) // { version, against, diff }
  let cfg = $state(null)
  let hosts = $state([])
  let msg = $state('')
  let busy = $state(false)

  const KIND = { opnsense: 'OPNsense', npm: 'Nginx Proxy Manager', pve: 'Proxmox: VM en CT', file: 'Bestanden' }

  async function load() {
    try {
      data = await api('/configs')
      error = ''
      if (!cfg) cfg = JSON.parse(JSON.stringify(data.settings))
    } catch (e) { error = e.message }
  }
  onMount(async () => {
    await load()
    // Geopend vanuit de zoekbalk: meteen die configuratie tonen.
    const it = initialItem && data?.items.find((x) => x.item === initialItem)
    if (it) pick(it)
  })

  async function pick(it) {
    sel = it
    cur = null
    try {
      versions = await api(`/configs/versions?item=${encodeURIComponent(it.item)}`)
      if (versions.length) await show(versions[0])
    } catch (e) { error = e.message }
  }
  async function show(v, against = null) {
    try {
      cur = await api(`/configs/versions/${v.id}/diff${against ? `?against=${against}` : ''}`)
    } catch (e) { error = e.message }
  }
  async function download(v) {
    try {
      const text = await withReauth(() => api(`/configs/versions/${v.id}/download`))
      const a = document.createElement('a')
      const base = v.name.split(' · ').pop().split('/').pop().replace(/ /g, '_') || 'config'
      a.href = URL.createObjectURL(new Blob([typeof text === 'string' ? text : JSON.stringify(text, null, 1)], { type: 'text/plain' }))
      a.download = `${stamp(v.ts)}-${base}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    } catch (e) { error = e.message }
  }
  async function runNow() {
    busy = true
    msg = ''
    try {
      await api('/configs/run', { method: 'POST' })
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        await load()
        if (!data?.running) break
      }
      msg = data?.last ? `✓ ${data.last.items} configuraties bekeken, ${data.last.changed} gewijzigd` : ''
    } catch (e) { msg = `✕ ${e.message}` } finally { busy = false }
  }

  async function openSettings() {
    tab = 'instellingen'
    if (!hosts.length) try { hosts = await api('/ssh/hosts') } catch (e) { error = e.message }
  }
  async function save() {
    msg = ''
    try {
      const body = { ...cfg, hour: Number(cfg.hour), files: cfg.files.filter((f) => f.host_id && f.path.trim()).map((f) => ({ host_id: Number(f.host_id), path: f.path.trim() })) }
      cfg = await withReauth(() => api('/configs/settings', { method: 'PUT', body }))
      msg = '✓ bewaard'
      await load()
    } catch (e) { msg = `✕ ${e.message}` }
  }

  const stamp = (ts) => new Date(ts).toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-')
  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  const lineClass = (l) => (l.startsWith('+++') || l.startsWith('---') ? 'h' : l.startsWith('@@') ? 'at' : l[0] === '+' ? 'add' : l[0] === '-' ? 'del' : '')
  let groups = $derived.by(() => {
    const g = {}
    for (const it of data?.items || []) (g[it.kind] ||= []).push(it)
    return Object.entries(g)
  })
</script>

<Modal title="git log -p /etc" {onclose} wide>
  <div class="tabs">
    <button class="mini" class:on={tab === 'lijst'} onclick={() => (tab = 'lijst')}>configuraties</button>
    <button class="mini" class:on={tab === 'instellingen'} onclick={openSettings}>instellingen</button>
    <span class="sp"></span>
    <button class="mini" disabled={busy || data?.running} onclick={runNow}>{busy || data?.running ? 'ophalen…' : 'nu ophalen'}</button>
  </div>
  {#if error}<p class="err">{error}</p>{/if}
  {#if msg}<p class="small" class:e={msg.startsWith('✕')} class:g={msg.startsWith('✓')}>{msg}</p>{/if}
  {#if data?.last?.errors?.length}{#each data.last.errors as e}<p class="e small">{e.source}: {e.error}</p>{/each}{/if}

  {#if tab === 'lijst'}
    {#if !data}<p class="hint">laden…</p>
    {:else if !data.items.length}
      <p class="hint">Nog geen kopieën. Elke nacht om {data.settings.hour}:00 haalt de homepage de config.xml van OPNsense, de
        proxy hosts van NPM en de .conf van elke VM en container op, plus de bestanden die je onder <b>instellingen</b> kiest.
        Klik op <b>nu ophalen</b> voor een eerste kopie.</p>
    {:else}
      <div class="split">
        <div class="list">
          {#each groups as [kind, items]}
            <span class="lbl">{KIND[kind] || kind}</span>
            {#each items as it (it.item)}
              <button class="it" class:on={sel?.item === it.item} onclick={() => pick(it)}>
                <span class="nm">{it.name}</span>
                <small>{it.versions} versie{it.versions === 1 ? '' : 's'} · {when(it.ts)}
                  {#if it.added || it.removed}<span class="add">+{it.added}</span> <span class="del">−{it.removed}</span>{/if}</small>
              </button>
            {/each}
          {/each}
          {#if data.last}<p class="hint small">laatst opgehaald {when(data.last.at)}</p>{/if}
        </div>
        <div class="view">
          {#if !sel}<p class="hint">Kies links een configuratie om de wijzigingen te zien.</p>
          {:else}
            <div class="vers">
              {#each versions as v, i (v.id)}
                <div class="v" class:on={cur?.version.id === v.id}>
                  <button class="link" onclick={() => show(v)}>{when(v.ts)}</button>
                  <small>{i === versions.length - 1 ? 'eerste kopie' : `+${v.added} −${v.removed}`}</small>
                  {#if cur && cur.version.id !== v.id && v.ts < cur.version.ts}
                    <button class="mini" title="Vergelijk de gekozen versie met deze" onclick={() => show(cur.version, v.id)}>vergelijk</button>
                  {/if}
                  <button class="mini" title="Volledige inhoud downloaden (vraagt 2FA)" onclick={() => download(v)}>↓</button>
                </div>
              {/each}
            </div>
            {#if cur}
              <p class="small m">{cur.against ? `${when(cur.against.ts)} → ${when(cur.version.ts)}` : 'eerste kopie'} · wachtwoorden en sleutels zijn gemaskeerd</p>
              <pre class="diff">{#each (cur.diff || '(geen verschil)').split('\n') as l}<span class={lineClass(l)}>{l}
</span>{/each}</pre>
            {/if}
          {/if}
        </div>
      </div>
    {/if}
  {:else if cfg}
    <div class="form">
      <label class="row">Elke nacht om
        <select bind:value={cfg.hour}>{#each Array(24) as _, h}<option value={h}>{String(h).padStart(2, '0')}:00</option>{/each}</select></label>
      <label class="chk"><input type="checkbox" bind:checked={cfg.opnsense} /> OPNsense: config.xml (API-recht "Diagnostics: Configuration History")</label>
      <label class="chk"><input type="checkbox" bind:checked={cfg.npm} /> Nginx Proxy Manager: proxy hosts, redirections, streams</label>
      <label class="chk"><input type="checkbox" bind:checked={cfg.pve} /> Proxmox: de .conf van elke VM en container</label>
      <span class="lbl">Eigen bestanden of mappen (via SSH, tot 256 kB per bestand)</span>
      {#each cfg.files as f, i}
        <div class="row">
          <select bind:value={f.host_id}>
            <option value={null}>host…</option>
            {#each hosts as h}<option value={h.id}>{h.name}</option>{/each}
          </select>
          <input class="path" bind:value={f.path} placeholder="/etc/nginx" />
          <button class="mini x" onclick={() => cfg.files.splice(i, 1)} aria-label="Weg">✕</button>
        </div>
      {/each}
      <div class="row">
        <button class="mini" onclick={() => cfg.files.push({ host_id: null, path: '' })}>+ bestand of map</button>
        <span class="sp"></span>
        <button class="mini" onclick={save}>bewaren</button>
      </div>
      <p class="hint small">Een map wordt volledig gelezen (alleen tekstbestanden). Een nieuwe versie wordt alleen bewaard als
        er iets veranderd is; je krijgt dan een melding en een regel op de tijdlijn. De laatste 90 versies per bestand blijven
        bewaard, versleuteld.</p>
    </div>
  {/if}
</Modal>

<style>
  .tabs { display: flex; gap: 6px; margin-bottom: 12px; align-items: center }
  .sp { flex: 1 }
  .split { display: grid; grid-template-columns: minmax(200px, 280px) 1fr; gap: 14px }
  .list { display: flex; flex-direction: column; gap: 2px; max-height: 68vh; overflow: auto }
  .it { all: unset; cursor: pointer; display: flex; flex-direction: column; padding: 6px 8px; border-radius: 8px; font-size: 12.5px }
  .it:hover { background: var(--fill) }
  .it.on { background: rgba(169, 199, 255, .1) }
  .it .nm { color: var(--text-h); word-break: break-all }
  .it small, .m { color: var(--muted); font-size: 11.5px }
  .view { min-width: 0 }
  .vers { display: flex; flex-direction: column; max-height: 160px; overflow: auto; margin-bottom: 8px }
  .v { display: flex; gap: 8px; align-items: center; font-size: 12px; padding: 2px 4px; border-radius: 6px }
  .v.on { background: rgba(169, 199, 255, .1) }
  .v small { flex: 1; color: var(--muted) }
  .link { all: unset; cursor: pointer; color: #a9c7ff }
  .diff { margin: 0; padding: 10px; border-radius: 8px; background: rgba(0, 0, 0, .35); font-size: 11.5px; line-height: 1.45;
          max-height: 52vh; overflow: auto; white-space: pre-wrap; word-break: break-all }
  .diff span { display: block }
  .add { color: var(--ok) }
  .del { color: var(--err) }
  .diff .add { background: rgba(110, 220, 150, .08) }
  .diff .del { background: rgba(255, 110, 110, .08) }
  .diff .at { color: #a9c7ff }
  .diff .h { color: var(--muted) }
  .form { display: flex; flex-direction: column; gap: 8px; font-size: 12.5px }
  .row { display: flex; gap: 8px; align-items: center }
  .row select { width: auto }
  .path { flex: 1 }
  .chk { display: flex; gap: 6px; align-items: center }
  .chk input { width: auto }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .small { font-size: 11.5px; margin: 4px 0 }
  @media (max-width: 700px) { .split { grid-template-columns: 1fr } .list { max-height: 30vh } }
</style>
