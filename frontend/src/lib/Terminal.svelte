<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import HostForm from './HostForm.svelte'
  import SshDefaults from './SshDefaults.svelte'
  import SshDiscover from './SshDiscover.svelte'
  import SshKeys from './SshKeys.svelte'
  import SshSnippets from './SshSnippets.svelte'
  import TermSession from './TermSession.svelte'

  // Terminalvenster: hosts links (in mappen, doorzoekbaar), open sessies als tabbladen. Sessies blijven lopen
  // als het venster dicht is. Het beste van PuTTY en RDM: snel verbinden, standaard login, hosts uit Proxmox,
  // snippets, typen in alle tabs tegelijk, zoeken in de uitvoer en de log bewaren.
  let { open = false, request = null, services = [], onclose } = $props()

  let hosts = $state([])
  let keys = $state([])
  let defaults = $state(null)
  let snippets = $state([])
  let tabs = $state([])
  let active = $state(null)
  let modal = $state(null)
  let error = $state('')
  let filter = $state('')
  let quick = $state('')
  let broadcast = $state(false)
  let findOpen = $state(false)
  let findText = $state('')
  let snipOpen = $state(false)
  let seq = 0
  let sessions = $state({})

  const pref = (k, d) => { try { return JSON.parse(localStorage.getItem('hp-term-' + k)) ?? d } catch { return d } }
  const savePref = (k, v) => { try { localStorage.setItem('hp-term-' + k, JSON.stringify(v)) } catch { /* */ } }
  let fontSize = $state(pref('font', 13))
  let collapsed = $state(pref('collapsed', {}))

  async function load() {
    try {
      ;[hosts, keys, defaults, snippets] = await Promise.all([
        api('/ssh/hosts'), api('/ssh/keys'), api('/ssh/defaults'), api('/ssh/snippets')])
    } catch (e) {
      error = e.message
    }
  }
  onMount(load)

  let folders = $derived([...new Set(hosts.map((h) => h.folder).filter(Boolean))].sort())
  let tree = $derived.by(() => {
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean)
    const hit = (h) => words.every((w) => `${h.name} ${h.host} ${h.username} ${h.folder}`.toLowerCase().includes(w))
    const out = new Map([['', []]])
    for (const h of [...hosts].sort((a, b) => a.name.localeCompare(b.name))) {
      if (!hit(h)) continue
      if (!out.has(h.folder || '')) out.set(h.folder || '', [])
      out.get(h.folder || '').push(h)
    }
    return [...out].filter(([f, xs]) => xs.length || !f).sort(([a], [b]) => (a === '' ? -1 : b === '' ? 1 : a.localeCompare(b)))
  })

  function toggleFolder(f) {
    collapsed[f] = !collapsed[f]
    savePref('collapsed', collapsed)
  }

  async function start(h) {
    error = ''
    try {
      await withReauth(() => api('/ssh/ready'))
    } catch (e) {
      error = e.message
      return
    }
    const uid = ++seq
    tabs.push({ uid, host: h, phase: 'verbinden' })
    active = uid
  }

  // Snel verbinden zoals in PuTTY/RDM: "root@192.168.0.50:2222", "pve50" of een naam uit de lijst.
  async function quickConnect(e) {
    e.preventDefault()
    const q = quick.trim()
    if (!q) return
    const known = hosts.find((h) => h.name.toLowerCase() === q.toLowerCase() || h.host === q)
    if (known) { quick = ''; return start(known) }
    const m = q.match(/^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9.:_-]+?)(?::(\d+))?$/)
    if (!m) { error = 'Gebruik gebruiker@host:poort'; return }
    try {
      const h = await withReauth(() => api('/ssh/hosts', { method: 'POST', body: {
        name: m[2], host: m[2], port: Number(m[3] || 22), username: m[1] || '', folder: 'snel verbinden' } }))
      quick = ''
      await load()
      start(h)
    } catch (err) { error = err.message }
  }

  function closeTab(uid) {
    const i = tabs.findIndex((t) => t.uid === uid)
    tabs.splice(i, 1)
    delete sessions[uid]
    if (active === uid) active = tabs[Math.max(0, i - 1)]?.uid ?? null
  }

  // Typen in alle verbonden tabs tegelijk (multi-exec), zoals MobaXterm en RDM.
  function typed(uid, d) {
    if (!broadcast) return
    for (const t of tabs) if (t.uid !== uid && t.phase === 'verbonden') sessions[t.uid]?.send(d)
  }

  function sendSnippet(s) {
    snipOpen = false
    const text = s.command + (s.run ? '\r' : '')
    const targets = broadcast ? tabs.filter((t) => t.phase === 'verbonden') : tabs.filter((t) => t.uid === active)
    for (const t of targets) sessions[t.uid]?.send(text)
    sessions[active]?.focus()
  }

  const refocus = () => setTimeout(() => sessions[active]?.focus(), 0)

  function zoom(d) {
    fontSize = Math.min(24, Math.max(9, fontSize + d))
    savePref('font', fontSize)
    refocus()
  }

  function wheel(e) {
    if (!e.ctrlKey) return
    e.preventDefault()
    zoom(e.deltaY < 0 ? 1 : -1)
  }

  function findKey(e) {
    if (e.key === 'Enter') sessions[active]?.find(findText, e.shiftKey)
    if (e.key === 'Escape') { findOpen = false; sessions[active]?.find(''); sessions[active]?.focus() }
  }

  function key(e) {
    if (!open) return
    // Ctrl+Shift+F zoeken, Ctrl+Shift+D tab dupliceren, Ctrl+Shift+←/→ vorige of volgende tab.
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyF') { e.preventDefault(); findOpen = true }
    else if (e.ctrlKey && e.shiftKey && e.code === 'KeyD' && active) { e.preventDefault(); duplicate() }
    else if (e.ctrlKey && e.shiftKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight') && tabs.length > 1) {
      e.preventDefault()
      const i = tabs.findIndex((t) => t.uid === active)
      active = tabs[(i + (e.key === 'ArrowLeft' ? -1 : 1) + tabs.length) % tabs.length].uid
    }
  }

  function duplicate() {
    const t = tabs.find((x) => x.uid === active)
    if (t) start(t.host)
  }

  // Vraag van buitenaf (bv. knop in het mini dashboard): open een sessie naar deze host, of een venster
  // van de terminal (keys, defaults, discover) vanuit de veiligheidscheck of de instellingen-checklist.
  let handled = null
  $effect(() => {
    if (!request || request === handled) return
    handled = request
    load().then(() => {
      if (request.modal) { modal = { kind: request.modal }; return }
      const h = hosts.find((x) => x.id === request.hostId)
      if (h) start(h)
    })
  })

  function closeModal() {
    modal = null
    setTimeout(() => sessions[active]?.focus(), 0)
  }

  const dot = { verbinden: 'mid', verbonden: 'ok', fout: 'err', gesloten: 'off' }
  let connected = $derived(tabs.filter((t) => t.phase === 'verbonden').length)
</script>

<svelte:window onkeydown={key} />

<div class="ov" class:hidden={!open}>
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# ssh</span>
      <div class="right"><button class="mini x" onclick={onclose} aria-label="Terminal sluiten">✕</button></div>
    </div>
    <div class="cols">
      <aside>
        <form class="qc" onsubmit={quickConnect}>
          <input bind:value={quick} placeholder="snel: root@192.168.0.50" aria-label="Snel verbinden" />
        </form>
        <input class="flt" bind:value={filter} placeholder="zoeken…" aria-label="Hosts zoeken" />
        <div class="ah">
          <span class="lbl">hosts ({hosts.length})</span>
          <span>
            <button class="mini" onclick={() => (modal = { kind: 'discover' })} title="Hosts uit Proxmox ophalen">⟳ pve</button>
            <button class="mini" onclick={() => (modal = { kind: 'host', host: null })} title="Host toevoegen">+</button>
          </span>
        </div>
        <div class="list">
          {#each tree as [folder, items] (folder)}
            {#if folder}
              <button class="fold" onclick={() => toggleFolder(folder)}>
                {collapsed[folder] && !filter ? '▸' : '▾'} {folder} <small>{items.length}</small>
              </button>
            {/if}
            {#if !folder || !collapsed[folder] || filter}
              {#each items as h (h.id)}
                <div class="h" class:in={!!folder}>
                  <button class="go" onclick={() => start(h)} ondblclick={(e) => e.preventDefault()}
                          title="Nieuwe sessie naar {h.username || defaults?.username || 'root'}@{h.host}">
                    <b>{h.name}</b><small>{h.username || defaults?.username || 'root'}@{h.host}{h.port !== 22 ? `:${h.port}` : ''}</small>
                  </button>
                  <button class="mini ed" onclick={() => (modal = { kind: 'host', host: h })} aria-label="Bewerken">✎</button>
                </div>
              {/each}
            {/if}
          {/each}
          {#if !hosts.length}
            <p class="hint">Haal je machines op met <b>⟳ pve</b>, of voeg er een toe met +. Stel onder <b>⚙ standaard</b>
              één gebruiker en wachtwoord in voor allemaal.</p>
          {/if}
        </div>
        <div class="foot">
          <button class="mini" onclick={() => (modal = { kind: 'defaults' })} title="Standaard gebruiker en wachtwoord">⚙ standaard</button>
          <button class="mini" onclick={() => (modal = { kind: 'keys' })}>sleutels ({keys.length})</button>
          <button class="mini" onclick={() => (modal = { kind: 'snippets' })}>snippets</button>
        </div>
        {#if error}<p class="err">{error}</p>{/if}
      </aside>
      <section>
        <div class="tabs">
          {#each tabs as t (t.uid)}
            <span class="tab" class:on={active === t.uid}>
              <button class="tb" onclick={() => (active = t.uid)} onauxclick={(e) => e.button === 1 && closeTab(t.uid)}>
                <i class={dot[t.phase]}></i>{t.host.name}</button>
              {#if t.phase === 'gesloten' || t.phase === 'fout'}
                <button class="tx" onclick={() => sessions[t.uid]?.reconnect()} title="Opnieuw verbinden">↻</button>
              {/if}
              <button class="tx" onclick={() => closeTab(t.uid)} aria-label="Sessie sluiten">✕</button>
            </span>
          {/each}
        </div>
        {#if tabs.length}
          <div class="tools">
            <span class="tg">
              <button class="mini" class:bc={broadcast} onclick={() => { broadcast = !broadcast; refocus() }}
                      title="Wat je typt gaat naar alle verbonden tabs">⇶ alle tabs{broadcast ? ` (${connected})` : ''}</button>
              <span class="snip">
                <button class="mini" onclick={() => (snipOpen = !snipOpen)} disabled={!snippets.length}
                        title={snippets.length ? 'Snippet sturen' : 'Nog geen snippets'}>⌘ snippets</button>
                {#if snipOpen}
                  <div class="menu card">
                    {#each snippets as s}
                      <button onclick={() => sendSnippet(s)} title={s.command}><b>{s.name}</b><small>{s.command}</small></button>
                    {/each}
                  </div>
                {/if}
              </span>
              <button class="mini" onclick={duplicate} title="Nog een sessie naar deze host (Ctrl+Shift+D)">⧉</button>
            </span>
            <span class="tg">
              {#if findOpen}
                <!-- svelte-ignore a11y_autofocus -->
                <input class="find" bind:value={findText} onkeydown={findKey} autofocus placeholder="zoeken, Enter / Shift+Enter" />
              {/if}
              <button class="mini" onclick={() => { findOpen = !findOpen; if (!findOpen) sessions[active]?.find('') }} title="Zoeken in de uitvoer (Ctrl+Shift+F)">⌕</button>
              <button class="mini" onclick={() => zoom(-1)} title="Kleiner (Ctrl+scroll)">A−</button>
              <button class="mini" onclick={() => zoom(1)} title="Groter (Ctrl+scroll)">A+</button>
              <button class="mini" onclick={() => { sessions[active]?.clear(); refocus() }} title="Scherm en geschiedenis wissen">⌫</button>
              <button class="mini" onclick={() => sessions[active]?.saveLog()} title="Uitvoer opslaan als .log">⤓ log</button>
            </span>
          </div>
        {/if}
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <div class="stage" class:bcast={broadcast} onwheel={wheel}>
          {#each tabs as t (t.uid)}
            <TermSession bind:this={sessions[t.uid]} host={t.host} active={open && active === t.uid} {fontSize}
                         onstate={(p) => (t.phase = p)} ontyped={(d) => typed(t.uid, d)} />
          {/each}
          {#if !tabs.length}
            <div class="empty">
              <p>Kies links een host om een sessie te openen.</p>
              <p class="hint">Selecteren = kopiëren · rechtsklik = plakken · middenklik = laatste selectie plakken ·
                Ctrl+Shift+C/V · Ctrl+scroll = lettergrootte · Ctrl+Shift+←/→ = andere tab</p>
            </div>
          {/if}
        </div>
      </section>
    </div>
  </div>
</div>

{#if modal?.kind === 'host'}
  <HostForm host={modal.host} {keys} {services} {folders} {defaults} onclose={closeModal} onsaved={load}
            onkeys={() => (modal = { kind: 'keys' })} />
{:else if modal?.kind === 'keys'}
  <SshKeys {keys} {hosts} onclose={closeModal} onchanged={load} />
{:else if modal?.kind === 'defaults'}
  <SshDefaults {defaults} {keys} onclose={closeModal} onsaved={(d) => (defaults = d)} />
{:else if modal?.kind === 'discover'}
  <SshDiscover onclose={closeModal} onimported={load} />
{:else if modal?.kind === 'snippets'}
  <SshSnippets {snippets} onclose={closeModal} onsaved={(s) => (snippets = s)} />
{/if}

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .cols { flex: 1; display: flex; min-height: 0 }
  aside { width: 250px; flex: none; border-right: 1px solid var(--line); padding: 10px; display: flex; flex-direction: column; gap: 6px; min-height: 0 }
  aside input { padding: 7px 10px; font-size: 12.5px }
  .ah { display: flex; justify-content: space-between; align-items: center }
  .ah span { display: flex; gap: 4px }
  .list { flex: 1; overflow: auto; display: flex; flex-direction: column; gap: 3px; min-height: 0 }
  .fold { background: none; border: 0; color: var(--muted); font: inherit; font-size: 12px; text-align: left; cursor: pointer; padding: 6px 2px 2px }
  .fold:hover { color: var(--text-h) }
  .fold small { color: var(--dim) }
  .h { display: flex; gap: 4px; align-items: stretch }
  .h.in { padding-left: 10px }
  .go { flex: 1; min-width: 0; text-align: left; background: var(--fill); border: 1px solid rgba(255, 255, 255, .06); border-radius: 8px; padding: 5px 8px; color: var(--text); cursor: pointer; font: inherit }
  .go:hover { background: var(--fill-h) }
  .go b { display: block; font-weight: 500; color: var(--text-h); font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .go small { display: block; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .ed { align-self: center; opacity: .5 }
  .h:hover .ed { opacity: 1 }
  .foot { display: flex; gap: 4px; flex-wrap: wrap; padding-top: 6px; border-top: 1px solid var(--line) }
  section { flex: 1; min-width: 0; display: flex; flex-direction: column }
  .tabs { display: flex; gap: 4px; padding: 6px 8px 0; border-bottom: 1px solid var(--line); overflow-x: auto; min-height: 36px }
  .tab { display: flex; align-items: center; border: 1px solid var(--line); border-bottom: 0; border-radius: 8px 8px 0 0; background: rgba(255, 255, 255, .03) }
  .tab.on { background: #0c0c0c; border-color: var(--line-2) }
  .tb, .tx { background: none; border: 0; color: var(--text); cursor: pointer; font: inherit; font-size: 12.5px; padding: 6px 8px; white-space: nowrap }
  .tx { color: var(--dim); padding: 6px 6px }
  .tx:hover { color: var(--text-h) }
  .tb i { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 7px; background: #666 }
  .tb i.ok { background: var(--ok) }
  .tb i.mid { background: var(--mid) }
  .tb i.err { background: var(--err) }
  .tools { display: flex; justify-content: space-between; gap: 8px; padding: 5px 8px; background: #0c0c0c; border-bottom: 1px solid rgba(255, 255, 255, .05); flex-wrap: wrap }
  .tg { display: flex; gap: 4px; align-items: center }
  .bc { background: rgba(230, 181, 107, .2); color: var(--mid); border-color: rgba(230, 181, 107, .5) }
  .find { padding: 4px 8px; font-size: 12px; width: 220px }
  .snip { position: relative }
  .menu { position: absolute; top: calc(100% + 4px); left: 0; z-index: 5; min-width: 260px; max-width: 420px; max-height: 50vh; overflow: auto; padding: 6px; display: flex; flex-direction: column; gap: 2px }
  .menu button { background: none; border: 0; text-align: left; padding: 6px 8px; border-radius: 6px; cursor: pointer; color: var(--text); font: inherit }
  .menu button:hover { background: var(--fill-h) }
  .menu b { display: block; font-weight: 500; font-size: 12.5px; color: var(--text-h) }
  .menu small { display: block; color: var(--dim); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .stage { flex: 1; position: relative; min-height: 0; background: #0c0c0c }
  .stage.bcast { box-shadow: inset 0 0 0 2px rgba(230, 181, 107, .45) }
  .empty { color: var(--muted); text-align: center; margin-top: 16vh; font-size: 13px; padding: 0 20px }
  .empty .hint { font-size: 12px; line-height: 1.8 }
  @media (max-width: 700px) {
    .cols { flex-direction: column }
    aside { width: auto; max-height: 34vh; border-right: 0; border-bottom: 1px solid var(--line) }
  }
</style>
