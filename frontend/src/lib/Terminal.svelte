<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import HostForm from './HostForm.svelte'
  import SshKeys from './SshKeys.svelte'
  import TermSession from './TermSession.svelte'

  // Terminalvenster: hosts links, open sessies als tabbladen. Sessies blijven lopen als het venster dicht is.
  let { open = false, request = null, services = [], onclose } = $props()

  let hosts = $state([])
  let keys = $state([])
  let tabs = $state([])
  let active = $state(null)
  let modal = $state(null)
  let error = $state('')
  let seq = 0
  let sessions = {}

  async function load() {
    try {
      ;[hosts, keys] = await Promise.all([api('/ssh/hosts'), api('/ssh/keys')])
    } catch (e) {
      error = e.message
    }
  }
  onMount(load)

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

  function closeTab(uid) {
    const i = tabs.findIndex((t) => t.uid === uid)
    tabs.splice(i, 1)
    delete sessions[uid]
    if (active === uid) active = tabs[Math.max(0, i - 1)]?.uid ?? null
  }

  // Vraag van buitenaf (bv. knop in het mini dashboard): open een sessie naar deze host.
  let handled = null
  $effect(() => {
    if (!request || request === handled) return
    handled = request
    load().then(() => {
      const h = hosts.find((x) => x.id === request.hostId)
      if (h) start(h)
    })
  })

  function closeModal() {
    modal = null
    setTimeout(() => sessions[active]?.focus(), 0)
  }

  const dot = { verbinden: 'mid', verbonden: 'ok', fout: 'err', gesloten: 'off' }
</script>

<div class="ov" class:hidden={!open}>
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# ssh</span>
      <div class="right"><button class="mini x" onclick={onclose} aria-label="Terminal sluiten">✕</button></div>
    </div>
    <div class="cols">
      <aside>
        <div class="ah"><span class="lbl">hosts</span><button class="mini" onclick={() => (modal = { kind: 'host', host: null })}>+</button></div>
        {#each hosts as h (h.id)}
          <div class="h">
            <button class="go" onclick={() => start(h)} title="Nieuwe sessie naar {h.username}@{h.host}">
              <b>{h.name}</b><small>{h.username}@{h.host}{h.port !== 22 ? `:${h.port}` : ''}</small>
            </button>
            <button class="mini ed" onclick={() => (modal = { kind: 'host', host: h })} aria-label="Bewerken">✎</button>
          </div>
        {:else}
          <p class="hint">Voeg een host toe. Maak eerst een sleutel aan onder <b>sleutels</b> en zet de publieke sleutel op de server.</p>
        {/each}
        <button class="mini keys" onclick={() => (modal = { kind: 'keys' })}>sleutels ({keys.length})</button>
        {#if error}<p class="err">{error}</p>{/if}
      </aside>
      <section>
        <div class="tabs">
          {#each tabs as t (t.uid)}
            <span class="tab" class:on={active === t.uid}>
              <button class="tb" onclick={() => (active = t.uid)}><i class={dot[t.phase]}></i>{t.host.name}</button>
              {#if t.phase === 'gesloten' || t.phase === 'fout'}
                <button class="tx" onclick={() => sessions[t.uid]?.reconnect()} title="Opnieuw verbinden">↻</button>
              {/if}
              <button class="tx" onclick={() => closeTab(t.uid)} aria-label="Sessie sluiten">✕</button>
            </span>
          {/each}
        </div>
        <div class="stage">
          {#each tabs as t (t.uid)}
            <TermSession bind:this={sessions[t.uid]} host={t.host} active={open && active === t.uid} onstate={(p) => (t.phase = p)} />
          {/each}
          {#if !tabs.length}
            <p class="empty">Kies links een host om een sessie te openen.</p>
          {/if}
        </div>
      </section>
    </div>
  </div>
</div>

{#if modal?.kind === 'host'}
  <HostForm host={modal.host} {keys} {services} onclose={closeModal} onsaved={load}
            onkeys={() => (modal = { kind: 'keys' })} />
{:else if modal?.kind === 'keys'}
  <SshKeys {keys} onclose={closeModal} onchanged={load} />
{/if}

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .cols { flex: 1; display: flex; min-height: 0 }
  aside { width: 230px; flex: none; border-right: 1px solid var(--line); padding: 12px; overflow: auto; display: flex; flex-direction: column; gap: 4px }
  .ah { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px }
  .h { display: flex; gap: 4px; align-items: stretch }
  .go { flex: 1; min-width: 0; text-align: left; background: var(--fill); border: 1px solid rgba(255, 255, 255, .06); border-radius: 8px; padding: 6px 8px; color: var(--text); cursor: pointer; font: inherit }
  .go:hover { background: var(--fill-h) }
  .go b { display: block; font-weight: 500; color: var(--text-h); font-size: 13px }
  .go small { display: block; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .ed { align-self: center }
  .keys { margin-top: auto }
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
  .stage { flex: 1; position: relative; min-height: 0; background: #0c0c0c }
  .empty { color: var(--muted); text-align: center; margin-top: 18vh; font-size: 13px }
  @media (max-width: 700px) {
    .cols { flex-direction: column }
    aside { width: auto; max-height: 30vh; border-right: 0; border-bottom: 1px solid var(--line) }
  }
</style>
