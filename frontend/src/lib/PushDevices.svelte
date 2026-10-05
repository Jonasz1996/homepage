<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Meldingen op je gsm (web push): dit toestel aanmelden en de toestellen beheren. Het dashboard stuurt zelf,
  // via de pushdienst van de browser (Google, Apple, Mozilla); geen extra app of account.
  let { onclose } = $props()

  const LEVELS = { err: 'alleen storingen en herstel', warn: 'ook waarschuwingen', info: 'alles' }

  let items = $state([])
  let error = $state('')
  let busy = $state(false)
  let ready = $state(false)
  let supported = $state(false)
  let reg = null
  let mine = $state(null)
  let lost = $state(false)
  let blocked = $state(false)
  let label = $state(guessLabel())
  let level = $state('err')
  let tested = $state({})

  function guessLabel() {
    const ua = navigator.userAgent
    if (/iPhone|iPod/.test(ua)) return 'iPhone'
    if (/iPad/.test(ua)) return 'iPad'
    const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /SamsungBrowser/.test(ua) ? 'Samsung Internet'
      : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'browser'
    const os = /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : ''
    return os ? `${browser} op ${os}` : browser
  }

  // Zelfde opslag als in de service worker (public/sw.js): die vernieuwt er later het pushadres mee.
  function store(mode, fn) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open('homepage', 1)
      open.onupgradeneeded = () => open.result.createObjectStore('kv')
      open.onerror = () => reject(open.error)
      open.onsuccess = () => {
        const tx = open.result.transaction('kv', mode)
        const req = fn(tx.objectStore('kv'))
        tx.oncomplete = () => { open.result.close(); resolve(req.result) }
        tx.onerror = () => { open.result.close(); reject(tx.error) }
      }
    })
  }

  const keyBytes = (b64) => Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0))
  const keyText = (buf) => buf ? btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : ''

  async function detect() {
    if (!window.isSecureContext || !('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) return
    // Geen registratie: een ontwikkelbuild (de service worker draait alleen in de echte build).
    if (!(await navigator.serviceWorker.getRegistration().catch(() => null))) return
    reg = await navigator.serviceWorker.ready
    supported = true
    blocked = Notification.permission === 'denied'
  }

  async function load() {
    try { items = await api('/webpush/subscriptions'); error = '' } catch (e) { error = e.message }
    if (!reg) return
    // Kent de server dit toestel nog? (bv. weg na "afgemeld" bij de pushdienst, of verwijderd op een ander toestel)
    const sub = await reg.pushManager.getSubscription().catch(() => null)
    const saved = await store('readonly', (s) => s.get('webpush')).catch(() => null)
    const known = !!saved?.id && items.some((i) => i.id === saved.id)
    mine = known ? saved.id : null
    lost = (!!sub && !known) || (!sub && known)
  }

  onMount(async () => {
    await detect()
    await load()
    ready = true
  })

  async function enable() {
    busy = true
    error = ''
    try {
      if ((await Notification.requestPermission()) !== 'granted') {
        blocked = Notification.permission === 'denied'
        throw new Error('Je browser laat geen meldingen toe voor deze site.')
      }
      const { public_key } = await api('/webpush/key')
      let sub = await reg.pushManager.getSubscription()
      // Aangemeld met een andere sleutel (bv. na een herinstallatie): eerst afmelden, anders weigert de pushdienst.
      if (sub && keyText(sub.options?.applicationServerKey) !== public_key) { await sub.unsubscribe(); sub = null }
      sub ||= await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(public_key) })
      const j = sub.toJSON()
      const subscription = { endpoint: j.endpoint, keys: j.keys }
      const saved = await store('readonly', (s) => s.get('webpush')).catch(() => null)
      let r = null
      if (mine && saved?.renew) {
        // De server kent dit toestel nog, alleen het pushadres is nieuw: zelfde rij, naam en keuze houden.
        r = await api('/webpush/subscriptions/renew', { method: 'PUT', body: { id: saved.id, renew: saved.renew, subscription } })
          .then((x) => ({ id: saved.id, renew: x?.renew || saved.renew })).catch(() => null)
      }
      r ||= await withReauth(() => api('/webpush/subscriptions', {
        method: 'POST', body: { ...subscription, label: label.trim() || guessLabel(), min_level: level },
      }))
      await store('readwrite', (s) => s.put({ id: r.id, renew: r.renew, applicationServerKey: public_key }, 'webpush'))
      await load()
      await test(items.find((i) => i.id === r.id))
    } catch (e) { error = e.message } finally { busy = false }
  }

  async function setLevel(d, v) {
    try { await withReauth(() => api(`/webpush/subscriptions/${d.id}`, { method: 'PATCH', body: { min_level: v } })) }
    catch (e) { error = e.message }
    await load()
  }

  async function test(d) {
    if (!d) return
    tested = { ...tested, [d.id]: '…' }
    try {
      const r = await api(`/webpush/subscriptions/${d.id}/test`, { method: 'POST' })
      tested = { ...tested, [d.id]: r.ok ? 'testmelding verstuurd' : '' }
    } catch (e) { error = e.message; tested = { ...tested, [d.id]: '' } }
    await load()
  }

  async function remove(d) {
    if (!confirm(`${d.label} krijgt dan geen meldingen meer. Verwijderen?`)) return
    try {
      await withReauth(() => api(`/webpush/subscriptions/${d.id}`, { method: 'DELETE' }))
      if (d.id === mine) {
        await (await reg?.pushManager.getSubscription())?.unsubscribe()
        await store('readwrite', (s) => s.delete('webpush')).catch(() => {})
      }
    } catch (e) { error = e.message }
    await load()
  }

  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
</script>

<Modal title="Meldingen op je gsm" {onclose}>
  <p class="hint">Storingen en herstel als melding op je gsm, ook als het dashboard dicht is. Het dashboard stuurt ze zelf,
    via de pushdienst van je browser; geen extra app of account.</p>
  {#if error}<p class="err">{error}</p>{/if}

  {#if ready && !supported}
    <p class="hint">Op dit toestel kan het niet. Werkt alleen via https, in Chrome/Edge/Firefox of als app op je beginscherm.</p>
  {:else if ready}
    {#if lost}
      <p class="lost">Dit toestel krijgt geen meldingen meer: opnieuw aanmelden.</p>
    {/if}
    {#if blocked}
      <p class="err">Meldingen staan geblokkeerd voor deze site. Zet ze aan in de instellingen van je browser.</p>
    {/if}
    {#if !mine || lost}
      <div class="form">
        {#if !mine}
          <label class="lbl" for="pd-label">naam van dit toestel</label>
          <input id="pd-label" bind:value={label} maxlength="80" />
          <label class="lbl" for="pd-level">welke meldingen</label>
          <select id="pd-level" bind:value={level}>{#each Object.entries(LEVELS) as [k, l]}<option value={k}>{l}</option>{/each}</select>
        {/if}
        <div><button class="btn" disabled={busy || blocked} onclick={enable}>
          {busy ? 'bezig…' : lost ? 'Opnieuw aanmelden' : 'Dit toestel meldingen laten krijgen'}</button></div>
      </div>
    {/if}
  {/if}

  {#each items as d (d.id)}
    <div class="dev">
      <div class="hh">
        <b>{d.label}</b>{#if d.id === mine}<small class="me">dit toestel</small>{/if}
        <span class="sp"></span>
        <select class="lv" value={d.min_level} onchange={(e) => setLevel(d, e.currentTarget.value)} aria-label="Welke meldingen voor {d.label}">
          {#each Object.entries(LEVELS) as [k, l]}<option value={k}>{l}</option>{/each}
        </select>
        <button class="mini" onclick={() => test(d)}>test</button>
        <button class="mini x" onclick={() => remove(d)}>verwijder</button>
      </div>
      <small>{d.last_ok_at ? `laatst gelukt ${when(d.last_ok_at)}` : 'nog niets afgeleverd'}{#if tested[d.id]}{` · ${tested[d.id]}`}{/if}</small>
      {#if d.last_error}<div class="err">{d.last_error}</div>{/if}
    </div>
  {:else}
    {#if ready}<p class="hint">Nog geen toestellen.</p>{/if}
  {/each}

  <p class="hint small">Op iPhone: eerst Delen → Zet op beginscherm (iOS 16.4 of nieuwer), dan hier aanzetten.
    Op Android: Chrome → Toevoegen aan startscherm.</p>
</Modal>

<style>
  .form { display: flex; flex-direction: column; gap: 4px; margin-bottom: 14px }
  .form .lbl { margin-top: 6px }
  .form .btn { margin-top: 10px }
  .lost { color: var(--mid); font-size: 13px }
  .dev { border-top: 1px solid var(--line); padding: 8px 0 }
  .hh { display: flex; gap: 8px; align-items: center; flex-wrap: wrap }
  .hh b { color: var(--text-h); font-weight: 500 }
  .me { color: var(--ok); font-size: 11.5px }
  .sp { flex: 1 }
  .lv { width: auto; font-size: 12px; padding: 3px 6px }
  .dev small { color: var(--muted); font-size: 11.5px }
  .dev .err { margin-top: 2px; min-height: 0 }
  .small { font-size: 12px; margin-top: 14px }
</style>
