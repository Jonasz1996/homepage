<script>
  import { onMount } from 'svelte'
  import { api, ApiError, withReauth } from './api.js'
  import { dash } from './dash.svelte.js'
  import Modal from './Modal.svelte'
  import ProefPlan from './ProefPlan.svelte'

  // Noodplan: één document om af te drukken, met wat er waar draait, waar de back-ups staan en hoe je alles terugzet.
  // De worker maakt het elke maandag; het document zelf vraagt een recente 2FA (namen, IP- en MAC-adressen).
  // Het staat in een iframe zonder scripts: ook een fout in het escapen kan daar niets uitvoeren.
  let { onclose } = $props()

  let st = $state(null)
  let html = $state('')
  let error = $state('')
  let msg = $state('')
  let busy = $state(false)
  let needAuth = $state(false)
  let plan = $state(null)
  let frame = $state()

  // Afdrukken vanuit het iframe lukt niet in de app (WebView) en op een iPhone of iPad (die drukken de pagina eromheen af).
  const ua = navigator.userAgent
  const noPrint = /wv\)/.test(ua) || /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
  const NO_PRINT = 'Afdrukken lukt hier niet: download het als html en open het in je browser (op een iPhone: open het bestand en kies Deel → Druk af).'

  async function load() {
    try { st = await api('/noodplan'); error = '' } catch (e) { error = e.message }
  }
  onMount(async () => {
    await load()
    if (st?.at) await show()
    if (st?.running) {
      const before = st.at
      await wait()
      if (st?.at && st.at !== before) await show()
    }
  })

  async function show() {
    needAuth = false
    try {
      html = await withReauth(() => api('/noodplan/document?formaat=html'))
      error = ''
    } catch (e) {
      if (e.message === 'Geannuleerd') needAuth = true
      else error = e.message
    }
  }

  async function wait() {
    // Tot een minuut of twee: elke 2 s kijken of het klaar is (ook als de worker het aan het maken is).
    for (let i = 0; i < 60 && st?.running; i++) {
      await new Promise((r) => setTimeout(r, 2000))
      await load()
    }
  }
  async function runNow() {
    busy = true
    msg = ''
    plan = null
    const before = st?.at
    const failedBefore = st?.failed?.at
    try {
      try {
        await api('/noodplan/run', { method: 'POST' })
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 409)) throw e
        msg = 'Loopt al'
      }
      await load()
      await wait()
      if (st?.running) msg = '✕ nog bezig: kijk straks opnieuw'
      else if (st?.at && st.at !== before) {
        msg = '✓ bijgewerkt'
        await show()
      } else if (st?.failed && st.failed.at !== failedBefore) msg = `✕ niet bijgewerkt: ${st.failed.error}`
      else msg = '✕ niet bijgewerkt: kijk in de log (journalctl -u homepage-api)'
    } catch (e) { msg = `✕ ${e.message}` } finally { busy = false }
  }
  async function proef() {
    plan = null
    try { plan = await api('/noodplan/proef', { method: 'POST' }); error = '' } catch (e) { error = e.message }
  }

  function print() {
    msg = ''
    if (noPrint || !frame?.contentWindow) { msg = NO_PRINT; return }
    try { frame.contentWindow.print() } catch { msg = NO_PRINT }
  }
  async function download(fmt) {
    msg = ''
    try {
      const text = fmt === 'html' && html ? html : await withReauth(() => api(`/noodplan/document?formaat=${fmt}`))
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([text], { type: fmt === 'html' ? 'text/html' : 'text/markdown' }))
      a.download = `noodplan-${day(st.at)}.${fmt}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    } catch (e) {
      if (e.message !== 'Geannuleerd') msg = `✕ ${e.message}`
    }
  }

  // Zo hoog als het document: het venster scrolt, niet het iframe (ook na het draaien van de gsm).
  function fit() {
    const doc = frame?.contentDocument
    if (doc?.documentElement) frame.style.height = doc.documentElement.scrollHeight + 'px'
  }

  const pad = (n) => String(n).padStart(2, '0')
  const day = (ts) => { const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` }
  const DAYS = ['zo', 'ma', 'di', 'wo', 'do', 'vr', 'za']
  const full = (ts) => { const d = new Date(ts); return `${DAYS[d.getDay()]} ${d.getDate()}/${d.getMonth() + 1} ${pad(d.getHours())}:${pad(d.getMinutes())}` }
  const short = (ts) => { const d = new Date(ts); return `${d.getDate()}/${d.getMonth() + 1}` }
  let running = $derived(busy || !!st?.running)
  let bad = $derived((st?.sources || []).filter((s) => !s.ok))
</script>

<svelte:window onresize={fit} />

<Modal title="less noodplan.html" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if !st && !error}<p class="hint">laden…</p>
  {:else if st}
    {#if st.at}
      <p class="small">Bijgewerkt {full(st.at)}{#if st.next} · volgende: maandag {short(st.next)} rond 6:00{/if}{#if st.trigger === 'knop' && st.by} · op vraag van {st.by}{/if}</p>
    {:else}
      <p class="small">Nog geen noodplan. Het dashboard maakt het elke maandagochtend, of nu met <b>nu bijwerken</b>.</p>
    {/if}

    <div class="row">
      <button class="mini" disabled={!html} onclick={print}>afdrukken</button>
      <button class="mini" disabled={!st.at} onclick={() => download('html')} title="Om te bewaren of later in je browser af te drukken">↓ html</button>
      <button class="mini" disabled={!st.at} onclick={() => download('md')} title="Hetzelfde als platte tekst (Markdown)">↓ tekst</button>
      <button class="mini" disabled={running} onclick={runNow}>{running ? 'bijwerken…' : 'nu bijwerken'}</button>
      <button class="mini" disabled={running} onclick={proef} title="Toon wat nu bijwerken zou doen, zonder het te doen">proef</button>
    </div>
    {#if running}<p class="small m">Dit duurt tot een minuut.{#if st.running_by === 'worker'} De worker is ermee bezig.{/if}</p>{/if}
    {#if msg}<p class="small" class:e={msg.startsWith('✕')} class:g={msg.startsWith('✓')}>{msg}</p>
    {:else if st.failed && !running}<p class="small e">✕ De laatste poging ({full(st.failed.at)}) mislukte: {st.failed.error}</p>{/if}

    {#each bad as s (s.key)}
      <p class="small w">{s.name}: {s.error || 'fout'}.
        {#if s.covered}Dezelfde cluster staat er via {s.covered}.{:else if s.from}Dit deel komt uit het noodplan van {short(s.from)}.{:else}Dit deel ontbreekt: het lukte nog nooit.{/if}</p>
    {/each}
    {#if st.masked}
      <p class="small w">Er stond iets in dat op een geheim leek ({(st.masked_kinds || []).join(', ')}); dat is vervangen door ***. Kijk na waar het staat.</p>
    {/if}
    {#each (st.problems || []).filter((p) => p.key === 'oud') as p (p.key)}<p class="small w">Verouderd: {p.text}.</p>{/each}

    {#if st.offsite?.enabled && st.offsite.error}
      <p class="small e">✕ Niet in {st.offsite.dir}: {st.offsite.error}</p>
    {:else if st.offsite?.enabled && st.offsite.at}
      <p class="small g">✓ Ook in {st.offsite.dir} ({full(st.offsite.at)}): noodplan.html en noodplan.md</p>
    {:else if !st.offsite?.enabled}
      <p class="small m">Alleen in het dashboard. Zet de kopie buiten de container aan, dan heb je het ook als het dashboard plat ligt.
        <button class="mini" onclick={() => dash.open('health', { tab: 'homepage' })}>instellen</button></p>
    {/if}

    {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}

    {#if needAuth}
      <p class="small">Het noodplan bevat namen, IP- en MAC-adressen: bevestig met je 2FA-code om het te tonen.
        <button class="mini" onclick={show}>tonen</button></p>
    {/if}
    {#if html}
      <iframe class="paper" title="Noodplan" sandbox="allow-same-origin allow-modals allow-popups allow-popups-to-escape-sandbox"
              srcdoc={html} bind:this={frame} onload={fit}></iframe>
    {/if}
    <p class="hint">Er staan geen wachtwoorden of sleutels in, alleen waar ze staan. Druk het af na grote wijzigingen en bewaar
      de afdruk veilig: er staan IP-adressen en namen in.</p>
  {/if}
</Modal>

<style>
  .row { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 }
  .paper { display: block; width: 100%; min-height: 300px; border: 0; border-radius: 6px; background: #fff; margin-top: 8px }
  .small { font-size: 12px; margin: 3px 0 }
  .m { color: var(--muted) }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .w { color: var(--mid) }
</style>
