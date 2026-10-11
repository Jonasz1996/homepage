<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import { ask } from './dialog.svelte.js'
  import { copyText } from './copy.js'
  import { dash } from './dash.svelte.js'
  import CopyCmd from './CopyCmd.svelte'
  import ProefPlan from './ProefPlan.svelte'

  // net → check van buitenaf: een gratis Cloudflare Worker bekijkt de gekozen tegels vanuit het netwerk van Cloudflare.
  // Het dashboard vraagt hem elke minuut om de tegels met het oudste resultaat; de Worker belt zelf nooit naar hier.
  // Geheimen komen nooit in de browser, behalve het geheim dat je bij zelf plakken hier zelf maakt (één keer getoond).
  let data = $state(null)
  let error = $state('')
  let busy = $state('')
  let msg = $state('')
  let plan = $state(null)
  // Het formulier: één keer gevuld uit wat bewaard is, zodat het verversen elke 30 s niets overschrijft.
  let filled = false
  let apiId = $state(null)
  let domains = $state('')
  let workerUrl = $state('')
  // Zelf plakken: het geheim dat deze browser maakte, en het script om te kopiëren.
  let secret = $state('')
  let script = $state(null)
  let copied = $state(false)
  let view = $state('gecheckt')
  let voorstel = $state(null)
  let picked = $state({})

  async function load() {
    try {
      const d = await api('/buitencheck')
      data = d
      error = ''
      if (!filled) {
        apiId = d.api?.id ?? null
        domains = d.suffixes.join(', ')
        workerUrl = d.worker_url || ''
        filled = true
      }
    } catch (e) { error = e.message }
  }
  onMount(() => {
    load()
    return poll(load, 30000)
  })

  const hhmm = (ts) => (ts ? new Date(ts).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' }) : '')
  const suffixes = () => domains.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  const host = (url) => { try { return new URL(url).host } catch { return url || '' } }

  let tiles = $derived(data?.tiles || [])
  let down = $derived(tiles.filter((t) => t.vanbuiten.status === 'down').length)
  let waiting = $derived(tiles.filter((t) => t.vanbuiten.status === 'wacht').length)
  let withToken = $derived((data?.apis || []).filter((a) => a.workers_token))
  let paste = $derived(data?.how === 'plakken')
  let checked = $derived(Object.values(picked).filter(Boolean).length)

  // Waarom een tegel die van buitenaf stuk is geen eigen melding kreeg.
  const QUIET = {
    groep: 'gemeld als groep', massa: 'gemeld als massastoring', dashboard: 'stil: thuis is bijna alles stuk',
    onderhoud: 'stil: onderhoud', pauze: 'stil: check gepauzeerd', thuis: 'stil: thuis ook stuk',
    ouder: 'stil: wat erboven hangt is stuk', npm: 'stil: NPM is stuk', tunnel: 'stil: tunnel al gemeld',
  }
  function line(t) {
    const b = t.vanbuiten
    if (b.status === 'wacht') return { text: b.at ? 'wacht op een nieuwe check' : 'wacht op de eerste check', cls: 'm' }
    const home = t.inside === 'up' ? 'thuis ✓ · ' : t.inside === 'down' ? 'thuis ✕ · ' : ''
    if (b.status === 'up') return { text: `${home}buiten ✓${b.ms != null ? ` ${b.ms} ms` : ''}`, cls: 'g' }
    if (b.quiet) return { text: `buiten ✕ · ${QUIET[b.quiet] || `stil: ${b.quiet}`}`, cls: 'm' }
    // Thuis ook stuk: die melding kwam al van de check van binnenuit.
    if (t.inside === 'down') return { text: 'thuis ✕ · buiten ✕', cls: 'm' }
    return { text: `${home}buiten ✕`, cls: 'e' }
  }
  function testLine(r) {
    if (r.error) return `✕ ${r.error}`
    const extra = r.promoted ? ' · nieuw geheim in gebruik' : ''
    if (!r.service) return `✓ De Worker antwoordt${r.colo ? ` vanuit ${r.colo}` : ''}${extra}`
    if (!r.ok) return `✕ ${r.service}: ${r.why || `HTTP ${r.code}`}${extra}`
    return `✓ ${r.service}: ${r.code} in ${r.ms} ms${r.colo ? ` vanuit ${r.colo}` : ''}${r.note ? ` · ${r.note}` : ''}${extra}`
  }

  async function run(what, fn) {
    busy = what
    msg = ''
    try { await fn(); error = '' } catch (e) { error = e.message } finally { busy = '' }
  }

  // --- in Cloudflare zetten ---------------------------------------------------------------------------------
  const deployBody = (rotate) => ({ rotate, api_id: apiId, suffixes: suffixes().length ? suffixes() : null })
  const proef = (rotate = false) => run('proef', async () => {
    plan = (await api('/buitencheck/deploy/proef', { method: 'POST', body: deployBody(rotate) })).plan
  })
  async function deploy(rotate = false) {
    const q = !data.ready ? ['De Worker in je Cloudflare-account zetten?', 'Zetten']
      : rotate ? ['Een nieuw geheim maken en de Worker opnieuw zetten? Het oude blijft gelden tot dat lukt.', 'Opnieuw zetten']
      : ['De Worker opnieuw in Cloudflare zetten, met hetzelfde geheim?', 'Opnieuw zetten']
    if (!(await ask(q[0], { ok: q[1] }))) return
    await run('deploy', async () => {
      const r = await withReauth(() => api('/buitencheck/deploy', { method: 'POST', body: deployBody(rotate) }))
      plan = null
      await load()
      msg = `Gezet. Test: ${testLine(r.test)}`
    })
  }
  async function removeToken() {
    if (!(await ask('Het Workers-token uit API-beheer weghalen? Opnieuw zetten kan pas als je het terugzet.', { ok: 'Weghalen' }))) return
    await run('token', async () => {
      data = await api(`/buitencheck/workers-token${data.api ? `?api_id=${data.api.id}` : ''}`, { method: 'DELETE' })
    })
  }

  // --- zelf plakken -----------------------------------------------------------------------------------------
  function newSecret() {
    // 32 willekeurige bytes, base64url: 43 tekens.
    const b = crypto.getRandomValues(new Uint8Array(32))
    return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  const makeSecret = () => run('secret', async () => {
    const s = newSecret()
    await withReauth(() => api('/buitencheck/token', { method: 'POST', body: { token: s } }))
    secret = s
    await load()
  })
  async function loadScript() {
    if (!script) script = await api('/buitencheck/script')
    return script
  }
  const copyScript = () => run('script', async () => {
    copied = await copyText((await loadScript()).script)
    if (copied) setTimeout(() => (copied = false), 1500)
  })
  function showScript(e) {
    if (e.currentTarget.open) loadScript().catch((x) => (error = x.message))
  }
  const testAndEnable = () => run('test', async () => {
    await withReauth(() => api('/buitencheck/settings', { method: 'PUT', body: { worker_url: workerUrl.trim() || null } }))
    const r = await api('/buitencheck/test', { method: 'POST', body: { next: true } })
    if (r.promoted) secret = ''
    await load()
    msg = testLine(r)
  })
  const pasted = () => run('test', async () => {
    const r = await api('/buitencheck/test', { method: 'POST', body: { next: true } })
    if (r.promoted) secret = ''
    await load()
    msg = testLine(r)
  })
  const cancelNext = () => run('cancel', async () => {
    data = await api('/buitencheck/token-next', { method: 'DELETE' })
    secret = ''
  })

  // --- ingesteld --------------------------------------------------------------------------------------------
  const testNow = () => run('test', async () => {
    msg = testLine(await api('/buitencheck/test', { method: 'POST', body: {} }))
  })
  async function toggle() {
    if (data.enabled && !(await ask('De check van buitenaf uitzetten? Dan merkt het dashboard niet meer als iets alleen van buitenaf stuk is.', { ok: 'Uitzetten', danger: true }))) return
    await run('toggle', async () => {
      data = await withReauth(() => api('/buitencheck/settings', { method: 'PUT', body: { enabled: !data.enabled } }))
    })
  }
  function rotate() {
    if (paste) makeSecret()
    else deploy(true)
  }

  // --- tegels -----------------------------------------------------------------------------------------------
  async function openVoorstel(which) {
    view = which
    if (voorstel) return
    try {
      voorstel = await api('/buitencheck/voorstel')
      picked = Object.fromEntries(voorstel.suggest.map((x) => [x.id, x.pick]))
    } catch (e) { error = e.message }
  }
  const addTiles = () => run('tiles', async () => {
    const add = Object.keys(picked).filter((k) => picked[k]).map(Number)
    await api('/buitencheck/tiles', { method: 'PUT', body: { add } })
    voorstel = null
    picked = {}
    view = 'gecheckt'
    await load()
  })
  async function removeTile(t) {
    if (!(await ask(`${t.name} niet meer van buitenaf checken? Dan merkt het dashboard het niet als dit van buitenaf uitvalt.`, { ok: 'Weghalen', danger: true }))) return
    await run('tiles', async () => {
      await withReauth(() => api('/buitencheck/tiles', { method: 'PUT', body: { remove: [t.id] } }))
      voorstel = null
      await load()
    })
  }
</script>

{#if error}<p class="err">{error}</p>{/if}
{#if !data}
  {#if !error}<p class="hint">laden…</p>{/if}
{:else}
  {#if !data.ready}
    <p class="hint">Alle checks lopen nu van binnenuit, rechtstreeks naar de server. Een gratis Cloudflare Worker kan je
      tegels ook van buitenaf bekijken, zoals een bezoeker op het internet. Zo zie je een tunnel, NPM of DNS die van
      buitenaf stuk is terwijl thuis alles werkt.</p>
    <div class="ways">
      <section class="box">
        <b>Via Cloudflare zetten (aanbevolen)</b>
        {#if data.apis.length}
          <label class="lbl" for="bc-api">Cloudflare-API</label>
          <select id="bc-api" bind:value={apiId}>
            {#each data.apis as a (a.id)}<option value={a.id}>{a.name}{a.workers_token ? '' : ' (zonder workers_token)'}</option>{/each}
          </select>
        {/if}
        {#if !withToken.length}
          <p class="hint small">Nog geen Cloudflare-API met workers_token. Voeg het geheim workers_token toe in API-beheer
            (soort Cloudflare Tunnel, met je account-id).
            <button class="mini" onclick={() => dash.open('apis')}>API-beheer openen</button></p>
        {/if}
        <label class="lbl" for="bc-dom">Domeinen</label>
        <input id="bc-dom" type="text" bind:value={domains} placeholder="jbogaert.be" autocomplete="off" />
        <div class="btns">
          <button class="mini" disabled={!!busy} onclick={() => proef()}>{busy === 'proef' ? 'bezig…' : 'proef'}</button>
          <button class="mini" disabled={!!busy || !withToken.length} onclick={() => deploy()}>{busy === 'deploy' ? 'bezig…' : 'In Cloudflare zetten'}</button>
        </div>
      </section>
      <section class="box">
        <b>Zelf plakken</b>
        <ol class="steps">
          <li>Klik op geheim maken. Je ziet het één keer: laat dit venster open tot stap 4.
            <div class="btns"><button class="mini" disabled={!!busy} onclick={makeSecret}>geheim maken</button></div>
            {#if secret}
              <CopyCmd cmd={secret} />
              <small class="w">Plak dit als HOMEPAGE_TOKEN in Cloudflare. Je ziet het hier niet meer terug.</small>
            {/if}
          </li>
          <li>Cloudflare → Workers &amp; Pages → Create → Start with Hello World. Naam: <b>{data.name || 'homepage-buitencheck-… (na stap 1)'}</b>. Deploy.</li>
          <li>Edit code: vervang alles door het script (script kopiëren) en klik Deploy.
            <div class="btns"><button class="mini" disabled={!!busy} onclick={copyScript}>{copied ? '✓ gekopieerd' : 'script kopiëren'}</button></div>
            <details ontoggle={showScript}>
              <summary>script bekijken</summary>
              {#if script}<pre class="script">{script.script}</pre>{:else}<p class="hint small">laden…</p>{/if}
            </details>
          </li>
          <li>Settings → Variables and Secrets: voeg HOMEPAGE_TOKEN toe als Secret (het geheim van stap 1) en
            ALLOWED_SUFFIXES als Text (<b>{data.suffixes.join(',') || 'jbogaert.be'}</b>).</li>
          <li>Kopieer het adres van de Worker (…workers.dev), plak het hieronder en klik testen en aanzetten.
            <label class="lbl" for="bc-url">Adres van je Worker</label>
            <input id="bc-url" type="url" bind:value={workerUrl} autocomplete="off"
                   placeholder={`https://${data.name || 'homepage-buitencheck-…'}.<naam>.workers.dev`} />
            <div class="btns"><button class="mini" disabled={!!busy || !workerUrl.trim()} onclick={testAndEnable}>{busy === 'test' ? 'bezig…' : 'testen en aanzetten'}</button></div>
          </li>
        </ol>
      </section>
    </div>
  {:else}
    <div class="head">
      {#if !data.enabled}
        <b class="m">Uit</b>
      {:else if data.worker.error && data.worker.fail}
        <b class="e">Worker antwoordt niet: {data.worker.error}</b>
      {:else if data.worker.ok_at}
        <b class="g">Worker in orde · laatst {hhmm(data.worker.ok_at)} vanuit {data.worker.colo || '?'}</b>
      {:else}
        <b class="m">Wacht op de eerste ronde</b>
      {/if}
      <small>{tiles.length} tegels · {down} down · {waiting} wachten</small>
    </div>
    {#if data.mass}
      <p class="banner e">Van buitenaf is bijna niets bereikbaar sinds {hhmm(data.mass.since)}: {data.mass.why}</p>
    {/if}
    {#each data.groups as g (g.cause)}
      <p class="banner e">{g.count} tegels van buitenaf onbereikbaar sinds {hhmm(g.since)}: {g.why}</p>
    {/each}
    {#if data.token_next_at}
      <div class="banner w">
        <span>Er wacht een nieuw geheim sinds {hhmm(data.token_next_at)}. Het vorige werkt nog tot de Worker het nieuwe kent.</span>
        {#if secret}<CopyCmd cmd={secret} /><small>Plak dit als HOMEPAGE_TOKEN in Cloudflare. Je ziet het hier niet meer terug.</small>{/if}
        <div class="btns">
          <button class="mini" disabled={!!busy} onclick={pasted}>ik heb het geplakt</button>
          <button class="mini" disabled={!!busy} onclick={cancelNext}>annuleren</button>
        </div>
      </div>
    {/if}
    {#if data.deployed && data.api?.workers_token}
      <div class="banner">
        <span>Het token met Workers Scripts → Edit is alleen nodig om de Worker opnieuw te zetten.</span>
        <button class="mini" disabled={!!busy} onclick={removeToken}>token weghalen</button>
      </div>
    {/if}
    {#if data.worker.script != null && data.worker.script < data.script_version}
      <div class="banner w">
        <span>Er is een nieuwe versie van de Worker: zet hem opnieuw.</span>
        {#if !paste}<button class="mini" disabled={!!busy} onclick={() => proef()}>proef</button>{/if}
      </div>
    {/if}
    <div class="btns">
      <button class="mini" disabled={!!busy} onclick={testNow}>{busy === 'test' ? 'bezig…' : 'test nu'}</button>
      <button class="mini" disabled={!!busy} onclick={toggle}>{data.enabled ? 'uitzetten' : 'aanzetten'}</button>
      <button class="mini" disabled={!!busy} onclick={rotate}>nieuw geheim</button>
      {#if paste}
        <button class="mini" disabled={!!busy} onclick={copyScript}>{copied ? '✓ gekopieerd' : 'script kopiëren'}</button>
      {:else}
        <button class="mini" disabled={!!busy} onclick={() => proef()}>proef</button>
        <button class="mini" disabled={!!busy} onclick={() => deploy()}>opnieuw zetten</button>
      {/if}
    </div>
  {/if}

  {#if msg}<p class="small" class:e={msg.startsWith('✕') || msg.includes(' ✕ ')} class:g={!msg.startsWith('✕') && !msg.includes(' ✕ ')}>{msg}</p>{/if}
  {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}

  <div class="seg" role="group" aria-label="Tegels">
    <button class="mini" class:on={view === 'gecheckt'} aria-pressed={view === 'gecheckt'} onclick={() => (view = 'gecheckt')}>gecheckt ({tiles.length})</button>
    <button class="mini" class:on={view === 'voorstel'} aria-pressed={view === 'voorstel'} onclick={() => openVoorstel('voorstel')}>voorstel{voorstel ? ` (${voorstel.suggest.length})` : ''}</button>
    <button class="mini" class:on={view === 'rest'} aria-pressed={view === 'rest'} onclick={() => openVoorstel('rest')}>rest{voorstel ? ` (${voorstel.other.length})` : ''}</button>
  </div>

  {#if view === 'gecheckt'}
    {#each tiles as t (t.id)}
      {@const l = line(t)}
      <div class="tile">
        <div class="tw">
          <div class="l1"><b>{t.name}</b><span class={l.cls}>{l.text}</span></div>
          <small>{host(t.url)}{#if t.problem} · <span class="e">{t.problem}</span>{/if}{#if t.vanbuiten.why} · {t.vanbuiten.why}{:else if t.vanbuiten.note} · {t.vanbuiten.note}{/if}{#if t.vanbuiten.since && t.vanbuiten.status !== 'wacht'} · sinds {hhmm(t.vanbuiten.since)}{/if}</small>
        </div>
        <button class="mini x del" disabled={!!busy} aria-label="{t.name} niet meer van buitenaf checken"
                title="niet meer van buitenaf checken" onclick={() => removeTile(t)}>✕</button>
      </div>
    {:else}
      <p class="hint">Nog geen tegels: kies ze onder voorstel.</p>
    {/each}
  {:else if !voorstel}
    <p class="hint">laden…</p>
  {:else if view === 'voorstel'}
    {#each voorstel.suggest as s (s.id)}
      <label class="tile pick">
        <input type="checkbox" bind:checked={picked[s.id]} />
        <span class="tw">
          <span class="l1"><b>{s.name}</b></span>
          <small>{host(s.url)}{#if s.npm} · {s.npm === 'toegangslijst in NPM' ? 'toegangslijst in NPM: misschien alleen thuis' : s.npm}{/if}</small>
        </span>
      </label>
    {:else}
      <p class="hint">Geen tegels meer om toe te voegen.</p>
    {/each}
    {#if voorstel.suggest.length}
      <div class="btns"><button class="mini" disabled={!!busy || !checked} onclick={addTiles}>Toevoegen ({checked})</button></div>
    {/if}
  {:else}
    {#each voorstel.other as o (o.id)}
      <div class="tile"><div class="tw"><div class="l1"><b>{o.name}</b><span class="m">{o.why}</span></div>
        <small>{o.url || 'geen adres'}</small></div></div>
    {:else}
      <p class="hint">Niets: elke tegel met een adres kan van buitenaf gecheckt worden.</p>
    {/each}
  {/if}

  <p class="hint small">Gratis plan van Cloudflare: één verzoek per minuut (1.440 van de 100.000 per dag), hoogstens 45
    adressen per verzoek. Elke tegel om de 5 minuten, tot 225 tegels. Een tegel gaat down na 2 mislukte checks na
    elkaar; vallen er 3 of meer om dezelfde reden uit, dan krijg je één melding.</p>
{/if}

<style>
  .ways { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; align-items: start }
  @media (max-width: 600px) { .ways { grid-template-columns: 1fr } }
  .box { padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: var(--fill); min-width: 0 }
  .box > b, .head b { color: var(--text-h); font-weight: 500; font-size: 13px }
  .steps { padding-left: 18px; margin: 6px 0 0; font-size: 12.5px; line-height: 1.5 }
  .steps li { margin-bottom: 8px }
  .steps b { color: var(--text-h); font-weight: 500; overflow-wrap: anywhere }
  input, select { width: 100%; box-sizing: border-box }
  .btns { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 4px; align-items: center }
  details { margin-top: 4px }
  summary { color: var(--muted); font-size: 11.5px; cursor: pointer }
  .script { max-height: 240px; overflow: auto; max-width: 100%; font-size: 11px; margin-top: 4px }
  .head { display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline; margin-bottom: 6px }
  .head small { color: var(--dim); font-size: 11.5px }
  .banner { margin: 6px 0; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--line-2); font-size: 12.5px;
            display: flex; flex-direction: column; gap: 4px; align-items: flex-start }
  .banner.e { border-color: rgba(229, 139, 139, .5) }
  .banner.w { border-color: rgba(230, 181, 107, .5) }
  .banner small { color: var(--muted) }
  .seg { display: flex; flex-wrap: wrap; gap: 6px; margin: 14px 0 6px }
  .tile { display: flex; gap: 8px; align-items: center; padding: 6px 0; border-bottom: 1px solid rgba(255, 255, 255, .05);
          font-size: 12.5px }
  .tile.pick { cursor: pointer }
  .tile.pick input { width: auto; accent-color: #bbb; flex-shrink: 0 }
  .tw { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px }
  .l1 { display: flex; gap: 4px 10px; flex-wrap: wrap; align-items: baseline; min-width: 0 }
  .l1 b { color: var(--text-h); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100% }
  .tw small { color: var(--dim); font-size: 11.5px; overflow-wrap: anywhere }
  .del { width: 36px; height: 36px; padding: 0; flex-shrink: 0 }
  .small { font-size: 11.5px; margin-top: 10px }
  .g { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .m { color: var(--muted) }
</style>
