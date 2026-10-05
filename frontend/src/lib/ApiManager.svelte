<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import { SHOW } from './apicalls.js'
  import ApiCallEditor from './ApiCallEditor.svelte'

  // API-beheer: alle API's per categorie, met hun adres, aanmelding, sleutels en eigen calls, en welke tegels ze
  // gebruiken. Sjablonen voor bekende apps, en het in één keer instellen van veel tegels.
  let { onclose, onchanged } = $props()

  let data = $state.raw(null)
  let error = $state('')
  let q = $state('')
  let selId = $state(null)
  let view = $state('list') // list | api | call | new | suggest
  let callSel = $state(null) // bestaande call, of {} voor een nieuwe
  let form = $state(null)
  let busy = $state(false)
  let msg = $state('')
  let testResult = $state(null)
  let linking = $state(false)
  let linkQ = $state('')
  let linkSel = $state(new Set())
  let sug = $state(null)
  let closedCats = $state(new Set())

  async function load() {
    try { data = await api('/apis'); error = '' } catch (e) { error = e.message }
  }
  async function loadSuggest() {
    try { sug = await api('/apis/suggest') } catch (e) { error = e.message }
  }
  onMount(() => { load(); loadSuggest() })

  let sel = $derived(data?.apis.find((a) => a.id === selId) || null)
  let kinds = $derived(Object.fromEntries((data?.kinds || []).map((k) => [k.name, k])))
  let templates = $derived(Object.fromEntries((data?.templates || []).map((t) => [t.key, t])))
  let filtered = $derived.by(() => {
    const s = q.trim().toLowerCase()
    return (data?.apis || []).filter((a) => !s || `${a.name} ${a.url} ${a.kind_label} ${a.category} ${a.tiles.map((t) => t.name).join(' ')}`.toLowerCase().includes(s))
  })
  let byCat = $derived.by(() => {
    const m = new Map()
    for (const c of data?.categories || []) m.set(c, [])
    for (const a of filtered) { if (!m.has(a.category)) m.set(a.category, []); m.get(a.category).push(a) }
    return [...m].filter(([, list]) => list.length)
  })
  let sugCount = $derived((sug?.matches.length || 0) + (sug?.adopt.length || 0))
  let withApi = $derived((data?.tiles || []).filter((t) => t.api_id).length)

  // --- een API openen en bewerken ---------------------------------------------------
  const authOf = (a) => ({ type: 'none', name: '', prefix: '', ...(a?.config?.auth || {}) })
  function needed(kind, auth) {
    if (kind !== 'rest') return Object.keys(kinds[kind]?.secrets || {})
    return auth.type === 'none' ? [] : auth.type === 'basic' ? ['username', 'password'] : ['token']
  }
  function open(a) {
    selId = a.id
    view = 'api'
    msg = ''
    testResult = null
    linking = false
    const { auth, headers, insecure, ...rest } = a.config || {}
    form = {
      name: a.name, category: a.category, kind: a.kind, url: a.url, insecure: !!insecure, auth: authOf(a),
      headers: Object.entries(headers || {}).map(([k, v]) => ({ k, v })),
      extra: Object.keys(rest).length ? JSON.stringify(rest, null, 2) : '', secrets: {}, removed: [], newCat: '',
    }
  }
  function body(f) {
    let extra = {}
    if (f.extra.trim()) {
      try { extra = JSON.parse(f.extra) } catch { throw new Error('Extra instellingen zijn geen geldige JSON') }
    }
    const config = { ...extra }
    if (f.insecure) config.insecure = true
    if (f.kind === 'rest') {
      config.auth = { type: f.auth.type, ...(f.auth.name ? { name: f.auth.name } : {}), ...(f.auth.prefix ? { prefix: f.auth.prefix } : {}) }
      const h = Object.fromEntries(f.headers.filter((r) => r.k.trim()).map((r) => [r.k.trim(), r.v]))
      if (Object.keys(h).length) config.headers = h
    }
    const secrets = {}
    for (const k of f.removed) secrets[k] = null
    for (const [k, v] of Object.entries(f.secrets)) if (v) secrets[k] = v
    return { name: f.name.trim(), category: (f.newCat || f.category).trim() || 'Overig', kind: f.kind, url: f.url.trim(), config,
             secrets: Object.keys(secrets).length ? secrets : null }
  }
  async function saveApi() {
    busy = true
    error = ''
    try {
      const b = body(form)
      // Een ander adres of een andere aanmelding voor bewaarde sleutels vraagt een recente 2FA.
      await withReauth(() => api(`/apis/${sel.id}`, { method: 'PATCH', body: b }))
      await load()
      open(data.apis.find((a) => a.id === selId))
      msg = 'Bewaard.'
      onchanged?.()
    } catch (e) { error = e.message } finally { busy = false }
  }
  async function delApi() {
    const n = sel.tiles.length
    if (!confirm(`API '${sel.name}' verwijderen?${n ? ` ${n} tegel(s) worden weer gewone snelkoppelingen.` : ''}`)) return
    try {
      await api(`/apis/${sel.id}`, { method: 'DELETE' })
      selId = null
      view = 'list'
      await load()
      onchanged?.()
    } catch (e) { error = e.message }
  }
  async function test() {
    testResult = { busy: true }
    try {
      const r = await api(`/apis/${sel.id}/try`, { method: 'POST', body: { call: { name: 'test', path: '' } } })
      testResult = r.ok ? { ok: true, text: `bereikbaar in ${r.ms} ms` } : { ok: false, text: r.error }
    } catch (e) { testResult = { ok: false, text: e.message } }
  }
  async function moveCall(i, d) {
    const ids = sel.calls.map((c) => c.id)
    const [x] = ids.splice(i, 1)
    ids.splice(i + d, 0, x)
    await api(`/apis/${sel.id}/calls/order`, { method: 'POST', body: { ids } })
    await load()
  }

  // --- tegels koppelen ---------------------------------------------------------------
  let linkList = $derived.by(() => {
    const s = linkQ.trim().toLowerCase()
    return (data?.tiles || []).filter((t) => t.api_id !== selId && (!s || `${t.name} ${t.url || ''}`.toLowerCase().includes(s)))
  })
  function toggleLink(id) {
    const s = new Set(linkSel)
    s.has(id) ? s.delete(id) : s.add(id)
    linkSel = s
  }
  async function link(ids, attach = true) {
    try {
      await api(`/apis/${sel.id}/tiles`, { method: 'POST', body: { service_ids: [...ids], attach } })
      linkSel = new Set()
      linking = false
      await load()
      onchanged?.()
    } catch (e) { error = e.message }
  }

  // --- nieuwe API ------------------------------------------------------------------------
  let nw = $state(null)
  let tq = $state('')
  function startNew() {
    view = 'new'
    selId = null
    nw = null
    tq = ''
    error = ''
  }
  function pickTemplate(t) {
    nw = { template: t.key, name: t.key === 'rest' ? '' : t.label, url: t.url || '', category: t.category, secrets: {}, t,
           tile: '' }
  }
  let tplByCat = $derived.by(() => {
    const s = tq.trim().toLowerCase()
    const m = new Map()
    for (const t of data?.templates || []) {
      if (s && !`${t.label} ${t.key} ${t.category}`.toLowerCase().includes(s)) continue
      if (!m.has(t.category)) m.set(t.category, [])
      m.get(t.category).push(t)
    }
    return [...m]
  })
  async function create() {
    busy = true
    error = ''
    try {
      // Aanmelding, vaste headers en calls komen van het sjabloon op de server.
      const r = await api('/apis', { method: 'POST', body: {
        name: nw.name.trim() || nw.t.label, category: nw.category, kind: nw.t.kind, url: nw.url.trim(), template: nw.template,
        config: {}, secrets: Object.fromEntries(Object.entries(nw.secrets).filter(([, v]) => v)),
      } })
      if (nw.tile) await api(`/apis/${r.id}/tiles`, { method: 'POST', body: { service_ids: [Number(nw.tile)] } })
      await load()
      open(data.apis.find((a) => a.id === r.id))
      onchanged?.()
    } catch (e) { error = e.message } finally { busy = false }
  }

  // --- herkennen en in bulk -----------------------------------------------------------------
  let bulk = $state({}) // service_id → { on, secrets: {}, url }
  let adoptSel = $state(new Set())
  function openSuggest() {
    view = 'suggest'
    selId = null
    error = ''
    msg = ''
    bulk = Object.fromEntries((sug?.matches || []).map((m) => [m.service_id, { on: true, secrets: {}, url: m.url }]))
    adoptSel = new Set((sug?.adopt || []).map((a) => a.service_id))
  }
  let ready = $derived((sug?.matches || []).filter((m) => bulk[m.service_id]?.on))
  async function runBulk() {
    busy = true
    error = ''
    try {
      const items = ready.map((m) => ({ service_id: m.service_id, template: m.template, url: bulk[m.service_id].url || null,
                                         secrets: Object.fromEntries(Object.entries(bulk[m.service_id].secrets).filter(([, v]) => v)) }))
      const r = await api('/apis/bulk', { method: 'POST', body: { items } })
      msg = `${r.created} API's aangemaakt en gekoppeld.`
      await Promise.all([load(), loadSuggest()])
      bulk = Object.fromEntries((sug?.matches || []).map((m) => [m.service_id, { on: true, secrets: {}, url: m.url }]))
      onchanged?.()
    } catch (e) { error = e.message } finally { busy = false }
  }
  async function runAdopt() {
    busy = true
    error = ''
    try {
      const r = await api('/apis/adopt', { method: 'POST', body: { service_ids: [...adoptSel] } })
      msg = `${r.moved} tegels verhuisd naar ${r.apis} API('s).`
      await Promise.all([load(), loadSuggest()])
      adoptSel = new Set()
      onchanged?.()
    } catch (e) { error = e.message } finally { busy = false }
  }
  const tplSecrets = (key) => templates[key]?.secrets || []
  const host = (u) => { try { return new URL(u).host } catch { return u } }
</script>

<div class="ov">
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# api --beheer</span>
      <div class="right">
        <button class="mini x" onclick={onclose} aria-label="API-beheer sluiten">✕</button>
      </div>
    </div>

    <div class="cols">
      <aside class="side">
        <div class="sact">
          <button class="mini ok" onclick={startNew}>+ API</button>
          <button class="mini" class:hot={sugCount} onclick={openSuggest} title="Tegels herkennen en in één keer een API geven">⚡ tegels herkennen{#if sugCount}<b class="n">{sugCount}</b>{/if}</button>
        </div>
        <input class="srch" bind:value={q} placeholder="zoek API of tegel" aria-label="Zoek API" />
        {#if data}
          <p class="stat">{data.apis.length} API's · {withApi} van {data.tiles.length} tegels gekoppeld</p>
          {#each byCat as [cat, list] (cat)}
            <button class="cat" onclick={() => { const s = new Set(closedCats); s.has(cat) ? s.delete(cat) : s.add(cat); closedCats = s }}>
              {closedCats.has(cat) ? '▸' : '▾'} {cat} <small>{list.length}</small></button>
            {#if !closedCats.has(cat)}
              {#each list as a (a.id)}
                <button class="item" class:on={a.id === selId} onclick={() => open(a)}>
                  <span class="in">{a.name}</span>
                  <small>{a.kind_label} · {a.tiles.length} tegel{a.tiles.length === 1 ? '' : 's'}{a.calls.length ? ` · ${a.calls.length} calls` : ''}</small>
                </button>
              {/each}
            {/if}
          {:else}
            <p class="hint">{q ? 'Niets gevonden.' : 'Nog geen API\'s. Begin met ⚡ tegels herkennen of + API.'}</p>
          {/each}
        {/if}
      </aside>

      <section class="main">
        {#if error}<p class="e">{error}</p>{/if}

        {#if view === 'list' || !data}
          <div class="intro">
            <h3>API's beheren</h3>
            <p>Een API stel je hier één keer in: adres, aanmelding en sleutel (versleuteld bewaard). Daarna kies je bij een tegel
              welke API ze gebruikt (✎ bewerken → API), of koppel je hier veel tegels tegelijk.</p>
            <ul>
              <li><b>⚡ tegels herkennen</b>: tegels zoals Radarr, Jellyfin of Immich krijgen in één keer een API uit een sjabloon; je vult alleen de sleutel in.
                Tegels die hun sleutels nog zelf hebben (Proxmox, AdGuard, ...) verhuis je hier in één klik.</li>
              <li><b>+ API</b>: kies een sjabloon of begin leeg met een eigen API.</li>
              <li><b>calls</b>: per API eigen endpoints toevoegen. Druk op ▶ probeer en klik in het antwoord op wat je op de tegel wil zien.</li>
            </ul>
          </div>

        {:else if view === 'new'}
          <h3>Nieuwe API</h3>
          {#if !nw}
            <input class="srch" bind:value={tq} placeholder="zoek een app, bv. sonarr" aria-label="Zoek sjabloon" />
            {#each tplByCat as [cat, list] (cat)}
              <p class="lbl">{cat}</p>
              <div class="tpls">
                {#each list as t (t.key)}
                  <button class="tpl" onclick={() => pickTemplate(t)}><b>{t.label}</b>
                    <small>{t.kind !== 'rest' ? 'ingebouwd' : t.calls ? `${t.calls} calls klaar` : 'zelf calls toevoegen'}</small></button>
                {/each}
              </div>
            {/each}
          {:else}
            <div class="frm">
              <p class="hint"><b>{nw.t.label}</b>{nw.t.hint ? ` · ${nw.t.hint}` : ''} <button class="mini" onclick={() => (nw = null)}>ander sjabloon</button></p>
              <label class="lbl" for="an-name">Naam</label>
              <input id="an-name" bind:value={nw.name} placeholder="bv. Radarr" maxlength="80" />
              <label class="lbl" for="an-url">Adres van de API</label>
              <input id="an-url" bind:value={nw.url} placeholder="https://radarr.jbogaert.be" />
              <label class="lbl" for="an-cat">Categorie</label>
              <input id="an-cat" bind:value={nw.category} list="api-cats" maxlength="40" />
              {#each nw.t.secrets as k}
                <label class="lbl" for="an-s-{k}">{k}{nw.t.secret && nw.t.secrets.length === 1 ? ` · ${nw.t.secret}` : nw.t.secret_help[k] ? ` · ${nw.t.secret_help[k]}` : ''}</label>
                <input id="an-s-{k}" type={k.endsWith('username') ? 'text' : 'password'} bind:value={nw.secrets[k]} autocomplete="new-password" />
              {/each}
              <label class="lbl" for="an-tile">Meteen koppelen aan tegel (optioneel)</label>
              <select id="an-tile" bind:value={nw.tile}>
                <option value="">geen</option>
                {#each data.tiles.filter((t) => !t.api_id) as t (t.id)}<option value={String(t.id)}>{t.name}</option>{/each}
              </select>
              <div class="row act">
                <button class="btn" onclick={create} disabled={busy || !nw.url.trim()}>Aanmaken</button>
                <button class="btn alt" onclick={() => (view = 'list')}>Annuleren</button>
              </div>
            </div>
          {/if}

        {:else if view === 'suggest'}
          <h3>Tegels herkennen</h3>
          {#if msg}<p class="okm">{msg}</p>{/if}
          {#if !sug?.matches.length && !sug?.adopt.length}
            <p class="hint">Geen tegels meer om te herkennen: alles met een bekende app heeft een API, of je stelt de rest zelf in met + API.</p>
          {/if}
          {#if sug?.matches.length}
            <p class="hint">Deze tegels lijken op een bekende app. Vul de sleutel in en ze krijgen elk hun eigen API, met calls die meteen werken.
              Zonder sleutel wordt de API toch aangemaakt; die vul je later in.</p>
            <div class="tw">
              <table class="bulk">
                <thead><tr><th></th><th>tegel</th><th>app</th><th>adres van de API</th><th>sleutel</th></tr></thead>
                <tbody>
                  {#each sug.matches as m (m.service_id)}
                    {@const b = bulk[m.service_id]}
                    {#if b}
                      <tr class:off={!b.on}>
                        <td><input type="checkbox" bind:checked={b.on} aria-label="{m.name} meenemen" /></td>
                        <td>{m.name}</td>
                        <td><small>{m.label}</small></td>
                        <td><input class="u" bind:value={b.url} aria-label="Adres voor {m.name}" /></td>
                        <td class="sec">
                          {#each tplSecrets(m.template) as k}
                            <input type={k.endsWith('username') ? 'text' : 'password'} bind:value={b.secrets[k]} placeholder={k === 'token' ? (templates[m.template]?.secret || 'sleutel') : k}
                                   autocomplete="new-password" aria-label="{k} voor {m.name}" />
                          {:else}<small>geen nodig</small>{/each}
                        </td>
                      </tr>
                    {/if}
                  {/each}
                </tbody>
              </table>
            </div>
            <div class="row act"><button class="btn" onclick={runBulk} disabled={busy || !ready.length}>Maak {ready.length} API's</button></div>
          {/if}
          {#if sug?.adopt.length}
            <h4>Tegels met eigen sleutels</h4>
            <p class="hint">Deze tegels hebben hun adres en sleutels nog zelf. Verhuis ze naar API-beheer: tegels met hetzelfde adres en dezelfde
              sleutels (bv. de nodes van één Proxmox-cluster) delen daarna één API. Er verandert niets aan wat ze tonen.</p>
            {#each sug.adopt as a (a.service_id)}
              <label class="chk ad"><input type="checkbox" checked={adoptSel.has(a.service_id)}
                onchange={() => { const s = new Set(adoptSel); s.has(a.service_id) ? s.delete(a.service_id) : s.add(a.service_id); adoptSel = s }} />
                {a.name} <small>{kinds[a.type]?.label || a.type} · {host(a.url)}</small></label>
            {/each}
            <div class="row act"><button class="btn" onclick={runAdopt} disabled={busy || !adoptSel.size}>Verhuis {adoptSel.size} tegels</button></div>
          {/if}

        {:else if view === 'call' && sel}
          <ApiCallEditor conn={sel} call={callSel?.id ? callSel : null} prefix={kinds[sel.kind]?.prefix || ''}
                         onsaved={load} onclose={() => { view = 'api'; callSel = null }} />

        {:else if view === 'api' && sel && form}
          <div class="head">
            <h3>{sel.name}</h3><small>{sel.kind_label}{sel.template ? ` · sjabloon ${templates[sel.template]?.label || sel.template}` : ''}</small>
            <button class="mini" onclick={test} disabled={testResult?.busy}>▶ test verbinding</button>
            {#if testResult && !testResult.busy}<span class="tr" class:bad={!testResult.ok}>{testResult.text}</span>{/if}
          </div>

          <div class="grid">
            <div><label class="lbl" for="ap-name">Naam</label><input id="ap-name" bind:value={form.name} maxlength="80" /></div>
            <div><label class="lbl" for="ap-cat">Categorie</label>
              <input id="ap-cat" bind:value={form.category} list="api-cats" maxlength="40" /></div>
            <div class="full"><label class="lbl" for="ap-url">Adres van de API</label><input id="ap-url" bind:value={form.url} /></div>
            <div><label class="lbl" for="ap-kind">Soort</label>
              <select id="ap-kind" bind:value={form.kind}>
                {#each data.kinds as k}<option value={k.name}>{k.label}</option>{/each}
              </select></div>
            <div class="cb"><label class="chk"><input type="checkbox" bind:checked={form.insecure} /> zelfondertekend certificaat toestaan</label></div>
            {#if form.kind === 'rest'}
              <div><label class="lbl" for="ap-auth">Aanmelding</label>
                <select id="ap-auth" bind:value={form.auth.type}>
                  <option value="none">geen</option><option value="header">sleutel in een header</option>
                  <option value="bearer">Bearer-token</option><option value="query">sleutel in de url (?apikey=)</option>
                  <option value="basic">gebruikersnaam en wachtwoord</option>
                </select></div>
              {#if form.auth.type === 'header' || form.auth.type === 'query'}
                <div><label class="lbl" for="ap-an">{form.auth.type === 'header' ? 'Naam van de header' : 'Naam van de parameter'}</label>
                  <input id="ap-an" bind:value={form.auth.name} placeholder={form.auth.type === 'header' ? 'X-Api-Key' : 'apikey'} /></div>
              {/if}
              {#if form.auth.type === 'header'}
                <div><label class="lbl" for="ap-ap">Voor de sleutel (optioneel)</label><input id="ap-ap" bind:value={form.auth.prefix} placeholder="bv. Token " /></div>
              {/if}
            {/if}
          </div>

          <span class="lbl">Sleutels (versleuteld bewaard, nooit zichtbaar in de browser)</span>
          {#each [...new Set([...needed(form.kind, form.auth), ...sel.secret_keys])] as k (k)}
            <div class="sk">
              <code>{k}</code>
              {#if sel.secret_keys.includes(k) && !form.removed.includes(k) && form.secrets[k] === undefined}
                <span class="set">•••••• ingesteld</span>
                <button class="mini" onclick={() => (form.secrets[k] = '')}>wijzig</button>
                <button class="mini x" onclick={() => form.removed.push(k)}>wis</button>
              {:else if form.removed.includes(k)}
                <span class="gone">wordt gewist</span><button class="mini" onclick={() => (form.removed = form.removed.filter((x) => x !== k))}>herstel</button>
              {:else}
                <input type={k.endsWith('username') ? 'text' : 'password'} bind:value={form.secrets[k]} autocomplete="new-password"
                       placeholder={kinds[form.kind]?.secrets?.[k] || (k === 'token' ? 'API-sleutel' : k)} aria-label="Sleutel {k}" />
              {/if}
            </div>
          {/each}
          {#if !needed(form.kind, form.auth).length && !sel.secret_keys.length}<p class="hint">Geen sleutel nodig.</p>{/if}

          <details class="more" open={form.headers.length > 0 || !!form.extra}>
            <summary>{form.kind === 'rest' ? 'vaste headers en extra instellingen' : 'extra instellingen'}</summary>
            {#if form.kind === 'rest'}
              {#each form.headers as r, i}
                <div class="kv"><input bind:value={r.k} placeholder="Accept" /><input bind:value={r.v} placeholder="application/json" />
                  <button class="mini x" onclick={() => form.headers.splice(i, 1)}>✕</button></div>
              {/each}
              <button class="mini" onclick={() => form.headers.push({ k: '', v: '' })}>+ header</button>
            {/if}
            <label class="lbl" for="ap-extra">Instellingen (JSON) voor alle tegels met deze API{form.kind !== 'rest' ? '; per tegel (bv. node) zet je in de tegel zelf' : ''}</label>
            <textarea id="ap-extra" bind:value={form.extra} placeholder={'{ }'}></textarea>
            {#if kinds[form.kind]?.config}
              <div class="hint">{#each Object.entries(kinds[form.kind].config).filter(([k]) => k !== 'url') as [k, v]}<div><code>{k}</code> {v}</div>{/each}</div>
            {/if}
          </details>

          {#if msg}<p class="okm">{msg}</p>{/if}
          <div class="row act">
            <button class="btn" onclick={saveApi} disabled={busy}>Bewaren</button>
            <button class="btn alt danger right" onclick={delApi}>Verwijderen</button>
          </div>

          <div class="sect">
            <h4>Calls <small>{sel.kind === 'rest' ? 'wat de tegels van deze API tonen' : `extra endpoints naast wat ${sel.kind_label} al toont`}</small></h4>
            {#each sel.calls as c, i (c.id)}
              <div class="call">
                <button class="cl" onclick={() => { callSel = c; view = 'call' }}>
                  <span class="m m-{c.method}">{c.method}</span><span class="cn">{c.name}</span><code>{c.path || '/'}</code>
                  <small>{SHOW[c.show]}{c.fields.length ? ` · ${c.fields.length} velden` : ''}{c.table?.columns?.length ? ' · tabel' : ''}</small>
                </button>
                <button class="mini" onclick={() => moveCall(i, -1)} disabled={!i} aria-label="Hoger">↑</button>
                <button class="mini" onclick={() => moveCall(i, 1)} disabled={i === sel.calls.length - 1} aria-label="Lager">↓</button>
              </div>
            {:else}
              <p class="hint">Nog geen calls.{sel.kind === 'rest' ? ' Voeg er een toe: daarmee bepaal je wat de tegel toont.' : ''}</p>
            {/each}
            <button class="mini ok" onclick={() => { callSel = {}; view = 'call' }}>+ call</button>
          </div>

          <div class="sect">
            <h4>Tegels <small>{sel.tiles.length} gebruiken deze API</small></h4>
            <div class="chips">
              {#each sel.tiles as t (t.id)}
                <span class="chip">{t.name}<button class="mini x" onclick={() => link([t.id], false)} aria-label="{t.name} loskoppelen">✕</button></span>
              {/each}
            </div>
            {#if !linking}
              <button class="mini" onclick={() => { linking = true; linkSel = new Set(); linkQ = '' }}>+ tegels koppelen</button>
            {:else}
              <div class="pick">
                <div class="row"><input bind:value={linkQ} placeholder="zoek tegel" aria-label="Zoek tegel" />
                  <button class="mini" onclick={() => (linkSel = new Set(linkList.map((t) => t.id)))}>alles zichtbaar</button>
                  <button class="mini" onclick={() => (linkSel = new Set())}>niets</button></div>
                <div class="plist">
                  {#each linkList as t (t.id)}
                    <label class="chk"><input type="checkbox" checked={linkSel.has(t.id)} onchange={() => toggleLink(t.id)} />
                      {t.name} <small>{t.url ? host(t.url) : ''}{t.api_id ? ' · heeft al een API' : t.own_keys ? ' · eigen sleutels' : ''}</small></label>
                  {/each}
                </div>
                <div class="row">
                  <button class="btn" onclick={() => link(linkSel)} disabled={!linkSel.size}>Koppel {linkSel.size} tegels</button>
                  <button class="btn alt" onclick={() => (linking = false)}>Annuleren</button>
                </div>
              </div>
            {/if}
          </div>
        {/if}
      </section>
    </div>
  </div>
</div>

<datalist id="api-cats">{#each data?.categories || [] as c}<option value={c}></option>{/each}</datalist>

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .cols { flex: 1; display: grid; grid-template-columns: 290px minmax(0, 1fr); min-height: 0; border-top: 1px solid var(--line) }
  .side { border-right: 1px solid var(--line); overflow: auto; padding: 10px; display: flex; flex-direction: column; gap: 4px }
  .sact { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 4px }
  .hot { border-color: var(--accent, #7aa2ff) }
  .n { margin-left: 5px; font-weight: 500 }
  .srch { width: 100%; margin-bottom: 4px }
  .stat { color: var(--dim); font-size: 11.5px; margin: 0 0 6px }
  .cat { all: unset; cursor: pointer; font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; padding: 8px 2px 2px }
  .cat small { color: var(--dim) }
  .item { all: unset; cursor: pointer; display: flex; flex-direction: column; padding: 5px 8px; border-radius: 8px; border: 1px solid transparent }
  .item:hover { background: var(--fill-h) }
  .item.on { border-color: var(--line-2); background: var(--fill) }
  .in { color: var(--text-h); font-size: 13.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .item small { color: var(--dim); font-size: 11px }
  .main { overflow: auto; padding: 12px 16px 28px; min-width: 0 }
  h3 { margin: 0 0 8px; font-weight: 500; color: var(--text-h) }
  h4 { margin: 18px 0 6px; font-weight: 500; color: var(--text-h) }
  h4 small, .head small { color: var(--dim); font-weight: 400; font-size: 12px }
  .head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; margin-bottom: 6px }
  .head h3 { margin: 0 }
  .tr { font-size: 12px; color: var(--ok) }
  .tr.bad { color: var(--err) }
  .intro { max-width: 720px; color: var(--text); font-size: 13.5px; line-height: 1.6 }
  .intro li { margin-bottom: 6px }
  .hint { color: var(--muted); font-size: 12px; margin: 4px 0 }
  .e { color: var(--err); font-size: 13px }
  .okm { color: var(--ok); font-size: 12.5px }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px; max-width: 760px }
  .full { grid-column: 1 / -1 }
  .cb { display: flex; align-items: flex-end; padding-bottom: 8px }
  .sk { display: flex; gap: 8px; align-items: center; margin: 4px 0; max-width: 760px }
  .sk code { min-width: 80px; font-size: 12.5px; color: #d6e6ff }
  .sk input { flex: 1 }
  .set { color: var(--muted); font-size: 12.5px }
  .gone { color: var(--dim); text-decoration: line-through; font-size: 12.5px }
  .more { margin-top: 10px; max-width: 760px }
  .more summary { cursor: pointer; color: var(--muted); font-size: 12.5px }
  .kv { display: flex; gap: 6px; margin: 4px 0 }
  .kv input { flex: 1; min-width: 0 }
  textarea { min-height: 60px }
  .act { margin-top: 10px; max-width: 1080px }
  .right { margin-left: auto }
  .sect { border-top: 1px solid var(--line); margin-top: 18px; max-width: 900px }
  .call { display: flex; gap: 4px; align-items: center; margin: 3px 0 }
  .cl { all: unset; cursor: pointer; flex: 1; display: flex; gap: 8px; align-items: baseline; padding: 5px 8px; border-radius: 8px; border: 1px solid var(--line); min-width: 0 }
  .cl:hover { background: var(--fill-h) }
  .cl code { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .cl small { margin-left: auto; color: var(--dim); font-size: 11px; white-space: nowrap }
  .cn { color: var(--text-h); white-space: nowrap }
  .m { font-size: 10.5px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: var(--ok) }
  .m-POST, .m-PUT, .m-PATCH { color: var(--warn, #ffcf6e) }
  .m-DELETE { color: var(--err) }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 6px }
  .chip { display: inline-flex; gap: 4px; align-items: center; font-size: 12.5px; padding: 1px 4px 1px 9px; border: 1px solid var(--line-2); border-radius: 8px }
  .pick { border: 1px solid var(--line); border-radius: 10px; padding: 8px; display: flex; flex-direction: column; gap: 6px }
  .plist { max-height: 300px; overflow: auto; display: flex; flex-direction: column; gap: 2px }
  .plist small, .ad small { color: var(--dim) }
  .tpls { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px }
  .tpl { all: unset; cursor: pointer; display: flex; flex-direction: column; padding: 8px 10px; border: 1px solid var(--line); border-radius: 10px; background: var(--fill) }
  .tpl:hover { border-color: var(--line-2); background: var(--fill-h) }
  .tpl b { font-weight: 500; color: var(--text-h) }
  .tpl small { color: var(--dim); font-size: 11px }
  .frm { max-width: 520px; display: flex; flex-direction: column }
  .tw { overflow: auto }
  .bulk { width: 100%; border-collapse: collapse; font-size: 13px }
  .bulk th { text-align: left; font-weight: 400; color: var(--muted); font-size: 12px; padding: 4px 6px }
  .bulk td { padding: 3px 6px; border-top: 1px solid var(--line) }
  .bulk tr.off td { opacity: .45 }
  .bulk .u { min-width: 220px }
  .bulk .sec { display: flex; gap: 4px }
  .bulk .sec input { min-width: 160px }
  .ad { display: flex; gap: 6px; margin: 2px 0 }
  @media (max-width: 760px) {
    .cols { grid-template-columns: 1fr; grid-template-rows: auto 1fr }
    .side { max-height: 34vh; border-right: 0; border-bottom: 1px solid var(--line) }
    .grid { grid-template-columns: 1fr }
  }
</style>
