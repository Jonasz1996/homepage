<script>
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import { FORMATS, SHOW, fieldValue, guess, lastKey, level, pick, starred } from './apicalls.js'
  import { value } from './format.js'
  import JsonTree from './JsonTree.svelte'

  // Eén call van een API: pad en methode, uitproberen, en met een klik op het antwoord de velden voor de tegel
  // of een tabel voor het mini dashboard kiezen.
  let { conn, call = null, prefix = '', onsaved, onclose } = $props()

  const c = untrack(() => call) || {}
  const rows = (o) => Object.entries(o || {}).map(([k, v]) => ({ k, v }))
  let name = $state(c.name || '')
  let method = $state(c.method || 'GET')
  let path = $state(c.path || '')
  let query = $state(rows(c.query))
  let headers = $state(rows(c.headers))
  let body = $state(c.body || '')
  let show = $state(c.show || 'tile')
  let confirm = $state(c.confirm ?? true)
  let fields = $state((c.fields || []).map((f) => ({ suffix: '', warn: null, err: null, equals: '', ...f })))
  let table = $state(c.table?.path != null && c.table?.columns?.length ? { path: c.table.path, columns: c.table.columns.map((x) => ({ format: 'auto', ...x })) } : null)
  let result = $state.raw(null)
  let error = $state('')
  let busy = $state(false)
  let msg = $state('')

  $effect(() => { if (method !== 'GET') show = 'action' })

  const dict = (rs) => Object.fromEntries(rs.filter((r) => r.k.trim()).map((r) => [r.k.trim(), r.v]))
  function draft() {
    return {
      name: name.trim() || lastKey(path) || 'call', method, path: path.trim(), query: dict(query), headers: dict(headers),
      body: method !== 'GET' && body.trim() ? body : null, show, confirm,
      fields: fields.map((f) => ({ ...f, warn: f.warn === '' ? null : f.warn, err: f.err === '' ? null : f.err, equals: f.equals || null })),
      table: table && table.columns.length ? table : null,
    }
  }

  async function tryIt() {
    if (method !== 'GET' && !window.confirm(`Dit voert de ${method}-call echt uit op ${conn.name}. Doorgaan?`)) return
    busy = true
    error = ''
    try {
      const r = await withReauth(() => api(`/apis/${conn.id}/try`, { method: 'POST', body: { call: draft() } }))
      if (r.ok) result = { data: r.data, ms: r.ms }
      else { result = null; error = r.error }
    } catch (e) { error = e.message } finally { busy = false }
  }

  async function save() {
    busy = true
    error = ''
    try {
      if (call) await api(`/apis/calls/${call.id}`, { method: 'PATCH', body: draft() })
      else await api(`/apis/${conn.id}/calls`, { method: 'POST', body: draft() })
      msg = 'Bewaard. De tegels tonen het bij hun volgende verversing.'
      onsaved?.()
      if (!call) onclose()
    } catch (e) { error = e.message } finally { busy = false }
  }

  async function del() {
    if (!window.confirm(`Call '${call.name}' verwijderen?`)) return
    try {
      await api(`/apis/calls/${call.id}`, { method: 'DELETE' })
      onsaved?.()
      onclose()
    } catch (e) { error = e.message }
  }

  // Klik in het antwoord.
  function inside(tp, p) {
    const pre = tp === '' ? '' : tp + '.'
    if (!p.startsWith(pre)) return null
    const rest = p.slice(pre.length)
    const m = rest.match(/^\d+\.(.+)$/)
    return m ? m[1] : null
  }
  function onpick(p, v, kind) {
    if (kind === 'table') {
      table = table?.path === p ? null : { path: p, columns: [] }
      if (table && show === 'tile' && !fields.length) show = 'detail'
      return
    }
    if (kind === 'count') {
      fields.push({ label: lastKey(p), path: p, format: 'count', suffix: '', warn: null, err: null, equals: '' })
      return
    }
    const rel = table ? inside(table.path, p) : null
    if (rel != null) {
      if (!table.columns.some((x) => x.path === rel)) table.columns.push({ label: lastKey(rel), path: rel, format: guess(rel, v) })
      return
    }
    fields.push({ label: lastKey(p), path: p, format: guess(p, v), suffix: '', warn: null, err: null, equals: '' })
  }
  let used = $derived(new Set([...fields.map((f) => (f.format === 'count' ? '#' : '') + f.path),
                               ...(table ? ['▦' + table.path, ...table.columns.map((x) => (table.path ? table.path + '.0.' : '0.') + x.path)] : [])]))
  const preview = (f) => {
    if (!result) return null
    const [v, n] = fieldValue(result.data, f)
    return { v, level: level(n, f) }
  }
  let tableRows = $derived.by(() => {
    if (!result || !table) return []
    let rs = pick(result.data, table.path)
    if (rs && !Array.isArray(rs) && typeof rs === 'object') rs = Object.values(rs)
    return Array.isArray(rs) ? rs.slice(0, 5) : []
  })
  const move = (arr, i, d) => { const [x] = arr.splice(i, 1); arr.splice(i + d, 0, x) }
</script>

<div class="ed">
  <div class="top">
    <input class="nm" bind:value={name} placeholder="naam van de call, bv. wachtrij" maxlength="80" aria-label="Naam van de call" />
    <button class="mini" onclick={onclose}>← terug</button>
  </div>

  <div class="req">
    <select bind:value={method} aria-label="Methode">
      {#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as m}<option>{m}</option>{/each}
    </select>
    <span class="base" title={conn.url + prefix}>{conn.url.replace(/^https?:\/\//, '')}{prefix}</span>
    <input class="path" bind:value={path} placeholder="/api/v3/queue" aria-label="Pad" onkeydown={(e) => e.key === 'Enter' && tryIt()} />
    <button class="btn" onclick={tryIt} disabled={busy}>▶ probeer</button>
  </div>
  <p class="hint">Pad achter het adres van de API. <code>{'{node}'}</code> en andere <code>{'{namen}'}</code> komen uit de instellingen van de tegel.
    {#if method !== 'GET'}Iets anders dan GET is altijd een knop in het mini dashboard, en vraagt een recente 2FA.{/if}</p>

  <details class="more" open={query.length + headers.length > 0 || (method !== 'GET' && !!body)}>
    <summary>parameters, headers{method !== 'GET' ? ' en body' : ''}</summary>
    <div class="kvs">
      <span class="lbl">query (?naam=waarde)</span>
      {#each query as r, i}
        <div class="kv"><input bind:value={r.k} placeholder="pageSize" /><input bind:value={r.v} placeholder="50" /><button class="mini x" onclick={() => query.splice(i, 1)}>✕</button></div>
      {/each}
      <button class="mini" onclick={() => query.push({ k: '', v: '' })}>+ parameter</button>
      <span class="lbl">headers (niet geheim; de sleutel staat bij de API)</span>
      {#each headers as r, i}
        <div class="kv"><input bind:value={r.k} placeholder="Accept" /><input bind:value={r.v} placeholder="application/json" /><button class="mini x" onclick={() => headers.splice(i, 1)}>✕</button></div>
      {/each}
      <button class="mini" onclick={() => headers.push({ k: '', v: '' })}>+ header</button>
      {#if method !== 'GET'}
        <span class="lbl">body (JSON)</span>
        <textarea bind:value={body} placeholder={'{"name": "RefreshMonitoredDownloads"}'}></textarea>
      {/if}
    </div>
  </details>

  <div class="showrow">
    <span class="lbl">waar</span>
    {#each Object.entries(SHOW) as [k, label]}
      <label class="chk"><input type="radio" bind:group={show} value={k} disabled={method !== 'GET' && k !== 'action'} /> {label}</label>
    {/each}
    {#if show === 'action'}<label class="chk"><input type="checkbox" bind:checked={confirm} /> eerst bevestigen</label>{/if}
  </div>

  {#if error}<p class="e">{error}</p>{/if}

  <div class="split">
    <div class="resp">
      <div class="rh"><b>antwoord</b>{#if result}<small>{result.ms} ms · klik op een waarde om ze te tonen</small>{/if}</div>
      {#if result}
        <JsonTree data={result.data} {onpick} {used} />
      {:else}
        <p class="hint">Druk op ▶ probeer: je ziet hier het antwoord van de API. Klik dan op een waarde om er een veld voor de tegel van te maken, of op "▦ tabel" bij een lijst.</p>
      {/if}
    </div>

    <div class="cfg">
      {#if show !== 'action'}
        <div class="rh"><b>velden</b><small>{show === 'tile' ? 'op de tegel en in het mini dashboard' : 'in het mini dashboard'}</small></div>
        {#each fields as f, i (i)}
          {@const pv = preview(f)}
          <div class="fld">
            <div class="fr">
              <input class="fl" bind:value={f.label} placeholder="label" maxlength="30" aria-label="Label" />
              <input class="fp" bind:value={f.path} placeholder="pad, bv. queue.speed" aria-label="Pad in het antwoord" />
              {#if /(^|\.)\d+(\.|$)/.test(f.path)}<button class="mini" title="Over alle items in de lijst (met som, aantal, ...)" onclick={() => { f.path = starred(f.path); if (!['count', 'sum', 'avg', 'min', 'max'].includes(f.format)) f.format = typeof pv?.v === 'number' ? 'sum' : 'count' }}>* alle</button>{/if}
              <button class="mini" onclick={() => i && move(fields, i, -1)} disabled={!i} aria-label="Hoger">↑</button>
              <button class="mini x" onclick={() => fields.splice(i, 1)} aria-label="Veld verwijderen">✕</button>
            </div>
            <div class="fr small">
              <select bind:value={f.format} aria-label="Formaat">{#each Object.entries(FORMATS) as [k, l]}<option value={k}>{l}</option>{/each}</select>
              {#if f.format === 'count'}<input class="sm" bind:value={f.equals} placeholder="gelijk aan" title="Alleen tellen wat gelijk is aan (bv. down)" />{/if}
              <input class="xs" bind:value={f.suffix} placeholder="eenheid" title="Achter de waarde, bv. °C" maxlength="12" />
              <input class="xs" bind:value={f.warn} placeholder="geel ≥" title="Geel vanaf (is geel groter dan rood, dan is lager slechter)" inputmode="decimal" />
              <input class="xs" bind:value={f.err} placeholder="rood ≥" title="Rood vanaf" inputmode="decimal" />
              {#if pv}<span class="pv lv-{pv.level || 'none'}">= {value(pv.v)}</span>{/if}
            </div>
          </div>
        {:else}
          <p class="hint">Nog geen velden.{show === 'tile' ? ' Zonder velden toont de tegel niets van deze call.' : ''}</p>
        {/each}
        <button class="mini" onclick={() => fields.push({ label: '', path: '', format: 'auto', suffix: '', warn: null, err: null, equals: '' })}>+ veld</button>

        <div class="rh tbl"><b>tabel</b><small>in het mini dashboard</small></div>
        {#if table}
          <div class="fr"><span class="small">lijst</span><input class="fp" bind:value={table.path} placeholder="records (leeg = het antwoord zelf)" aria-label="Pad van de lijst" />
            <button class="mini x" onclick={() => (table = null)}>geen tabel</button></div>
          {#each table.columns as col, i (i)}
            <div class="fr small">
              <input class="fl" bind:value={col.label} placeholder="kolom" />
              <input class="fp" bind:value={col.path} placeholder="title" />
              <select bind:value={col.format}>{#each Object.entries(FORMATS) as [k, l]}<option value={k}>{l}</option>{/each}</select>
              <button class="mini x" onclick={() => table.columns.splice(i, 1)} aria-label="Kolom verwijderen">✕</button>
            </div>
          {/each}
          {#if !table.columns.length}<p class="hint">Klik in het antwoord op een waarde binnen de lijst om ze als kolom toe te voegen.</p>{/if}
          <button class="mini" onclick={() => table.columns.push({ label: '', path: '', format: 'auto' })}>+ kolom</button>
          {#if tableRows.length && table.columns.length}
            <table class="tp">
              <thead><tr>{#each table.columns as col}<th>{col.label || col.path}</th>{/each}</tr></thead>
              <tbody>{#each tableRows as r}<tr>{#each table.columns as col}{@const v = fieldValue(r, col)}<td>{value(v[0])}</td>{/each}</tr>{/each}</tbody>
            </table>
          {/if}
        {:else}
          <p class="hint">Klik bij een lijst in het antwoord op "▦ tabel".</p>
        {/if}
      {:else}
        <p class="hint">Een knop "{name || 'actie'}" in het mini dashboard van elke tegel met deze API, en in de zoekbalk (Ctrl+K). Uitvoeren vraagt een recente 2FA.</p>
      {/if}
    </div>
  </div>

  {#if msg}<p class="okm">{msg}</p>{/if}
  <div class="row act">
    <button class="btn" onclick={save} disabled={busy}>Bewaren</button>
    <button class="btn alt" onclick={onclose}>Annuleren</button>
    {#if call}<button class="btn alt danger right" onclick={del}>Verwijderen</button>{/if}
  </div>
</div>

<style>
  .ed { display: flex; flex-direction: column; gap: 8px }
  .top { display: flex; gap: 8px; align-items: center }
  .nm { flex: 1; font-size: 15px }
  .req { display: flex; gap: 6px; align-items: center; flex-wrap: wrap }
  .req select { width: auto }
  .base { color: var(--dim); font-size: 12px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .path { flex: 1; min-width: 200px }
  .hint { color: var(--muted); font-size: 12px; margin: 0 }
  .more summary { cursor: pointer; color: var(--muted); font-size: 12.5px }
  .kvs { display: flex; flex-direction: column; gap: 4px; padding: 6px 0 0 }
  .kv, .fr { display: flex; gap: 6px; align-items: center }
  .kv input { flex: 1; min-width: 0 }
  .showrow { display: flex; gap: 12px; align-items: center; flex-wrap: wrap }
  .showrow .lbl { margin: 0 }
  .split { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; min-height: 260px }
  .resp, .cfg { border: 1px solid var(--line); border-radius: 10px; padding: 8px 10px; background: var(--fill); min-width: 0 }
  .resp { max-height: 60vh; overflow: auto }
  .rh { display: flex; gap: 8px; align-items: baseline; margin-bottom: 6px }
  .rh b { color: var(--text-h); font-weight: 500 }
  .rh small { color: var(--dim); font-size: 11px }
  .rh.tbl { margin-top: 14px }
  .fld { padding: 6px 0; border-bottom: 1px solid var(--line) }
  .fr.small { margin-top: 4px; flex-wrap: wrap }
  .fl { width: 110px; flex: none }
  .fp { flex: 1; min-width: 80px }
  .xs { width: 84px; flex: none }
  .sm { width: 100px; flex: none }
  .fr select { width: auto; flex: none }
  .small { font-size: 12px; color: var(--muted) }
  .pv { font-size: 12px; color: var(--text-h); margin-left: auto }
  .pv.lv-warn { color: var(--warn, #ffcf6e) }
  .pv.lv-err { color: var(--err) }
  .pv.lv-ok { color: var(--ok) }
  .tp { width: 100%; margin-top: 8px; font-size: 12px; border-collapse: collapse }
  .tp th, .tp td { text-align: left; padding: 2px 6px; border-bottom: 1px solid var(--line); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px }
  .tp th { color: var(--muted); font-weight: 400 }
  .e { color: var(--err); font-size: 13px; margin: 0 }
  .okm { color: var(--ok); font-size: 12.5px; margin: 0 }
  .act { margin-top: 4px }
  .right { margin-left: auto }
  textarea { min-height: 70px }
  @media (max-width: 900px) { .split { grid-template-columns: 1fr } }
</style>
