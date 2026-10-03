<script>
  import { storm } from './fx.js'
  import { onMount } from 'svelte'
  import { ApiError, api, poll } from './api.js'
  import { bytes, value } from './format.js'
  import NpmImport from './NpmImport.svelte'

  // Gegevens en acties van de integratie in het mini dashboard.
  let { service, groups = [], onchanged } = $props()

  let data = $state(null)
  let error = $state('')
  let missing = $state(false)
  let filters = $state({})
  let msg = $state('')
  let pending = $state(null) // actie die op 2FA-bevestiging wacht
  let code = $state('')
  let busy = $state(false)

  async function load() {
    try {
      data = await api(`/services/${service.id}/integration`)
      error = data.error || ''
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) missing = true
      else error = e.message
    }
  }

  onMount(() => {
    load()
    return poll(load, 20000)
  })

  async function run(a) {
    if (a.confirm && !confirm(`${a.label}?`)) return
    busy = true
    msg = ''
    try {
      const r = await api(`/services/${service.id}/integration/action`, { method: 'POST', body: { action: a.id, params: a.params } })
      msg = r.message
      pending = null
      storm()
      setTimeout(load, 1500)
    } catch (e) {
      if (e instanceof ApiError && e.status === 403 && e.message === 'reauth_required') pending = a
      else msg = e.message
    } finally {
      busy = false
    }
  }

  async function confirmCode(e) {
    e.preventDefault()
    try {
      await api('/auth/reauth', { method: 'POST', body: { code } })
      code = ''
      const a = pending
      pending = null
      await run({ ...a, confirm: false })
    } catch (err) {
      msg = err.message
    }
  }

  const rowCells = (r) => (Array.isArray(r) ? r : r.cells)
  const rowActions = (r) => (Array.isArray(r) ? [] : r.actions || [])
  function visible(sec, i) {
    const q = (filters[i] || '').toLowerCase().trim()
    if (!q) return sec.rows
    return sec.rows.filter((r) => rowCells(r).some((c) => String(value(c.v)).toLowerCase().includes(q)))
  }
  const pctOf = (b) => (b.total ? Math.min(100, (b.used / b.total) * 100) : 0)
  const amount = (b, v) => (b.unit === 'bytes' ? bytes(v) : value(v))
</script>

{#if !missing}
  <section class="integ">
    <span class="lbl">{data?.label || 'integratie'}</span>
    {#if error}
      <p class="err">{error}</p>
      <p class="hint">Controleer de url en de geheimen onder <b>bewerken → Integratie en API</b>.</p>
    {:else if !data}
      <p class="hint">laden…</p>
    {:else}
      {#if pending}
        <form class="reauth" onsubmit={confirmCode}>
          <span>Bevestig <b>{pending.label}</b> met je 2FA-code</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" autofocus />
          <button class="mini">bevestig</button>
          <button type="button" class="mini x" onclick={() => (pending = null)}>annuleer</button>
        </form>
      {/if}
      {#if msg}<p class="msg">{msg}</p>{/if}

      {#each data.sections as sec, i}
        <div class="sec">
          <div class="sh">
            <span class="st">{sec.title}</span>
            {#if sec.filter && sec.rows.length > 8}
              <input class="filter" placeholder="filter" bind:value={filters[i]} />
            {/if}
            {#each sec.actions || [] as a}
              <button class="mini" class:x={a.danger} disabled={busy} onclick={() => run(a)}>{a.label}</button>
            {/each}
          </div>

          {#if sec.kind === 'kv'}
            <div class="kv">
              {#each sec.items as f}
                <div class="kvi lv-{f.level || 'none'}"><small>{f.label}</small><b>{value(f.value)}</b></div>
              {/each}
            </div>
          {:else if sec.kind === 'bars'}
            {#each sec.items as b}
              <div class="meter">
                <div class="bl"><span>{b.label}</span><span class="amt">{amount(b, b.used)} / {amount(b, b.total)}</span></div>
                <div class="track"><div class="fill" class:warn={pctOf(b) >= 80} class:errb={pctOf(b) >= 92} style="width:{pctOf(b)}%"></div></div>
                {#if b.note}<small class="note">{value(b.note)}</small>{/if}
              </div>
            {:else}
              <p class="hint">Geen gegevens.</p>
            {/each}
          {:else if sec.kind === 'table'}
            <div class="tw">
              <table class="tbl">
                <thead><tr>{#each sec.columns as c}<th>{c}</th>{/each}{#if sec.rows.some((r) => rowActions(r).length)}<th></th>{/if}</tr></thead>
                <tbody>
                  {#each visible(sec, i) as r}
                    <tr>
                      {#each rowCells(r) as c}<td class="lv-{c.level || 'none'}">{value(c.v)}</td>{/each}
                      {#if rowActions(r).length}
                        <td class="acts">
                          {#each rowActions(r) as a}
                            <button class="mini" class:x={a.danger} disabled={busy} onclick={() => run(a)}>{a.label}</button>
                          {/each}
                        </td>
                      {/if}
                    </tr>
                  {:else}
                    <tr><td colspan={sec.columns.length} class="lv-muted">{sec.empty || 'Niets te tonen.'}</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else if sec.kind === 'code'}
            <pre>{sec.text}</pre>
          {:else if sec.kind === 'npm-import'}
            <NpmImport {service} {groups} {onchanged} />
          {/if}
        </div>
      {/each}
    {/if}
  </section>
{/if}

<style>
  .integ { margin: 4px 0 18px }
  .sec { margin-top: 12px }
  .sh { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px }
  .st { color: var(--text-h); font-size: 12.5px }
  .st::before { content: "# "; color: var(--dim) }
  .filter { max-width: 180px; padding: 4px 8px; font-size: 12px; margin-left: auto }
  .kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px }
  .kvi { padding: 8px 10px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08) }
  .kvi small { display: block; color: var(--muted); font-size: 11.5px }
  .kvi b { display: block; font-size: 16px; color: var(--text-h) }
  .kvi.lv-warn b { color: var(--mid) }
  .kvi.lv-err b { color: var(--err) }
  .kvi.lv-err { border-color: var(--err) }
  .meter { margin-bottom: 8px }
  .bl { display: flex; justify-content: space-between; gap: 10px; font-size: 12px; color: var(--text) }
  .amt { color: var(--muted) }
  .track { height: 6px; border-radius: 3px; background: rgba(255, 255, 255, .08); overflow: hidden; margin-top: 3px }
  .fill { height: 100%; background: var(--ok) }
  .fill.warn { background: var(--mid) }
  .fill.errb { background: var(--err) }
  .note { color: var(--muted); font-size: 11px }
  .tw { max-height: 360px; overflow: auto }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .tbl th { position: sticky; top: 0; background: #151515; text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 4px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05); white-space: nowrap }
  .tbl td.lv-ok { color: var(--ok) }
  .tbl td.lv-warn { color: var(--mid) }
  .tbl td.lv-err { color: var(--err) }
  .tbl td.lv-muted { color: var(--dim) }
  .acts { text-align: right }
  .acts .mini { padding: 2px 7px; font-size: 11px }
  pre { max-height: 300px; overflow: auto; font-size: 11.5px; background: rgba(0, 0, 0, .35); padding: 10px; border-radius: 8px; color: var(--text) }
  .reauth { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding: 10px; border: 1px solid var(--mid); border-radius: 10px; font-size: 12.5px }
  .reauth input { width: 110px; padding: 5px 8px }
  .msg { color: var(--ok); font-size: 12.5px }
</style>
