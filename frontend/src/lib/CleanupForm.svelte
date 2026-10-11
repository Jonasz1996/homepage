<script>
  import { onMount, untrack } from 'svelte'
  import { api, ApiError, withReauth } from './api.js'
  import { ask } from './dialog.svelte.js'
  import { inZone, nsDomain } from './nieuweservice.js'
  import ProefPlan from './ProefPlan.svelte'
  import RunSteps from './RunSteps.svelte'

  // Tabblad "opruimen": alles van één naam weghalen, DNS eerst en de tegel als laatste. Alleen <naam>.<domein>, en
  // alleen records die naar NPM wijzen of van dit dashboard komen: wat blijft staan, zegt de proef.
  // service: de tegel waarvoor je "opruimen…" koos. ondone: er is iets weg (de tegels herladen).
  let { service = null, services = [], ondone = null } = $props()

  let domain = $state(null)
  let tile = $state(untrack(() => (service?.id ? String(service.id) : '')))
  let label = $state('')
  let backup = $state(false)
  let plan = $state(null)
  let sentKey = $state('')
  let sent = null
  let run = $state(null)
  let busy = $state(false)
  let error = $state('')
  let note = $state('')
  let orphans = $state(null)
  let loaded = $state(false)

  onMount(() => {
    nsDomain().then((d) => (domain = d.domain)).catch(() => {}).finally(() => (loaded = true))
    api('/nieuweservice/losse-dns').then((r) => (orphans = r)).catch((e) => (orphans = { items: [], error: e.message }))
  })

  let tiles = $derived(services.filter((s) => s.id === service?.id || inZone(s.url, domain)))
  function body() {
    if (tile) return { service_id: Number(tile), backup }
    const name = label.trim().toLowerCase()
    return { fqdn: domain ? `${name}.${domain}` : name, backup }
  }
  let changed = $derived(!!plan && JSON.stringify(body()) !== sentKey)

  async function proef(again = false) {
    const b = body()
    if (!b.service_id && !label.trim()) {
      error = 'Kies een tegel of geef een naam.'
      return
    }
    busy = true
    error = ''
    if (!again) note = ''
    try {
      plan = (await api('/nieuweservice/opruimen/proef', { method: 'POST', body: b })).plan
      sent = b
      sentKey = JSON.stringify(b)
    } catch (e) { error = e.message; plan = null } finally { busy = false }
  }

  async function go() {
    if (!(await ask(`Alles van ${plan.fqdn} verwijderen? ${plan.steps.length} stappen. Dit kan niet ongedaan gemaakt worden.`,
                    { ok: 'Opruimen', danger: true }))) return
    busy = true
    error = ''
    try {
      run = (await withReauth(() => api('/nieuweservice/opruimen', { method: 'POST', body: { ...sent, plan_hash: plan.hash } }))).run
      plan = null
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.message === 'plan_veranderd') {
        await proef(true)
        note = 'Het plan is intussen veranderd: hier is het nieuwe.'
      } else if (e instanceof ApiError && e.status === 409 && e.message === 'bezig') {
        error = 'Er loopt al iets: wacht tot het klaar is.'
      } else error = e.message
    } finally { busy = false }
  }

  function pick(name) {
    tile = ''
    label = domain && name.endsWith(`.${domain}`) ? name.slice(0, -domain.length - 1) : name
    plan = null
  }
  async function retry() {
    run = null
    await proef()
  }
</script>

{#if run}
  {#key run.id}
    <RunSteps {run} onfinish={(r) => { run = r; if (r.removed?.length) ondone?.() }} />
  {/key}
  {#if run.status !== 'bezig'}
    <div class="btns">
      {#if run.status !== 'klaar'}<button class="mini" onclick={retry}>opnieuw opruimen</button>{/if}
      <button class="mini" onclick={() => { run = null; plan = null }}>nog iets opruimen</button>
    </div>
  {/if}
{:else}
  <div class="grid">
    <label>Tegel
      <select id="nc-tile" bind:value={tile}>
        <option value="">— een naam typen —</option>
        {#each tiles as s (s.id)}<option value={String(s.id)}>{s.name} ({s.url})</option>{/each}
      </select>
    </label>
    {#if !tile}
      <label>Naam
        <span class="suffix">
          <input id="nc-fqdn" bind:value={label} placeholder="jellyfin" autocomplete="off" spellcheck="false" />
          <span class="sfx">.{domain || '?'}</span>
        </span>
      </label>
    {/if}
    {#if !tile && domain === null && loaded}
      <p class="hint small full">Nog geen domein: maak in API-beheer een API van soort cloudflare (Cloudflare DNS) met je
        zone, of een wildcardcertificaat in NPM.</p>
    {/if}
    <label class="chk full"><input id="nc-backup" type="checkbox" bind:checked={backup} /> ook uit de back-up halen (één CT
      draait vaak meer dan één service)</label>
  </div>

  {#if error}<p class="err">{error}</p>{/if}
  {#if note}<p class="hint small w">{note}</p>{/if}
  {#if plan && changed}<p class="hint small w">Gewijzigd na de proef: doe de proef opnieuw.</p>{/if}
  <div class="btns">
    <button class="mini" disabled={busy} onclick={() => proef()}>proef</button>
    <button class="mini x" disabled={busy || changed || !plan?.kan || !plan?.steps?.length} onclick={go}>opruimen</button>
  </div>
  {#if plan && !plan.kan && plan.waarom?.length}
    <div class="no">Kan niet:<ul>{#each plan.waarom as w, i (i)}<li>{w}</li>{/each}</ul></div>
  {/if}
  {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}

  {#if orphans?.error || orphans?.items?.length}
    <div class="sec">Records van dit dashboard zonder NPM-host</div>
    {#if orphans.error}<p class="err">{orphans.error}</p>{/if}
    <ul class="orph">
      {#each orphans.items as o (o.name + o.type)}
        <li><span>{o.name} <small>{o.type} → {o.content}</small></span>
          <button class="mini" onclick={() => pick(o.name)}>opruimen</button></li>
      {/each}
    </ul>
  {/if}
{/if}

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-items: end }
  .grid label:not(.chk) { display: flex; flex-direction: column; gap: 3px; font-size: 11.5px; color: var(--muted); min-width: 0 }
  .full { grid-column: 1 / -1 }
  .suffix { display: flex; align-items: center; gap: 4px }
  .suffix input { min-width: 0; flex: 1 }
  .sfx { white-space: nowrap; color: var(--text); font-size: 13px }
  .chk { line-height: 1.4 }
  .btns { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 }
  .small { font-size: 12px; margin: 2px 0 }
  .no { color: var(--err); font-size: 12.5px; margin: 6px 0 }
  .no ul { margin: 2px 0; padding-left: 18px }
  .sec { color: var(--muted); font-size: 11.5px; margin-top: 12px }
  .orph { list-style: none; padding: 0; margin: 4px 0; font-size: 12.5px }
  .orph li { display: flex; gap: 8px; align-items: center; justify-content: space-between; padding: 3px 0;
             border-top: 1px solid var(--line); overflow-wrap: anywhere }
  .orph small { color: var(--muted) }
  .w { color: var(--mid) }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr } }
</style>
