<script>
  import { onMount, untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import CleanupForm from './CleanupForm.svelte'
  import { ask } from './dialog.svelte.js'
  import Modal from './Modal.svelte'
  import NewServiceForm from './NewServiceForm.svelte'
  import RunSteps from './RunSteps.svelte'
  import Tabs from './Tabs.svelte'

  // Nieuwe service in één keer: proxy host en certificaat in NPM, DNS in Cloudflare (of een tunnelregel), de naam in
  // AdGuard, een tegel met check en de CT/VM in de back-up. En het omgekeerde: een service opruimen.
  // tab: maken | opruimen | geschiedenis. service: de tegel voor opruimen. ondone: er veranderde iets aan de tegels.
  let { tab = 'maken', service = null, groups = [], services = [], onclose, ondone = null } = $props()

  let current = $state(untrack(() => tab || 'maken'))
  let opties = $state(null)
  let optErr = $state('')
  let runs = $state(null)
  let runsErr = $state('')
  let shown = $state(null)
  // Echt uitvoeren: standaard uit (alleen de proef). Aanzetten vraagt een verse 2FA, uitzetten niet.
  let echt = $state(null)
  let echtBusy = $state(false)
  let echtErr = $state('')
  let real = $derived(echt?.on === true)

  async function loadOpties() {
    try { opties = await api('/nieuweservice/opties'); optErr = '' } catch (e) { optErr = e.message; opties = { systems: {} } }
  }
  async function loadRuns() {
    try { runs = (await api('/nieuweservice/runs')).runs; runsErr = '' } catch (e) { runsErr = e.message }
  }
  async function loadEcht() {
    try { echt = await api('/nieuweservice/echt'); echtErr = '' } catch (e) { echtErr = e.message }
  }
  onMount(() => { loadOpties(); loadRuns(); loadEcht() })

  async function setEcht(e) {
    const on = e.currentTarget.checked
    e.currentTarget.checked = real   // pas omzetten als de server het bevestigt
    if (on && !(await ask('Echt uitvoeren aanzetten? Maken, opruimen en ongedaan maken veranderen dan echt NPM, ' +
      'Cloudflare, AdGuard, Proxmox en de tegels. Doe het pas als een proef op je echte systemen klopte.', { ok: 'Aanzetten' }))) return
    echtBusy = true
    echtErr = ''
    try {
      const put = () => api('/nieuweservice/echt', { method: 'PUT', body: { on } })
      echt = on ? await withReauth(put) : await put()
    } catch (err) { echtErr = err.message } finally { echtBusy = false }
  }

  const half = (r) => (r.status === 'gestopt' || r.status === 'onderbroken') && !r.undone_by
  let tabs = $derived([
    { key: 'maken', label: 'maken' },
    { key: 'opruimen', label: 'opruimen' },
    { key: 'geschiedenis', label: 'geschiedenis', dot: runs?.some(half) ? 'err' : undefined },
  ])

  async function show(id) {
    try { shown = await api(`/nieuweservice/runs/${id}`); runsErr = '' } catch (e) { runsErr = e.message }
  }
  function changed() {
    loadRuns()
    ondone?.()
  }
  const KIND = { maken: 'maken', opruimen: 'opruimen', ongedaan: 'ongedaan maken' }
  const STATUS = { bezig: 'bezig', klaar: 'klaar', gestopt: 'gestopt', onderbroken: 'onderbroken', ongedaan: 'ongedaan gemaakt' }
  const when = (ts) => {
    const d = new Date(ts)
    return isNaN(d) ? '' : d.toLocaleString('nl-BE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
  }
</script>

<Modal title="service new" {onclose} wide>
  <Tabs items={tabs} bind:value={current} label="Nieuwe service" />
  <div class="echt">
    <label class="chk"><input id="ns-echt" type="checkbox" checked={real} disabled={!echt || echtBusy} onchange={setEcht} />
      echt uitvoeren</label>
    <span class="hint small">{real ? 'Aan: maken, opruimen en ongedaan maken veranderen echt iets (met je 2FA-code).'
      : 'Uit: alleen de proef. Klopt een proef op je echte systemen, zet het dan aan (vraagt je 2FA-code).'}</span>
  </div>
  {#if echtErr}<p class="err">{echtErr}</p>{/if}
  {#if optErr}<p class="err">{optErr}</p>{/if}

  {#if opties?.busy && current !== 'geschiedenis'}
    <!-- Een run die al liep toen je het venster opende (bv. van een ander toestel). -->
    {#key opties.busy.id}
      <RunSteps run={opties.busy} undo echt={real} onfinish={changed} />
    {/key}
  {/if}

  {#if current === 'maken'}
    <NewServiceForm {opties} {groups} {onclose} echt={real} ondone={changed} />
  {:else if current === 'opruimen'}
    <CleanupForm {service} {services} echt={real} ondone={changed} />
  {:else}
    {#if runsErr}<p class="err">{runsErr}</p>{/if}
    {#if runs && !runs.length}<p class="hint small">Nog niets gemaakt of opgeruimd.</p>{/if}
    <ul class="hist">
      {#each runs || [] as r (r.id)}
        <li>
          <button class="row-btn" class:on={shown?.id === r.id} onclick={() => (shown?.id === r.id ? (shown = null) : show(r.id))}>
            <span class="m">{when(r.at)}</span> · {KIND[r.kind] || r.kind} · <b>{r.fqdn || '?'}</b> ·
            <span class:e={half(r)} class:g={r.status === 'klaar' && !r.warning} class:w={r.status === 'klaar' && r.warning}>{STATUS[r.status] || r.status}</span>
          </button>
          {#if shown?.id === r.id}
            {#key shown.id}
              <RunSteps run={shown} undo echt={real} onfinish={() => loadRuns()} onundo={(u) => { shown = u; changed() }} />
            {/key}
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</Modal>

<style>
  .echt { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; margin: 6px 0 2px; font-size: 12.5px }
  .echt .chk { display: inline-flex; align-items: center; gap: 5px; color: var(--text-h); white-space: nowrap }
  .echt .hint { min-width: 0; overflow-wrap: anywhere }
  .hist { list-style: none; padding: 0; margin: 4px 0 }
  .hist li { border-top: 1px solid var(--line); padding: 2px 0 }
  .row-btn { width: 100%; text-align: left; background: none; border: 0; color: var(--text); padding: 6px 2px;
             font-size: 12.5px; cursor: pointer; overflow-wrap: anywhere }
  .row-btn:hover, .row-btn.on { color: var(--text-h) }
  .row-btn b { font-weight: 500 }
  .m { color: var(--muted) }
  .small { font-size: 12px; margin: 2px 0 }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .w { color: var(--mid) }
</style>
