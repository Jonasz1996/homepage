<script>
  import { onMount, untrack } from 'svelte'
  import { api } from './api.js'
  import CleanupForm from './CleanupForm.svelte'
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

  async function loadOpties() {
    try { opties = await api('/nieuweservice/opties'); optErr = '' } catch (e) { optErr = e.message; opties = { systems: {} } }
  }
  async function loadRuns() {
    try { runs = (await api('/nieuweservice/runs')).runs; runsErr = '' } catch (e) { runsErr = e.message }
  }
  onMount(() => { loadOpties(); loadRuns() })

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
  {#if optErr}<p class="err">{optErr}</p>{/if}

  {#if opties?.busy && current !== 'geschiedenis'}
    <!-- Een run die al liep toen je het venster opende (bv. van een ander toestel). -->
    {#key opties.busy.id}
      <RunSteps run={opties.busy} undo onfinish={changed} />
    {/key}
  {/if}

  {#if current === 'maken'}
    <NewServiceForm {opties} {groups} {onclose} ondone={changed} />
  {:else if current === 'opruimen'}
    <CleanupForm {service} {services} ondone={changed} />
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
              <RunSteps run={shown} undo onfinish={() => loadRuns()} onundo={(u) => { shown = u; changed() }} />
            {/key}
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</Modal>

<style>
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
