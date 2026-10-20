<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Openstaande updates: nodes en PBS via hun API, machines en containers via SSH, Docker via Portainer.
  // Installeren kan hier ook: eerst een snapshot, dan apt, dan kijken of de services nog leven; terugdraaien met één klik.
  let { onclose, onchanged } = $props()

  let data = $state(null)
  let plans = $state({})
  let runs = $state([])
  let error = $state('')
  let open = $state({})
  let onlyOpen = $state(true)
  let tab = $state('open')
  let picked = $state({})
  let snapshot = $state(true)
  let secOnly = $state(false)
  let refused = $state([])
  let detail = $state(null)
  let cfg = $state(null)
  let note = $state('')

  async function load() {
    try {
      const was = data?.running
      ;[data, plans, runs] = await Promise.all([api('/updates'), api('/updates/plans'), api('/updates/runs')])
      error = ''
      if (was && !data.running) onchanged?.()
      if (detail) detail = await api(`/updates/runs/${detail.id}`)
    } catch (e) { error = e.message }
  }
  let busy = $derived(runs.some((r) => !DONE.includes(r.status)))
  onMount(() => {
    load()
    api('/updates/settings').then((s) => (cfg = s)).catch(() => {})
    return poll(() => (data?.running || busy || (detail && !DONE.includes(detail.status))) && load(), 2000)
  })

  async function refresh() {
    try {
      await api('/updates/refresh', { method: 'POST' })
      await load()
    } catch (e) { error = e.message }
  }

  async function install(keys, withSnapshot = snapshot) {
    refused = []
    try {
      const r = await withReauth(() => api('/updates/install', { method: 'POST', body: { targets: keys, snapshot: withSnapshot, security_only: secOnly } }))
      refused = r.refused
      picked = {}
      if (r.runs.length && !r.refused.length) { tab = 'runs'; detail = r.runs.length === 1 ? { ...r.runs[0], output: '' } : null }
      await load()
    } catch (e) { error = e.message }
  }

  async function rollback(r) {
    if (!confirm(`${r.name} terugzetten naar snapshot ${r.snapshot.name}? Alles wat sindsdien op die machine veranderde gaat verloren.`)) return
    try {
      await withReauth(() => api(`/updates/runs/${r.id}/rollback`, { method: 'POST' }))
      detail = { ...r, status: 'terugdraaien', output: detail?.output || '' }
      await load()
    } catch (e) { error = e.message }
  }

  async function saveCfg() {
    note = ''
    try {
      cfg = await withReauth(() => api('/updates/settings', { method: 'PUT', body: { ...cfg, hour: Number(cfg.hour), keep_days: Number(cfg.keep_days) } }))
      note = 'bewaard'
    } catch (e) { note = e.message }
  }

  async function show(r) {
    try { detail = await api(`/updates/runs/${r.id}`) } catch (e) { error = e.message }
  }

  const DONE = ['ok', 'fout', 'services_down', 'teruggedraaid', 'terugdraaien_mislukt', 'geannuleerd']
  const STATUS = { wacht: 'wacht', snapshot: 'snapshot maken…', installeren: 'installeren…', controleren: 'services nakijken…',
                   ok: 'gelukt', fout: 'mislukt', services_down: 'services down', teruggedraaid: 'teruggedraaid',
                   terugdraaien: 'terugdraaien…', terugdraaien_mislukt: 'terugdraaien mislukt' }
  const KIND = { node: 'node', pbs: 'PBS', host: 'machine', ct: 'container', docker: 'docker' }
  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : 'nog nooit')
  let shown = $derived((data?.targets || []).filter((t) => !onlyOpen || t.count || t.error))
  let chosen = $derived(Object.keys(picked).filter((k) => picked[k]))
  let installable = $derived(shown.filter((t) => t.count && plans[t.key]?.can))
</script>

<Modal title="apt list --upgradable" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  <div class="tabs">
    <button class="mini" class:on={tab === 'open'} onclick={() => (tab = 'open')}>openstaand</button>
    <button class="mini" class:on={tab === 'runs'} onclick={() => (tab = 'runs')}>installaties{#if busy}<i class="pulse"></i>{/if}</button>
    <button class="mini" class:on={tab === 'auto'} onclick={() => (tab = 'auto')}>'s nachts{#if cfg?.auto}<b class="on-dot">●</b>{/if}</button>
  </div>
  {#if data && tab === 'open'}
    <div class="top">
      <div class="sum">
        <b>{data.total}</b> update{data.total === 1 ? '' : 's'} open
        {#if data.security}<span class="sec">· {data.security} beveiliging</span>{/if}
        <small>laatst gecontroleerd {when(data.checked_at)}</small>
      </div>
      <label class="chk"><input type="checkbox" bind:checked={onlyOpen} /> alleen met updates</label>
      <button class="mini" disabled={data.running} onclick={refresh}>{data.running ? 'bezig…' : 'nu controleren'}</button>
    </div>

    {#if installable.length}
      <div class="inst">
        <label class="chk"><input type="checkbox" checked={installable.every((t) => picked[t.key])}
               onchange={(e) => { for (const t of installable) picked[t.key] = e.currentTarget.checked }} /> alles</label>
        <label class="chk" title="Proxmox-snapshot vooraf, zodat je met één klik terug kan"><input type="checkbox" bind:checked={snapshot} /> snapshot vooraf</label>
        <label class="chk"><input type="checkbox" bind:checked={secOnly} /> alleen beveiligingsupdates</label>
        <button class="btn" disabled={!chosen.length || busy} onclick={() => install(chosen)}>
          {chosen.length ? `${chosen.length} installeren` : 'kies wat je wil installeren'}</button>
      </div>
    {/if}
    {#each refused as x}
      <p class="ref">{x.name}: {x.why}
        {#if x.nosnap}<button class="lnk" onclick={() => install([x.key], false)}>toch installeren zonder snapshot</button>{/if}</p>
    {/each}

    {#each shown as t (t.key)}
      {@const p = plans[t.key]}
      <div class="tg" class:bad={t.error}>
        <div class="hrow">
          {#if t.count && p?.can}<input type="checkbox" class="pick" bind:checked={picked[t.key]} aria-label="{t.name} kiezen" />{/if}
          <button class="hd" onclick={() => (open[t.key] = !open[t.key])} disabled={!t.count}>
            <span class="nm"><b>{t.name}</b><small>{KIND[t.kind] || t.kind}{t.node ? ` op ${t.node}` : ''}{t.vmid ? ` · ${t.vmid}` : ''}</small>
              {#if t.count && p?.can}<small class="snap" class:no={!p.snapshot} title={p.nosnap || ''}>{p.snapshot ? '◉ snapshot kan' : '○ geen snapshot'}</small>{/if}</span>
            {#if t.error}<span class="msg">{t.error}</span>
            {:else}
              <span class="cnt" class:zero={!t.count}>{t.count ? `${t.count}${t.kind === 'docker' ? ' verouderd' : ''}` : 'bijgewerkt'}</span>
              {#if t.security}<span class="sec">{t.security} beveiliging</span>{/if}
              {#if t.count}<span class="ar">{open[t.key] ? '▾' : '▸'}</span>{/if}
            {/if}
          </button>
        </div>
        {#if open[t.key] && t.count}
          {#if !p?.can}<p class="why">{p?.why || ''}</p>{/if}
          <table class="pk">
            <tbody>
              {#each t.packages as pk}
                <tr class:s={pk.sec}><td>{pk.n}</td><td class="m">{pk.from || ''}</td><td>{pk.to || ''}</td></tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    {:else}
      <p class="hint">
        {#if data.targets.length}Alles is bijgewerkt.{:else}Nog niets om op te volgen. Updates komen van <b>proxmox</b>-, <b>PBS</b>- en
          <b>portainer</b>-tegels, en van SSH-hosts waarbij je in de terminal <i>updates opvolgen</i> aanzet (op een Proxmox-node
          kan dat meteen voor alle containers).{/if}
      </p>
    {/each}
    <p class="hint small">Elke 6 uur gecontroleerd. Installeren kan voor machines en containers die via SSH bereikbaar zijn;
      Docker-images en OPNsense werk je bij in Portainer of OPNsense zelf.</p>
  {:else if tab === 'runs'}
    <table class="runs">
      <thead><tr><th>machine</th><th>gestart</th><th>status</th><th>snapshot</th><th></th></tr></thead>
      <tbody>
        {#each runs as r (r.id)}
          <tr class:sel={detail?.id === r.id} onclick={() => show(r)}>
            <td><b>{r.name}</b>{#if r.trigger === 'auto'}<small class="m"> · 's nachts</small>{/if}{#if r.security_only}<small class="m"> · beveiliging</small>{/if}</td>
            <td>{when(r.started_at || r.created_at)}</td>
            <td class="st-{r.status}">{STATUS[r.status] || r.status}{#if r.reboot_needed && r.status === 'ok'}<small class="m"> · herstart nodig</small>{/if}</td>
            <td><small>{r.snapshot?.name || (r.snapshot ? '…' : 'geen')}{r.snapshot?.removed_at ? ' (opgeruimd)' : ''}</small></td>
            <td>{#if r.can_rollback}<button class="mini danger" onclick={(e) => { e.stopPropagation(); rollback(r) }}>terugdraaien</button>{/if}</td>
          </tr>
        {:else}
          <tr><td colspan="5" class="hint">Nog niets geïnstalleerd vanuit het dashboard.</td></tr>
        {/each}
      </tbody>
    </table>
    {#if detail}
      <div class="det">
        <div class="dh"><b>{detail.name}</b> <span class="st-{detail.status}">{STATUS[detail.status] || detail.status}</span>
          {#if detail.error}<span class="e">{detail.error}</span>{/if}</div>
        {#if detail.checks?.length}
          <p class="checks">{#each detail.checks as c}<span class:e={!c.ok} class:o={c.ok}>{c.ok ? '✓' : '✗'} {c.name}</span>{/each}</p>
        {/if}
        <pre>{detail.output || '…'}</pre>
      </div>
    {/if}
  {:else if tab === 'auto' && cfg}
    <div class="auto">
      <label class="chk"><input type="checkbox" bind:checked={cfg.auto} /> elke nacht beveiligingsupdates installeren</label>
      <label>om <input type="number" min="0" max="23" bind:value={cfg.hour} /> uur</label>
      <p class="hint small">Alleen op containers en VM's waar een snapshot kan (nooit op een fysieke node), alleen de pakketten die als
        beveiligingsupdate gemarkeerd zijn, één machine na de andere. Is een gekoppelde service daarna down of faalt apt, dan
        draait de homepage zelf terug naar de snapshot en krijg je een melding.</p>
      <label>eigen snapshots van geslaagde installaties opruimen na <input type="number" min="1" max="90" bind:value={cfg.keep_days} /> dagen</label>
      <div class="row"><button class="btn" onclick={saveCfg}>bewaren</button><span class="m">{note}</span></div>
    </div>
  {:else}
    <p class="hint">laden…</p>
  {/if}
</Modal>

<style>
  .tabs { display: flex; gap: 6px; margin-bottom: 12px }
  .pulse { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #a9c7ff; margin-left: 6px; animation: p 1.2s infinite }
  @keyframes p { 50% { opacity: .3 } }
  .on-dot { color: var(--ok); margin-left: 5px; font-size: 9px }
  .top { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 10px }
  .sum { flex: 1; font-size: 13px }
  .sum b { font-size: 18px; color: var(--text-h); font-weight: 500 }
  .sum small { display: block; color: var(--dim); font-size: 11px }
  .chk { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center }
  .chk input, .pick { width: auto }
  .inst { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; padding: 8px 12px; border: 1px solid var(--line); border-radius: 10px; margin-bottom: 10px }
  .inst .btn { margin-left: auto }
  .ref { font-size: 12px; color: var(--mid); margin: 0 0 6px }
  .lnk { background: none; border: 0; color: #a9c7ff; cursor: pointer; font: inherit; text-decoration: underline; padding: 0 0 0 6px }
  .sec { color: var(--mid); font-size: 12px }
  .tg { border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08); margin-bottom: 6px }
  .tg.bad { border-color: rgba(229, 139, 139, .3) }
  .hrow { display: flex; align-items: center; padding-left: 10px }
  .hd { all: unset; box-sizing: border-box; flex: 1; display: flex; gap: 12px; align-items: center; padding: 8px 12px; cursor: pointer }
  .hd:disabled { cursor: default }
  .hd:focus-visible { outline: 1px solid var(--line-2) }
  .nm { flex: 1; min-width: 0 }
  .nm b { font-weight: 500; color: var(--text-h); font-size: 13px; margin-right: 8px }
  .nm small { color: var(--dim); font-size: 11.5px }
  .snap { margin-left: 8px; color: var(--ok) !important }
  .snap.no { color: var(--muted) !important }
  .why { font-size: 12px; color: var(--muted); margin: 0 12px 6px }
  .msg { color: var(--err); font-size: 12px; text-align: right }
  .cnt { color: var(--text-h); font-size: 12.5px }
  .cnt.zero { color: var(--ok) }
  .ar { color: var(--muted); font-size: 11px }
  .pk { width: 100%; border-collapse: collapse; font-size: 12px; margin: 0 0 6px }
  .pk td { padding: 3px 12px; border-top: 1px solid rgba(255, 255, 255, .05); white-space: nowrap }
  .pk td:first-child { width: 40%; white-space: normal; overflow-wrap: anywhere }
  .pk tr.s td:first-child { color: var(--mid) }
  .m { color: var(--dim) }
  .small { font-size: 11.5px; margin-top: 10px }
  .runs { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .runs th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 8px; border-bottom: 1px solid var(--line) }
  .runs td { padding: 6px 8px; border-bottom: 1px solid var(--line); cursor: pointer }
  .runs tr:hover td, .runs tr.sel td { background: var(--fill) }
  .runs b { font-weight: 500; color: var(--text-h) }
  .st-ok, .st-teruggedraaid, .o { color: var(--ok) }
  .st-fout, .st-services_down, .st-terugdraaien_mislukt, .e { color: var(--err) }
  .st-snapshot, .st-installeren, .st-controleren, .st-terugdraaien { color: #a9c7ff }
  .danger { color: var(--err) }
  .det { margin-top: 12px; border: 1px solid var(--line); border-radius: 10px; padding: 10px }
  .dh { display: flex; gap: 10px; flex-wrap: wrap; align-items: baseline; font-size: 13px }
  .dh b { font-weight: 500; color: var(--text-h) }
  .dh .e { font-size: 12px }
  .checks { display: flex; gap: 10px; flex-wrap: wrap; font-size: 12px; margin: 6px 0 }
  pre { max-height: 340px; overflow: auto; font-size: 11.5px; background: rgba(0, 0, 0, .35); padding: 8px 10px; border-radius: 8px; margin: 8px 0 0; white-space: pre-wrap }
  .auto { display: flex; flex-direction: column; gap: 10px; font-size: 12.5px; max-width: 640px }
  .auto label { display: flex; gap: 6px; align-items: center; color: var(--muted) }
  .auto label input[type=number] { width: 64px }
  .row { display: flex; gap: 10px; align-items: center }
  @media (max-width: 600px) { .runs th:nth-child(4), .runs td:nth-child(4) { display: none } }
</style>
