<script>
  import { onMount, untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import { bytes, duration } from './format.js'
  import { rel } from './cronfmt.js'
  import CopyCmd from './CopyCmd.svelte'

  // Back-updekking per VM/CT (job, kopieën per PBS, nieuwste, hersteltest) en een sync tussen twee PBS'en.
  let { onfix } = $props()
  let data = $state.raw(null)
  let error = $state('')
  let busy = $state('')
  let only = $state(true)

  async function load() {
    try { data = await api('/backups'); error = '' } catch (e) { error = e.message }
  }
  onMount(load)

  async function refresh() {
    busy = 'refresh'
    try {
      await api('/backups/refresh', { method: 'POST' })
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 1500))
        await load()
        if (!data?.running) break
      }
    } catch (e) { error = e.message } finally { busy = '' }
  }

  const LV = { err: 'probleem', warn: 'let op', ok: 'dubbel' }
  let rows = $derived((data?.clusters || []).map((c) => ({ ...c, shown: only ? c.rows.filter((r) => r.level !== 'ok') : c.rows })))
  let total = $derived(data?.counts || { err: 0, warn: 0, ok: 0, total: 0 })

  // --- PBS-sync ---------------------------------------------------------------------------------
  let plan = $state(null)
  let checked = $state.raw(null)
  let planErr = $state('')
  let steps = $state.raw(null)
  $effect(() => { if (data?.sync?.plan && !plan) untrack(() => (plan = { ...data.sync.plan })) })
  let timer
  $effect(() => {
    if (!plan) return
    const body = $state.snapshot(plan)
    clearTimeout(timer)
    timer = setTimeout(async () => {
      try { checked = await api('/backups/sync/plan', { method: 'POST', body }); planErr = '' } catch (e) { checked = null; planErr = e.message }
    }, 300)
    return () => clearTimeout(timer)
  })
  let pbs = $derived(data?.sync?.pbs || [])
  const storesOf = (id) => pbs.find((p) => p.service_id === id)?.stores || []
  function pick(side, id) {
    plan[side === 'src' ? 'source_id' : 'target_id'] = id
    plan[side === 'src' ? 'src_store' : 'dst_store'] = storesOf(id)[0] || ''
    if (side === 'src') plan.host = pbs.find((p) => p.service_id === id)?.host || ''
  }
  async function create() {
    if (!confirm(`Op ${checked.source} een sync-gebruiker met leesrecht maken, en op ${checked.target} een sync-job die elke dag om ${plan.schedule} ophaalt?`)) return
    busy = 'create'
    steps = null
    try {
      const r = await withReauth(() => api('/backups/sync/create', { method: 'POST', body: $state.snapshot(plan) }))
      steps = r.log
      await refresh()
    } catch (e) { planErr = e.message } finally { busy = '' }
  }
</script>

<div class="head">
  <span class="hint">Per VM/CT: in welke back-upjob van Proxmox hij zit, op hoeveel PBS'en een kopie staat, hoe oud de nieuwste
    is en wanneer hij voor het laatst hersteld getest is. Rood: geen back-upjob of geen kopie. Oranje: maar op één PBS.
    Elk half uur.</span>
  <span class="when">{busy === 'refresh' ? 'bezig…' : data?.at ? `bekeken ${rel(data.at)}` : ''}</span>
  <button class="mini" disabled={busy === 'refresh'} onclick={refresh}>⟳ nu</button>
</div>
{#if error}<p class="err">{error}</p>{/if}

{#if data && !data.clusters.length}
  <p class="hint">Nog geen gegevens. Daarvoor is een tegel van type <b>proxmox</b> nodig (het token heeft genoeg aan PVEAuditor),
    en voor de kopieën een tegel per PBS. {data.at ? '' : 'Druk op ⟳ nu.'}</p>
{:else if data}
  <div class="sum">
    <span class="c e">{total.err} zonder back-up of job</span>
    <span class="c w">{total.warn} maar op één PBS of uitgeschakeld</span>
    <span class="c g">{total.ok} dubbel</span>
    <label class="chk"><input type="checkbox" bind:checked={only} /> alleen wat niet dubbel is</label>
  </div>
  {#each rows as c (c.service_id)}
    {#if c.error}<p class="err">{c.service}: {c.error}</p>{/if}
    {#if c.shown.length}
      <div class="wrap">
        <table class="tbl">
          <thead><tr><th></th><th>VM/CT</th><th>job</th><th>kopieën</th><th>nieuwste</th><th>hersteltest</th></tr></thead>
          <tbody>
            {#each c.shown as r (r.vmid)}
              <tr class="lv-{r.level}">
                <td><span class="dot" title={LV[r.level]}></span></td>
                <td><b>{r.name}</b> <small>{r.type.toUpperCase()} {r.vmid} · {r.node}{r.stopped ? ' · uit' : ''}</small>
                  <div class="why">{r.why}</div></td>
                <td>{#if r.jobs.length}{r.jobs.join(', ')}{:else}<span class="e">geen</span>{/if}</td>
                <td>
                  {#each r.copies as k (k.pbs)}<span class="pbs" title={`${k.store}${k.ns ? ` / ${k.ns}` : ''} · ${k.count ?? '?'} back-ups`}>{k.pbs}</span>{/each}
                  {#if !r.copies.length}<span class="m">—</span>{/if}
                </td>
                <td class:w={r.newest > 26 * 3600} class:e={r.newest > 3 * 86400}>{r.newest != null ? duration(r.newest) : '—'}</td>
                <td>
                  {#if r.restore}<span class:g={r.restore.ok} class:e={!r.restore.ok}>{r.restore.ok ? '✓' : '✗'} {rel(r.restore.at)}</span>
                  {:else if r.type === 'ct'}<span class="m">nooit</span>{:else}<span class="m" title="De hersteltest doet alleen containers">—</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if !c.error}
      <p class="hint ok">Alle {c.rows.length} VM's en CT's staan op minstens twee PBS'en.</p>
    {/if}
  {/each}
  {#if total.total && !data.clusters.some((c) => c.rows.some((r) => r.restore))}
    <p class="hint">Nog geen hersteltest gedaan: <button class="link" onclick={() => onfix?.({ window: 'restoretest' })}>hersteltest instellen</button>.</p>
  {/if}

  <h3>PBS-sync: elke back-up op twee machines</h3>
  {#each data.sync.links as l (l.on + l.job)}
    <div class="link-row">
      <b>{l.from} → {l.to}</b> <small>sync-job {l.job} op {l.on} · {l.remote_store} → {l.store} · {l.schedule || 'geen uur'}</small>
      {#if l.last_state}<span class:g={l.last_state === 'OK'} class:e={l.last_state !== 'OK'}>laatste: {l.last_state}</span>{/if}
    </div>
  {/each}
  {#if data.sync.state === 'te-weinig'}
    <p class="hint">Daarvoor zijn twee PBS-tegels nodig (type proxmoxbackupserver).
      {data.sync.pbs.length ? `Nu werkt alleen ${data.sync.pbs.join(', ')}.` : 'Er is er nog geen.'}</p>
  {:else if data.sync.state === 'bestaat'}
    <p class="hint ok">De sync die het dashboard zou voorstellen, bestaat al.{total.warn ? ' Na de eerste run staan de VM\'s en CT\'s hierboven op twee PBS\'en.' : ''}</p>
  {:else if plan}
    <p class="hint">Voorstel: {checked?.target || 'de tweede PBS'} haalt elke nacht een kopie op van {checked?.source || 'de PBS'} waar
      Proxmox naartoe schrijft. Pas aan wat niet klopt; de commando's volgen mee.</p>
    <div class="form">
      <label>van <select value={plan.source_id} onchange={(e) => pick('src', +e.target.value)}>
        {#each pbs as p (p.service_id)}<option value={p.service_id}>{p.name}</option>{/each}</select></label>
      <label>datastore <select bind:value={plan.src_store}>{#each storesOf(plan.source_id) as s (s)}<option>{s}</option>{/each}</select></label>
      <label>naar <select value={plan.target_id} onchange={(e) => pick('dst', +e.target.value)}>
        {#each pbs as p (p.service_id)}<option value={p.service_id}>{p.name}</option>{/each}</select></label>
      <label>datastore <select bind:value={plan.dst_store}>{#each storesOf(plan.target_id) as s (s)}<option>{s}</option>{/each}</select></label>
      <label>adres van de bron <input bind:value={plan.host} placeholder="192.168.0.70" /></label>
      <label>poort <input bind:value={plan.port} inputmode="numeric" maxlength="5" /></label>
      <label>elke dag om <input bind:value={plan.schedule} placeholder="06:00" maxlength="5" /></label>
      <label class="wide">vingerafdruk van de bron <input bind:value={plan.fingerprint} placeholder="AB:CD:…" /></label>
    </div>
    {#if planErr}<p class="err">{planErr}</p>{/if}
    {#if checked}
      {#each checked.notes as n}<p class="note" class:w={checked.level === 'warn'} class:e={checked.level === 'err'}>{n}</p>{/each}
      <ol class="steps">
        <li>Op <b>{checked.source}</b>: een gebruiker die alleen mag lezen, met een token. Het tweede commando toont het
          geheim (value); bewaar het voor stap 2.
          {#each checked.commands.source as cmd}<CopyCmd {cmd} />{/each}</li>
        <li>Op <b>{checked.target}</b>: {checked.source} als remote, en de sync-job. Vul het geheim uit stap 1 in.
          {#each checked.commands.target as cmd}<CopyCmd {cmd} />{/each}</li>
        <li>Zet op {checked.target} ook een prune-job (Datastore → Prune &amp; GC), anders blijft de kopie groeien.</li>
      </ol>
      <div class="go">
        <button class="btn" disabled={busy === 'create' || !checked.ssh.source || !checked.ssh.target || checked.level === 'err'}
                onclick={create}>{busy === 'create' ? 'bezig…' : 'stap 1 en 2 zelf uitvoeren via SSH'}</button>
        <span class="hint">{#if checked.ssh.source && checked.ssh.target}Via de SSH-hosts {checked.ssh.source} en {checked.ssh.target}
          (als root). Vraagt je 2FA-code.{:else}Voor deze knop moeten {[!checked.ssh.source && checked.source, !checked.ssh.target && checked.target].filter(Boolean).join(' en ')}
          als SSH-host in de terminal staan. <button class="link" onclick={() => onfix?.({ window: 'terminal' })}>terminal openen</button>{/if}</span>
      </div>
      {#if steps}<pre class="log">{steps.join('\n')}</pre>{/if}
    {/if}
  {/if}
  <p class="hint small">Zie je een sync die al bestaat hier niet? Geef het token van de PBS-tegel ook de rol RemoteAudit op /remote;
    zonder dat recht houdt PBS de sync-jobs verborgen.</p>
  {#if data.pbs.some((p) => p.error)}
    {#each data.pbs.filter((p) => p.error) as p (p.service_id)}<p class="err">{p.name}: {p.error}</p>{/each}
  {/if}
{/if}

<style>
  .head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding: 10px 0 }
  .head .hint { flex: 1; min-width: 240px; font-size: 12px; margin: 0 }
  .when { color: var(--dim); font-size: 12px }
  .sum { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin: 0 0 8px; font-size: 12.5px }
  .chk { margin-left: auto; font-size: 12px; color: var(--muted); display: flex; gap: 5px; align-items: center }
  .wrap { overflow-x: auto }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; min-width: 620px }
  .tbl th { text-align: left; font-weight: 400; color: var(--muted); font-size: 11.5px; padding: 6px 8px; border-bottom: 1px solid var(--line) }
  .tbl td { padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top }
  .tbl td b { font-weight: 500; color: var(--text-h) }
  .tbl small, .m { color: var(--muted) }
  .why { font-size: 11.5px; color: var(--muted) }
  .lv-err .why { color: var(--err) }
  .lv-warn .why { color: var(--mid) }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: var(--ok); margin-top: 4px }
  .lv-err .dot { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .lv-warn .dot { background: var(--mid) }
  .pbs { display: inline-block; font-size: 11px; padding: 0 6px; margin: 0 4px 2px 0; border-radius: 6px; border: 1px solid var(--line-2) }
  .g { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .ok { color: var(--ok) }
  h3 { margin: 18px 0 6px; color: var(--text-h); font-weight: 500; font-size: 13px }
  .link-row { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; font-size: 12.5px; padding: 6px 10px;
              border: 1px solid var(--line); border-radius: 8px; margin-bottom: 6px; background: var(--fill) }
  .link-row b { font-weight: 500; color: var(--text-h) }
  .link-row small { color: var(--muted) }
  .form { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(200px, 100%), 1fr)); gap: 8px; margin: 8px 0 }
  .form label { display: flex; flex-direction: column; gap: 3px; font-size: 11.5px; color: var(--muted) }
  .form .wide { grid-column: 1 / -1 }
  .note { font-size: 12.5px; margin: 4px 0 }
  .steps { font-size: 12.5px; padding-left: 18px; margin: 8px 0 }
  .steps li { margin: 8px 0; line-height: 1.5 }
  .go { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 8px 0 }
  .go .hint { margin: 0; font-size: 12px; flex: 1; min-width: 220px }
  .link { background: none; border: none; padding: 0; color: var(--text-h); cursor: pointer; font: inherit; text-decoration: underline }
  .log { font-size: 12px; padding: 8px 10px; border-radius: 8px; background: rgba(0, 0, 0, .3); border: 1px solid var(--line); white-space: pre-wrap }
  .small { font-size: 11.5px }
</style>
