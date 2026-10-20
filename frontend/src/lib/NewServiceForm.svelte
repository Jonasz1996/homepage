<script>
  import { untrack } from 'svelte'
  import { api, ApiError, withReauth } from './api.js'
  import { ask } from './dialog.svelte.js'
  import { LABEL } from './nieuweservice.js'
  import ProefPlan from './ProefPlan.svelte'
  import RunSteps from './RunSteps.svelte'

  // Tabblad "maken": één formulier voor proxy host, certificaat, DNS, tegel en back-up. Eerst de proef (die verandert
  // niets), dan uitvoeren met precies dat plan (de server weigert als er intussen iets veranderde).
  // opties: GET /nieuweservice/opties (null zolang die laadt). ondone: een nieuwe service is klaar (de tegels herladen).
  let { opties = null, groups = [], ondone = null, onclose } = $props()

  const blank = () => ({
    name: '', ip: '', port: '', scheme: 'http', exposure: 'publiek', cert: 'auto', acl: '', p443: false, protect: '',
    ws: true, tile: true, group: untrack(() => groups[0]?.id ?? ''), label: '', check: true, zbx: '', backup: true, job: '',
  })
  let f = $state(blank())
  let touched = $state(false)   // zelf blootstelling gekozen: dan niet meer automatisch aanpassen
  let plan = $state(null)
  let sentKey = $state('')
  let sent = null
  let run = $state(null)
  let busy = $state(false)
  let error = $state('')
  let note = $state('')

  let sys = $derived(opties?.systems || {})
  let domain = $derived(opties?.domain || null)
  let noCf = $derived(!!opties && !sys.cloudflare)
  let lanLists = $derived((opties?.access_lists || []).filter((a) => a.lan_only))
  let pbsJobs = $derived((opties?.jobs || []).filter((j) => j.pbs))

  // Zonder Cloudflare DNS kan alleen "alleen thuis". Voor "alleen thuis" de enige lijst die alleen het LAN toelaat.
  $effect(() => {
    if (noCf && !touched && f.exposure !== 'lan') untrack(() => setExposure('lan', false))
  })
  function setExposure(v, byHand = true) {
    f.exposure = v
    if (byHand) touched = true
    if (v === 'lan' && !f.acl && lanLists.length === 1) f.acl = String(lanLists[0].id)
    if (v === 'lan') f.protect = ''
  }
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s)

  function body() {
    const name = f.name.trim().toLowerCase()
    return {
      name, ip: f.ip.trim(), port: Number(f.port) || 0, scheme: f.scheme, exposure: f.exposure, cert: f.cert,
      access_list_id: f.acl ? Number(f.acl) : null,
      poort_443_dicht: f.exposure === 'lan' && !f.acl && f.p443,
      bescherming_van: f.exposure === 'publiek' && f.protect ? Number(f.protect) : null,
      websockets: f.ws,
      tile: f.tile && f.group !== '' ? { group_id: Number(f.group), label: f.label.trim() || cap(name), check: f.check } : null,
      zabbix: f.zbx || null, backup: f.backup, backup_job: f.backup && f.job ? f.job : null,
    }
  }
  let changed = $derived(!!plan && JSON.stringify(body()) !== sentKey)

  function invalid(b) {
    if (!LABEL.test(b.name)) return 'Naam: één woord met kleine letters, cijfers of -, bv. jellyfin.'
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(b.ip)) return 'IP-adres: bv. 192.168.0.27.'
    if (!(b.port >= 1 && b.port <= 65535)) return 'Poort: een getal van 1 tot 65535.'
    return ''
  }

  async function proef(again = false) {
    const b = body()
    error = invalid(b)
    if (error) return
    busy = true
    if (!again) note = ''
    try {
      const r = await api('/nieuweservice/proef', { method: 'POST', body: b })
      plan = r.plan
      sent = b
      sentKey = JSON.stringify(b)
    } catch (e) { error = e.message; plan = null } finally { busy = false }
  }

  async function go() {
    if (!(await ask(`${plan.fqdn} maken? ${plan.steps.length} stappen, in deze volgorde. Stopt bij de eerste fout.`, { ok: 'Uitvoeren' }))) return
    busy = true
    error = ''
    try {
      const r = await withReauth(() => api('/nieuweservice/maken', { method: 'POST', body: { ...sent, plan_hash: plan.hash } }))
      run = r.run
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.message === 'plan_veranderd') {
        await proef(true)
        note = 'Het plan is intussen veranderd: hier is het nieuwe.'
      } else if (e instanceof ApiError && e.status === 409 && e.message === 'bezig') {
        error = 'Er loopt al iets: wacht tot het klaar is.'
      } else error = e.message
    } finally { busy = false }
  }

  function finished(r) {
    if (r.status === 'klaar') ondone?.()
  }
  function again() {
    f = blank()
    touched = false
    plan = null
    run = null
    error = ''
    note = ''
  }
  let link = $derived(run?.fqdn ? `${run.input?.cert === 'geen' ? 'http' : 'https'}://${run.fqdn}` : '')
</script>

{#if run}
  {#if run.status === 'klaar' && run.kind === 'maken' && run.todo?.length}
    <!-- Bv. een lokaal beheerde tunnel of geen AdGuard: de naam werkt pas als jij dit nog doet. -->
    <div class="todo">Klaar, nog zelf te doen:
      <ul>{#each run.todo as t, i (i)}<li>{t}</li>{/each}</ul>
    </div>
  {:else if run.status === 'klaar' && run.kind === 'maken'}
    <p class="done">Klaar: {run.fqdn} werkt. <a href={link} target="_blank" rel="noopener noreferrer">{link}</a></p>
  {/if}
  {#key run.id}
    <RunSteps {run} undo={run.kind === 'maken'} onfinish={(r) => { run = r; finished(r) }} onundo={(r) => (run = r)} />
  {/key}
  {#if run.status !== 'bezig'}
    <div class="btns">
      <button class="mini" onclick={again}>nog een service</button>
      <button class="mini" onclick={onclose}>sluiten</button>
    </div>
  {/if}
{:else}
  {#if !opties}<p class="hint small">Systemen nakijken…</p>{/if}
  {#if opties}
    <p class="sys">
      NPM: {sys.npm ? `${sys.npm.label}${sys.npm.split ? ` (schrijft als ${sys.npm.write})` : ''}` : 'geen'}
      · Cloudflare DNS: {sys.cloudflare ? sys.cloudflare.zone || '?' : 'geen'}
      · AdGuard: {sys.adguard ? sys.adguard.label : 'geen'}
      · Proxmox: {sys.proxmox?.length ? sys.proxmox.map((p) => p.label).join(', ') : 'geen'}
      {#if opties.npm_version}· NPM {opties.npm_version}{/if}
    </p>
    {#each opties.notes || [] as n, i (i)}<p class="hint small w">{n}</p>{/each}
  {/if}

  <div class="grid">
    <label class="full">Naam
      <span class="suffix">
        <input id="ns-name" bind:value={f.name} placeholder="jellyfin" autocomplete="off" spellcheck="false" />
        <span class="sfx">.{domain || '?'}</span>
      </span>
    </label>
    {#if opties && !domain}
      <p class="hint small full">Nog geen domein: maak in API-beheer een API van soort cloudflare (Cloudflare DNS) met je
        zone, of een wildcardcertificaat in NPM.</p>
    {/if}
    <div class="full backend">
      <label>IP-adres<input id="ns-ip" bind:value={f.ip} placeholder="192.168.0.27" inputmode="decimal" autocomplete="off" /></label>
      <label>Poort<input id="ns-port" bind:value={f.port} placeholder="8096" inputmode="numeric" autocomplete="off" /></label>
      <label>Protocol<select id="ns-scheme" bind:value={f.scheme}><option value="http">http</option><option value="https">https</option></select></label>
    </div>

    <div class="full">
      <span class="cap">Bereikbaar</span>
      <div class="btns">
        <label class="chk"><input id="ns-pub" type="radio" name="ns-exp" value="publiek" checked={f.exposure === 'publiek'}
               disabled={noCf} onchange={() => setExposure('publiek')} /> via internet</label>
        <label class="chk"><input id="ns-lan" type="radio" name="ns-exp" value="lan" checked={f.exposure === 'lan'}
               onchange={() => setExposure('lan')} /> alleen thuis</label>
      </div>
      {#if noCf}<p class="hint small">Via internet vraagt een Cloudflare DNS-API in API-beheer.</p>{/if}
    </div>

    <label>Certificaat
      <select id="ns-cert" bind:value={f.cert}>
        <option value="auto">automatisch</option>
        <option value="letsencrypt">Let's Encrypt voor deze naam</option>
        <option value="geen">geen (alleen http)</option>
      </select>
    </label>
    <label>Toegangslijst in NPM
      <select id="ns-acl" bind:value={f.acl}>
        <option value="">geen</option>
        {#each opties?.access_lists || [] as a (a.id)}
          <option value={String(a.id)}>{a.name}{a.lan_only ? ' (alleen thuis)' : ''}</option>
        {/each}
      </select>
    </label>
    {#if f.exposure === 'lan' && !f.acl && opties?.pattern !== 'tunnel'}
      <label class="chk full"><input id="ns-443" type="checkbox" bind:checked={f.p443} /> Poort 443 van NPM staat zeker
        niet open naar internet</label>
    {/if}
    {#if f.exposure === 'publiek' && opties?.protected_hosts?.length}
      <label class="full">zelfde bescherming als
        <select id="ns-protect" bind:value={f.protect}>
          <option value="">—</option>
          {#each opties.protected_hosts as h (h.id)}<option value={String(h.id)}>{h.name}</option>{/each}
        </select>
      </label>
    {/if}
    <label class="chk full"><input id="ns-ws" type="checkbox" bind:checked={f.ws} /> WebSockets doorlaten</label>

    <label class="chk full"><input id="ns-tile" type="checkbox" bind:checked={f.tile} disabled={!groups.length} /> tegel maken in</label>
    {#if f.tile && groups.length}
      <label>Groep
        <select id="ns-group" bind:value={f.group}>
          {#each groups as g (g.id)}<option value={g.id}>{g.label}</option>{/each}
        </select>
      </label>
      <label>naam van de tegel<input id="ns-label" bind:value={f.label} placeholder={cap(f.name.trim()) || 'Jellyfin'} /></label>
      <label>Zabbix-host
        <select id="ns-zbx" bind:value={f.zbx}>
          <option value="">automatisch</option>
          <option value="-">geen</option>
          {#each opties?.zabbix_hosts || [] as h (h.host)}
            <option value={h.host}>{h.name}{h.ips?.includes(f.ip.trim()) ? ' (dit IP)' : ''}</option>
          {/each}
        </select>
      </label>
      <label class="chk"><input id="ns-check" type="checkbox" bind:checked={f.check} /> met check (elke minuut)</label>
    {:else if !groups.length}
      <p class="hint small full">Nog geen groep: maak eerst een pagina met een groep.</p>
    {/if}
    <label class="chk full"><input id="ns-backup" type="checkbox" bind:checked={f.backup} /> CT/VM mee in de back-up</label>
    {#if f.backup}
      <label>back-upjob
        <select id="ns-job" bind:value={f.job}>
          <option value="">automatisch</option>
          {#each pbsJobs as j (j.id)}<option value={j.id}>{j.label}</option>{/each}
        </select>
      </label>
    {/if}
  </div>

  {#if !plan}<p class="hint small">Eerst de proef, dan uitvoeren. De proef verandert niets.</p>{/if}
  {#if error}<p class="err">{error}</p>{/if}
  {#if note}<p class="hint small w">{note}</p>{/if}
  {#if plan && changed}<p class="hint small w">Gewijzigd na de proef: doe de proef opnieuw.</p>{/if}
  <div class="btns">
    <button class="mini" disabled={busy} onclick={() => proef()}>proef</button>
    {#if plan?.kan && !changed}<button class="mini ok" disabled={busy} onclick={go}>uitvoeren</button>{/if}
  </div>
  {#if plan && !plan.kan && plan.waarom?.length}
    <div class="no">Kan niet:
      <ul>{#each plan.waarom as w, i (i)}<li>{w}</li>{/each}</ul>
    </div>
  {/if}
  {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}
{/if}

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-items: end }
  .grid label:not(.chk) { display: flex; flex-direction: column; gap: 3px; font-size: 11.5px; color: var(--muted); min-width: 0 }
  .full { grid-column: 1 / -1 }
  .backend { display: grid; grid-template-columns: minmax(0, 1fr) 5.5em 6em; gap: 8px }
  .suffix { display: flex; align-items: center; gap: 4px }
  .suffix input { min-width: 0; flex: 1 }
  .sfx { white-space: nowrap; color: var(--text); font-size: 13px }
  .cap { font-size: 11.5px; color: var(--muted) }
  .chk { line-height: 1.4; padding: 4px 0 }
  .btns { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 }
  .sys { color: var(--muted); font-size: 11.5px; margin: 0 0 8px; overflow-wrap: anywhere }
  .small { font-size: 12px; margin: 2px 0 }
  .done { margin: 4px 0; color: var(--ok); overflow-wrap: anywhere }
  .todo { margin: 4px 0; color: var(--mid); font-size: 12.5px; overflow-wrap: anywhere }
  .todo ul { margin: 2px 0; padding-left: 18px }
  .no { color: var(--err); font-size: 12.5px; margin: 6px 0 }
  .no ul { margin: 2px 0; padding-left: 18px }
  .w { color: var(--mid) }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr } }
</style>
