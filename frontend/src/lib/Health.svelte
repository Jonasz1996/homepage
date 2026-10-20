<script>
  import Cluster from './Cluster.svelte'
  import SecurityCheck from './SecurityCheck.svelte'
  import { onMount, untrack } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import { rel } from './cronfmt.js'
  import { bytes } from './format.js'

  // Gezondheid van de hardware en van de homepage zelf: schijven (SMART, ZFS), temperaturen en throttling,
  // vergeten snapshots, vervaldatum van domeinen, en of de worker, de back-up en de kopie buiten de container in orde zijn.
  let { open = false, initial = null, onclose, onfix } = $props()

  let data = $state(null)
  let error = $state('')
  let tab = $state('schijven')
  let now = $state(Date.now())
  let hours = $state(24)
  let temps = $state(null)
  let form = $state(null)
  let saving = $state(false)
  let note = $state('')
  let pass = $state('')
  let pass2 = $state('')
  let busy = $state('')

  async function load() {
    try {
      data = await api('/health')
      error = ''
      if (!form) form = JSON.parse(JSON.stringify(data.settings))
    } catch (e) { error = e.message }
  }
  async function loadTemps() {
    try { temps = await api(`/health/temps?hours=${hours}`) } catch (e) { error = e.message }
  }
  async function scan(what) {
    try {
      await api(`/health/scan/${what}`, { method: 'POST' })
      await load()
    } catch (e) { error = e.message }
  }

  $effect(() => { if (open) untrack(load) })
  $effect(() => { if (initial?.tab) untrack(() => (tab = initial.tab)) })
  $effect(() => { if (open && tab === 'temperatuur') { hours; untrack(loadTemps) } })

  onMount(() => {
    const a = poll(() => open && load(), 30000)
    const b = poll(() => open && data?.running?.length && load(), 3000)
    const c = poll(() => (now = Date.now()), 20000)
    return () => { a(); b(); c() }
  })

  // De klok van de browser kan iets achterlopen op die van de server: nooit "zo meteen" voor iets dat al gebeurde.
  const ago = (ts) => rel(ts, Math.max(now, Date.parse(ts)))
  const LEVEL = { ok: 'in orde', warn: 'opletten', err: 'probleem', unknown: 'onbekend' }
  const age = (h) => h == null ? '—' : h >= 8760 ? `${(h / 8760).toFixed(1)} jaar` : h >= 720 ? `${Math.round(h / 720)} maanden` : `${Math.round(h / 24)} dagen`
  const day = (s) => s ? new Date(s).toLocaleDateString('nl-BE', { day: 'numeric', month: 'short', year: 'numeric' }) : '—'
  let running = $derived(new Set(data?.running || []))
  let hosts = $derived(data?.hardware?.hosts || [])
  let snaps = $derived(data?.snapshots?.items || [])
  let oldSnaps = $derived(snaps.filter((s) => (s.age_days || 0) >= (data?.settings?.snapshot_days || 14)))
  let sc = $derived(data?.selfcheck || {})
  let s = $derived(data?.summary)

  async function delSnap(x) {
    if (!confirm(`Snapshot "${x.name}" van ${x.guest} (${x.vmid}) verwijderen? Dit kan niet ongedaan gemaakt worden.`)) return
    busy = `${x.vmid}/${x.name}`
    try {
      await withReauth(() => api('/health/snapshots/delete', { method: 'POST', body: { service_id: x.service_id, node: x.node, type: x.type, vmid: x.vmid, name: x.name } }))
      await load()
    } catch (e) { error = e.message } finally { busy = '' }
  }

  async function save() {
    saving = true
    note = ''
    try {
      const body = { ...form, domains: form.domains.filter((d) => d.name.trim()).map((d) => ({ name: d.name.trim(), expires: d.expires || null })) }
      form = await api('/health/settings', { method: 'PUT', body })
      note = 'bewaard'
      await load()
      if (body.domains.length) scan('domains')
    } catch (e) { note = e.message } finally { saving = false }
  }

  async function setKey() {
    if (pass !== pass2) { note = 'de twee wachtzinnen verschillen'; return }
    try {
      await withReauth(() => api('/health/offsite-key', { method: 'PUT', body: { passphrase: pass } }))
      pass = pass2 = ''
      note = 'sleutel versleuteld; hij gaat mee bij de volgende kopie'
      await load()
      scan('selfcheck')
    } catch (e) { note = e.message }
  }

  // --- temperatuurgrafiek ---
  const W = 900, Hh = 220, PAD = 34
  const COLORS = ['#8fd6a4', '#a9c7ff', '#f0b46b', '#e58fb8', '#c7a9ff', '#7fd8d8', '#e6d27a', '#ff8f7a']
  let chart = $derived.by(() => {
    if (!temps?.series?.length) return null
    const names = Object.fromEntries(hosts.map((h) => [h.key, h.name]))
    const disks = Object.fromEntries(hosts.flatMap((h) => (h.disks || []).map((d) => [d.key, d.model || d.dev])))
    const lines = temps.series.map((x, i) => ({
      ...x, color: COLORS[i % COLORS.length],
      label: `${names[x.target] || x.target} · ${x.sensor === 'cpu' ? 'cpu' : disks[x.sensor.slice(5)] || 'schijf'}`,
    }))
    const all = lines.flatMap((l) => l.points)
    const t0 = Math.min(...all.map((p) => p[0])), t1 = Math.max(...all.map((p) => p[0]), t0 + 1)
    const lo = Math.floor(Math.min(...all.map((p) => p[1]), 30) / 10) * 10
    const hi = Math.ceil(Math.max(...all.map((p) => p[1]), (data?.settings?.cpu_warn || 85) + 5) / 10) * 10
    const x = (t) => PAD + (t - t0) / (t1 - t0) * (W - PAD - 8)
    const y = (v) => 8 + (hi - v) / (hi - lo) * (Hh - 30)
    const ticks = []
    for (let v = lo; v <= hi; v += 10) ticks.push(v)
    return { lines: lines.map((l) => ({ ...l, d: l.points.map((p, i) => `${i ? 'L' : 'M'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join('') })),
             ticks, y, t0, t1, warn: y(data?.settings?.cpu_warn || 85), dwarn: y(data?.settings?.disk_warn || 55) }
  })
  let hidden = $state(new Set())
</script>

<div class="ov" class:hidden={!open}>
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# smartctl --alles &amp;&amp; zpool status</span>
      <div class="right">
        <button class="mini x" onclick={onclose} aria-label="Gezondheid sluiten">✕</button>
      </div>
    </div>

    <div class="tabs">
      {#each [['schijven', 'schijven'], ['temperatuur', 'temperatuur'], ['snapshots', 'snapshots'], ['domeinen', 'domeinen'], ['cluster', 'cluster'], ['homepage', 'homepage zelf'], ['beveiliging', 'beveiliging']] as [k, label]}
        <button class="mini" class:on={tab === k} onclick={() => (tab = k)}>{label}
          {#if k === 'snapshots' && s?.old_snapshots}<b class="n w">{s.old_snapshots}</b>{/if}
          {#if k === 'domeinen' && s?.domains_soon}<b class="n w">{s.domains_soon}</b>{/if}
          {#if k === 'cluster' && s?.cluster?.err + s?.cluster?.warn}<b class="n" class:e={s.cluster.err} class:w={!s.cluster.err}>{s.cluster.err + s.cluster.warn}</b>{/if}
          {#if k === 'homepage' && s?.problems?.length}<b class="n e">{s.problems.length}</b>{/if}
        </button>
      {/each}
    </div>

    {#if error}<p class="err pad">{error}</p>{/if}

    <div class="body">
    {#if tab === 'schijven'}
      <div class="head">
        <span class="hint">Elke 10 minuten via SSH (als root) op elke fysieke machine. Slapende harde schijven worden niet gewekt.</span>
        <span class="when">{running.has('hardware') ? 'bezig…' : data?.hardware?.checked_at ? `bekeken ${ago(data.hardware.checked_at)}` : 'nog niet bekeken'}</span>
        <button class="mini" disabled={running.has('hardware')} onclick={() => scan('hardware')}>⟳ nu</button>
      </div>
      {#if data && !hosts.length}
        <p class="hint pad">Nog geen machines. De gezondheid gebruikt de SSH-hosts uit de terminal (⟳ pve) met hun standaard login;
          open elke node één keer om de hostsleutel te bevestigen. Containers en VM's worden overgeslagen.</p>
      {/if}
      <div class="grid">
        {#each hosts as h (h.key)}
          <div class="host lv-{h.level}">
            <div class="hh">
              <b>{h.name}</b>
              <small>{h.model || h.host}</small>
              <span class="right">
                {#if h.cpu_temp != null}<span class="t" class:hot={h.cpu_temp >= data.settings.cpu_warn}>cpu {h.cpu_temp.toFixed(0)} °C</span>{/if}
                <span class="pill lv-{h.level}">{h.error ? 'niet bereikbaar' : LEVEL[h.level]}</span>
              </span>
            </div>
            {#if h.error}<p class="e small">{h.error}</p>{/if}
            {#if h.throttle?.now?.length}<p class="w small">⚡ nu: {h.throttle.now.join(', ')} — een Pi 5 wil een voeding van 5 V / 5 A.</p>
            {:else if h.throttle?.since_boot?.length}<p class="dim small">sinds opstarten: {h.throttle.since_boot.join(', ')}</p>{/if}
            {#if !h.error && h.smartctl === false}<p class="dim small">smartctl ontbreekt: <code>apt install smartmontools</code></p>{/if}
            {#each h.disks || [] as d (d.key)}
              <div class="disk">
                <i class="dot lv-{d.standby && !d.why?.length ? 'sleep' : d.level}" title={d.standby ? 'slaapt' : LEVEL[d.level]}></i>
                <span class="dn"><b>{d.model || d.dev}</b><small>{d.dev} · {d.ssd ? (d.protocol === 'NVMe' ? 'NVMe' : 'SSD') : d.ssd === false ? 'HDD' : '?'} · {bytes(d.size)}{d.serial ? ` · ${d.serial}` : ''}</small></span>
                <span class="dv">
                  {#if d.temp != null}<span class:hot={d.temp >= data.settings.disk_warn}>{d.temp} °C</span>{/if}
                  {#if d.wear_used != null}<span title="Versleten volgens de schijf zelf">{d.wear_used}% versleten</span>{/if}
                  {#if d.hours != null}<span title="Uren in gebruik">{age(d.hours)}</span>{/if}
                  {#if d.standby}<span class="dim">slaapt</span>{/if}
                </span>
                {#if d.why?.length}<span class="why lv-{d.level}">{d.why.join(' · ')}</span>{/if}
              </div>
            {/each}
            {#each h.pools || [] as p (p.name)}
              <div class="disk pool">
                <i class="dot lv-{p.level}"></i>
                <span class="dn"><b>zfs {p.name}</b><small>{p.health} · {p.cap}% vol · frag {p.frag}%</small></span>
                <span class="dv"><span>{p.scrubbing ? 'scrub bezig' : p.scrub_at ? `scrub ${day(p.scrub_at)}` : 'nooit gescrubd'}</span></span>
                {#if p.why?.length}<span class="why lv-{p.level}">{p.why.join(' · ')}</span>{/if}
              </div>
            {/each}
          </div>
        {/each}
      </div>

    {:else if tab === 'temperatuur'}
      <div class="head">
        {#each [[6, '6 u'], [24, '24 u'], [168, '7 d'], [720, '30 d']] as [h, label]}
          <button class="mini" class:on={hours === h} onclick={() => (hours = h)}>{label}</button>
        {/each}
        <span class="hint">streepjeslijnen: grens processor {data?.settings?.cpu_warn} °C (rood) en schijf {data?.settings?.disk_warn} °C (oranje), instelbaar bij domeinen. Klik een lijn in de legende om ze te verbergen.</span>
      </div>
      {#if chart}
        <svg class="chart" viewBox="0 0 {W} {Hh}" preserveAspectRatio="none" role="img" aria-label="Temperaturen">
          {#each chart.ticks as v}
            <line x1={PAD} x2={W - 8} y1={chart.y(v)} y2={chart.y(v)} class="grid-l" />
            <text x={PAD - 6} y={chart.y(v) + 4} class="ax">{v}°</text>
          {/each}
          <line x1={PAD} x2={W - 8} y1={chart.warn} y2={chart.warn} class="lim" />
          <line x1={PAD} x2={W - 8} y1={chart.dwarn} y2={chart.dwarn} class="lim d" />
          {#each chart.lines as l (l.target + l.sensor)}
            {#if !hidden.has(l.target + l.sensor)}<path d={l.d} stroke={l.color} class="ln" />{/if}
          {/each}
        </svg>
        <div class="legend">
          {#each chart.lines as l (l.target + l.sensor)}
            {@const k = l.target + l.sensor}
            <button class="lg" class:off={hidden.has(k)} onclick={() => { const n = new Set(hidden); n.has(k) ? n.delete(k) : n.add(k); hidden = n }}>
              <i style="background:{l.color}"></i>{l.label} <b>{l.points.at(-1)[1].toFixed(0)}°</b>
            </button>
          {/each}
        </div>
      {:else}
        <p class="hint pad">{temps ? 'Nog geen metingen in deze periode.' : 'laden…'}</p>
      {/if}

    {:else if tab === 'snapshots'}
      <div class="head">
        <span class="hint">Snapshots houden oude blokken vast; vergeten exemplaren laten de opslag stilletjes vollopen.
          Ouder dan {data?.settings?.snapshot_days} dagen = vergeten. Verwijderen vraagt VM.Snapshot op het Proxmox-token.</span>
        <span class="when">{running.has('snapshots') ? 'bezig…' : data?.snapshots?.checked_at ? `bekeken ${ago(data.snapshots.checked_at)}` : 'nog niet bekeken'}</span>
        <button class="mini" disabled={running.has('snapshots')} onclick={() => scan('snapshots')}>⟳ nu</button>
      </div>
      {#each data?.snapshots?.errors || [] as e}<p class="e small pad">{e.service}{e.guest ? ` · ${e.guest}` : ''}: {e.error}</p>{/each}
      <table class="tbl">
        <thead><tr><th>vm/ct</th><th>snapshot</th><th>gemaakt</th><th>leeftijd</th><th>node</th><th></th></tr></thead>
        <tbody>
          {#each snaps as x (x.node + x.vmid + x.name)}
            <tr class:old={(x.age_days || 0) >= data.settings.snapshot_days}>
              <td><b>{x.guest}</b> <small>{x.type === 'qemu' ? 'VM' : 'CT'} {x.vmid}</small></td>
              <td>{x.name}{#if x.vmstate}<small class="dim"> + RAM</small>{/if}{#if x.description}<small class="dim block">{x.description}</small>{/if}</td>
              <td>{x.snaptime ? day(x.snaptime * 1000) : '—'}</td>
              <td class="num">{x.age_days != null ? `${Math.floor(x.age_days)} d` : '—'}</td>
              <td>{x.node}</td>
              <td><button class="mini danger" disabled={busy === `${x.vmid}/${x.name}`} onclick={() => delSnap(x)}>verwijderen</button></td>
            </tr>
          {:else}
            <tr><td colspan="6" class="hint">{data?.snapshots?.checked_at ? 'Geen snapshots. Netjes.' : 'Nog niet bekeken (heeft een Proxmox-tegel met API-token nodig).'}</td></tr>
          {/each}
        </tbody>
      </table>
      {#if oldSnaps.length}<p class="hint pad">{oldSnaps.length} vergeten snapshot{oldSnaps.length === 1 ? '' : 's'}.</p>{/if}

    {:else if tab === 'domeinen'}
      <div class="head">
        <span class="hint">Vervaldatum, registrar en nameservers via RDAP, elke dag. Meldingen 30, 7 en 1 dag op voorhand, en als
          de nameservers veranderen. DNS Belgium (.be) geeft geen vervaldatum: vul die dan zelf in.</span>
        <span class="when">{running.has('domains') ? 'bezig…' : data?.domains?.checked_at ? `bekeken ${ago(data.domains.checked_at)}` : ''}</span>
        <button class="mini" disabled={running.has('domains') || !data?.settings?.domains?.length} onclick={() => scan('domains')}>⟳ nu</button>
      </div>
      <table class="tbl">
        <thead><tr><th>domein</th><th>verloopt</th><th>registrar</th><th>nameservers</th></tr></thead>
        <tbody>
          {#each data?.domains?.items || [] as d (d.name)}
            <tr>
              <td><b>{d.name}</b>{#if d.error}<small class="e block">{d.error}</small>{/if}</td>
              <td class:e={d.days_left != null && d.days_left <= 7} class:w={d.days_left != null && d.days_left > 7 && d.days_left <= 30}>
                {d.expires ? `${day(d.expires)} (${d.days_left} d)` : '—'}{#if d.source === 'manueel'}<small class="dim"> · zelf ingevuld</small>{/if}</td>
              <td>{d.registrar || '—'}</td>
              <td><small>{(d.nameservers || []).join(', ') || '—'}</small></td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if form}
        <div class="form">
          <span class="lbl">domeinen</span>
          {#each form.domains as d, i}
            <div class="row">
              <input bind:value={d.name} placeholder="jbogaert.be" />
              <input type="date" bind:value={d.expires} title="Alleen als RDAP geen vervaldatum geeft" />
              <button class="mini" onclick={() => form.domains.splice(i, 1)} aria-label="Domein weghalen">✕</button>
            </div>
          {/each}
          <button class="mini" onclick={() => form.domains.push({ name: '', expires: null })}>+ domein</button>
          <span class="lbl">grenzen</span>
          <div class="row">
            <label>processor °C <input type="number" min="40" max="110" bind:value={form.cpu_warn} /></label>
            <label>schijf °C <input type="number" min="30" max="80" bind:value={form.disk_warn} /></label>
            <label>snapshot vergeten na (dagen) <input type="number" min="1" max="365" bind:value={form.snapshot_days} /></label>
          </div>
          <div class="row"><button class="btn" disabled={saving} onclick={save}>bewaren</button><span class="note">{note}</span></div>
        </div>
      {/if}

    {:else if tab === 'cluster'}
      <Cluster />
    {:else if tab === 'beveiliging'}
      <SecurityCheck onfix={(fix) => (fix.window === 'health' ? (tab = fix.tab) : onfix?.(fix))} />
    {:else}
      <div class="head">
        <span class="hint">Leeft de worker, is er een recente en leesbare back-up, en staat er een kopie buiten de container?</span>
        <span class="when">{running.has('selfcheck') ? 'bezig…' : sc.checked_at ? `bekeken ${ago(sc.checked_at)}` : ''}</span>
        <button class="mini" disabled={running.has('selfcheck')} onclick={() => scan('selfcheck')}>⟳ nu</button>
      </div>
      <div class="grid">
        <div class="host lv-{data?.worker?.ok ? 'ok' : 'err'}">
          <div class="hh"><b>worker</b><span class="right"><span class="pill lv-{data?.worker?.ok ? 'ok' : 'err'}">{data?.worker?.ok ? 'draait' : 'draait niet'}</span></span></div>
          <p class="small">{data?.worker?.ok ? `gestart ${ago(data.worker.started)}, laatste teken van leven ${ago(data.worker.at)}` : data?.worker?.why}</p>
          {#if !data?.worker?.ok}<p class="dim small">Op de container: <code>systemctl status homepage-worker</code></p>{/if}
        </div>
        <div class="host lv-{!sc.checked_at ? 'unknown' : sc.stale || sc.verified?.ok === false ? 'err' : 'ok'}">
          <div class="hh"><b>back-up</b><small>{sc.backup_dir}</small>
            {#if sc.checked_at}<span class="right"><span class="pill lv-{sc.stale ? 'err' : 'ok'}">{sc.stale ? 'te oud' : 'recent'}</span></span>{/if}</div>
          {#if !sc.checked_at}<p class="dim small">nog niet bekeken</p>{/if}
          {#if sc.verified?.name}
            <p class="small">{sc.verified.name}: {sc.verified.ok ? `leesbaar (${sc.verified.why})` : sc.verified.ok === false ? `onleesbaar — ${sc.verified.why}` : `niet nagekeken (${sc.verified.why})`}</p>
          {/if}
          {#each (sc.backups || []).slice(0, 5) as b}<p class="dim small">{b.name} · {bytes(b.size)} · {ago(b.at)}</p>{/each}
          {#if sc.checked_at && !(sc.backups || []).length}<p class="small e">Geen dumps gevonden. Elke nacht om 03:30 maakt homepage-backup.timer er één.</p>{/if}
        </div>
        <div class="host lv-ok">
          <div class="hh"><b>database</b><span class="right">{bytes(sc.db?.total)}</span></div>
          {#each sc.db?.tables || [] as t}<p class="dim small row2"><span>{t.name}</span><span>{bytes(t.size)}</span></p>{/each}
          {#each sc.disks || [] as d}<p class="small row2" class:w={d.pct >= 90}><span>schijf {d.path}</span><span>{d.pct}% · {bytes(d.free)} vrij</span></p>{/each}
        </div>
        <div class="host wide lv-{!data?.settings?.offsite ? 'unknown' : sc.offsite?.error ? 'warn' : 'ok'}">
          <div class="hh"><b>kopie buiten de container</b><small>{data?.offsite_dir}</small></div>
          {#if form}
            <label class="chk"><input type="checkbox" bind:checked={form.offsite} onchange={save} /> elk uur de nieuwste dumps en de versleutelde sleutel kopiëren</label>
          {/if}
          {#if data?.settings?.offsite}
            {#if sc.offsite?.error}<p class="small w">{sc.offsite.error}</p>{/if}
            {#if sc.offsite?.latest}<p class="small">{sc.offsite.count} dump{sc.offsite.count === 1 ? '' : 's'} daar, nieuwste {sc.offsite.latest.name}{sc.offsite.key ? ' · sleutel ✓' : ''}</p>{/if}
          {/if}
          <p class="dim small">Koppel een NAS-share, PBS-opslag of USB-schijf op {data?.offsite_dir} (bv. <code>pct set &lt;id&gt; -mp0 /mnt/nas/homepage,mp={data?.offsite_dir}</code>) en geef gebruiker homepage schrijfrechten. Zonder secret.key zijn de wachtwoorden en API-sleutels in een back-up onleesbaar; daarom gaat hij mee, versleuteld met een wachtzin die nergens bewaard wordt.</p>
          <p class="small">{data?.offsite_key?.set ? `wachtzin ingesteld ${ago(data.offsite_key.at)}` : 'nog geen wachtzin'}</p>
          <div class="row">
            <input type="password" bind:value={pass} placeholder="wachtzin (min. 12 tekens)" autocomplete="new-password" />
            <input type="password" bind:value={pass2} placeholder="nog eens" autocomplete="new-password" />
            <button class="mini" disabled={pass.length < 12} onclick={setKey}>{data?.offsite_key?.set ? 'wijzigen' : 'instellen'}</button>
          </div>
          {#if note}<p class="small note">{note}</p>{/if}
        </div>
      </div>
    {/if}
    </div>
  </div>
</div>

<style>
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .tabs { display: flex; gap: 6px; align-items: center; padding: 10px 12px 0; flex-wrap: wrap }
  .n { margin-left: 5px; font-weight: 500 }
  .body { flex: 1; overflow: auto; padding: 4px 12px 24px; margin-top: 8px; border-top: 1px solid var(--line) }
  .head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding: 10px 0 }
  .head .hint { flex: 1; min-width: 240px; font-size: 12px; margin: 0 }
  .when { color: var(--dim); font-size: 12px }
  .pad { padding: 0 2px }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(420px, 100%), 1fr)); gap: 12px }
  .host { border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; background: var(--fill); border-left: 3px solid var(--line-2) }
  .host.wide { grid-column: span 2 }
  .host.lv-ok { border-left-color: var(--ok) }
  .host.lv-warn { border-left-color: var(--mid) }
  .host.lv-err { border-left-color: var(--err) }
  .hh { display: flex; gap: 8px; align-items: baseline; margin-bottom: 6px }
  .hh b { color: var(--text-h); font-weight: 500 }
  .hh small { color: var(--muted); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .hh .right { margin-left: auto; display: flex; gap: 8px; align-items: baseline; font-size: 12px; white-space: nowrap }
  .pill { font-size: 11px; padding: 1px 8px; border-radius: 8px; background: var(--fill-h); color: var(--muted) }
  .pill.lv-ok { color: var(--ok) }
  .pill.lv-warn { color: var(--mid) }
  .pill.lv-err { color: var(--err) }
  .t { color: var(--muted) }
  .hot { color: var(--err) !important }
  .disk { display: grid; grid-template-columns: 10px minmax(0, 1fr) auto; gap: 4px 10px; align-items: center; padding: 5px 0; border-top: 1px solid var(--line) }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim) }
  .dot.lv-ok { background: var(--ok) }
  .dot.lv-warn { background: var(--mid) }
  .dot.lv-err { background: var(--err) }
  .dot.lv-sleep { background: #5f7f68 }
  .dn { min-width: 0; display: flex; flex-direction: column }
  .dn b { font-weight: 500; font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .dn small { color: var(--dim); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .dv { display: flex; gap: 10px; font-size: 12px; color: var(--muted); white-space: nowrap }
  .why { grid-column: 2 / -1; font-size: 11.5px }
  .why.lv-warn, .w { color: var(--mid) }
  .why.lv-err, .e { color: var(--err) }
  .why.lv-unknown, .dim { color: var(--dim) }
  .small { font-size: 12px; margin: 3px 0 }
  .block { display: block }
  .row2 { display: flex; justify-content: space-between; gap: 10px }
  code { font-size: 11.5px }
  .chart { width: 100%; height: 260px; display: block }
  .grid-l { stroke: var(--line); stroke-width: 1 }
  .lim { stroke: var(--err); stroke-dasharray: 4 4; opacity: .55 }
  .lim.d { stroke: var(--mid) }
  .ax { fill: var(--dim); font-size: 10px; text-anchor: end }
  .ln { fill: none; stroke-width: 1.6; vector-effect: non-scaling-stroke }
  .legend { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px }
  .lg { display: flex; gap: 6px; align-items: center; background: none; border: 1px solid var(--line); border-radius: 8px; padding: 2px 8px; color: var(--text); font: inherit; font-size: 12px; cursor: pointer }
  .lg i { width: 10px; height: 3px; border-radius: 2px }
  .lg b { font-weight: 500; color: var(--text-h) }
  .lg.off { opacity: .4 }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .tbl th { text-align: left; font-weight: 400; color: var(--muted); font-size: 11.5px; padding: 6px 8px; border-bottom: 1px solid var(--line) }
  .tbl td { padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top }
  .tbl td b { font-weight: 500; color: var(--text-h) }
  .tbl small { color: var(--muted) }
  .tbl tr.old td:nth-child(4) { color: var(--mid) }
  .num { text-align: right; white-space: nowrap }
  .danger { color: var(--err) }
  .form { margin-top: 18px; display: flex; flex-direction: column; gap: 8px; max-width: 720px }
  .lbl { font-size: 11.5px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-top: 6px }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap }
  .row input { flex: 1; min-width: 140px }
  .row label { display: flex; flex-direction: column; gap: 3px; font-size: 12px; color: var(--muted) }
  .row label input { width: 120px; flex: none }
  .note { font-size: 12px; color: var(--muted) }
  .chk { display: flex; gap: 6px; align-items: center; font-size: 12.5px; margin: 4px 0 }
  @media (max-width: 700px) {
    .grid { grid-template-columns: 1fr }
    .host.wide { grid-column: auto }
    .hh { flex-wrap: wrap }
    .hh .right { margin-left: 0 }
    .dv { grid-column: 2 / -1; flex-wrap: wrap; white-space: normal }
    .ov { padding: 0 }
    .tbl th:nth-child(3), .tbl td:nth-child(3), .tbl th:nth-child(5), .tbl td:nth-child(5) { display: none }
  }
</style>
