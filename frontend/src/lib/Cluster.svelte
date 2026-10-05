<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import CopyCmd from './CopyCmd.svelte'

  // Clusterstatus van Proxmox: quorum, nodes, Proxmox-versie per node, stemmen en QDevice, HA-resources en replicatie.
  let data = $state(null)
  let error = $state('')
  let busy = $state(false)

  async function load() {
    try { data = await api('/cluster'); error = '' } catch (e) { error = e.message }
  }
  onMount(load)

  async function refresh() {
    busy = true
    try {
      await api('/cluster/refresh', { method: 'POST' })
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 1500))
        await load()
        if (!data?.running) break
      }
    } catch (e) { error = e.message } finally { busy = false }
  }

  const ago = (ts) => {
    if (!ts) return ''
    const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
    return m < 60 ? `${Math.max(m, 0)} min geleden` : `${Math.floor(m / 60)} u geleden`
  }
  const sync = (t) => (t ? new Date(t * 1000).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '—')
  const release = (v) => (v || '').split('.').slice(0, 2).join('.')
  // Welke releases (8.2, 8.3) afwijken van wat de meeste nodes draaien.
  function odd(c) {
    const n = {}
    for (const x of c.nodes) if (x.version) n[release(x.version)] = (n[release(x.version)] || 0) + 1
    const keys = Object.keys(n)
    if (keys.length < 2) return new Set()
    const most = keys.sort((a, b) => n[b] - n[a])[0]
    return new Set(keys.filter((k) => k !== most))
  }
  function votes(c) {
    const nodes = c.nodes.reduce((t, n) => t + (n.votes || 1), 0)
    const total = nodes + (c.qdevice?.state ? 1 : 0)
    return { nodes, total, quorum: Math.floor(total / 2) + 1 }
  }
  // Waar corosync-qnetd komt: bij voorkeur de PBS op de Pi (draait altijd, staat los van de cluster).
  let qhost = $state('')
  $effect(() => {
    if (!qhost && data?.qnetd?.length) qhost = (data.qnetd.find((q) => /pi/i.test(q.name)) || data.qnetd[0]).host
  })
  const HA = { started: 'g', stopped: '', ignored: '', disabled: '', request_stop: 'w', migrate: 'w', relocate: 'w',
               error: 'e', fence: 'e', freeze: 'w', recovery: 'e' }
</script>

<div class="head">
  <span class="hint">Quorum, welke nodes corosync ziet, de Proxmox-versie per node, de stemmen, HA-resources en replicatie,
    elke 2 minuten via de Proxmox-API. Een melding als de cluster zijn quorum verliest, een node wegvalt, nodes een andere
    Proxmox-versie draaien, de QDevice wegvalt, een HA-resource in error staat of een replicatie mislukt.</span>
  <span class="when">{busy ? 'bezig…' : data?.at ? `bekeken ${ago(data.at)}` : ''}</span>
  <button class="mini" disabled={busy} onclick={refresh}>⟳ nu</button>
</div>
{#if error}<p class="err">{error}</p>{/if}
{#if data && !data.items.length}
  <p class="hint">Nog geen gegevens. Daarvoor is een tegel van type <b>proxmox</b> nodig; het token heeft genoeg aan de rol
    PVEAuditor (Sys.Audit).</p>
{/if}
<div class="grid">
  {#each data?.items || [] as c (c.service_id)}
    <div class="host" class:lv-err={c.quorate === false || c.error} class:lv-ok={c.quorate}>
      <div class="hh">
        <b>{c.cluster ? `cluster ${c.cluster}` : c.service}</b>
        {#if c.cluster}<small>via {c.service}</small>{/if}
        <span class="right">
          {#if c.error}<span class="pill lv-err">niet bereikbaar</span>
          {:else if !c.cluster}<span class="pill">geen cluster (losse node)</span>
          {:else if c.quorate}<span class="pill lv-ok">quorum</span>
          {:else}<span class="pill lv-err">geen quorum</span>{/if}
        </span>
      </div>
      {#if c.error}<p class="e small">{c.error}</p>{/if}
      {#if c.nodes.length}
        <div class="nodes">
          {#each c.nodes as n (n.name)}
            <span class="node" class:off={!n.online} class:odd={odd(c).has(release(n.version))}
                  title={[n.ip, n.version && `Proxmox ${n.version}`].filter(Boolean).join(' · ')}>
              <i class="dot" class:on={n.online}></i>{n.name}{#if n.version}<small>{n.version}</small>{/if}
            </span>
          {/each}
        </div>
        {#if odd(c).size}<p class="w small">Niet alle nodes draaien dezelfde Proxmox-versie. Breng ze via apt op gelijke
          hoogte; een cluster met gemengde versies kan bij migratie of HA rare fouten geven.</p>{/if}
      {/if}
      {#if c.cluster && c.qdevice !== undefined && c.qdevice !== null}
        {@const v = votes(c)}
        <div class="votes">
          <span class="lbl">Stemmen</span>
          <span>{v.total} stemmen, quorum bij {v.quorum}</span>
          {#if c.qdevice.state}
            <span class="pill" class:lv-ok={c.qdevice.state.toLowerCase() === 'connected'}
                  class:lv-err={c.qdevice.state.toLowerCase() !== 'connected'}>QDevice {c.qdevice.host || ''}: {c.qdevice.state}</span>
          {:else if v.nodes % 2 === 0}
            <span class="pill w">geen QDevice</span>
          {:else}
            <span class="pill">oneven, geen QDevice nodig</span>
          {/if}
        </div>
        {#if !c.qdevice.state && v.nodes % 2 === 0}
          <details class="qd">
            <summary>Waarom een QDevice, en hoe</summary>
            <p>Met {v.nodes} stemmen heeft de cluster er {v.quorum} nodig. Vallen er {v.nodes / 2} nodes uit (bijvoorbeeld een
              HP die 's nachts uit staat en een tweede die herstart voor een update), dan stopt de hele cluster: geen VM
              starten, geen back-up, geen instelling wijzigen. Een QDevice is een kleine dienst op een machine buiten de
              cluster die één extra stem geeft, zodat het totaal oneven wordt.</p>
            <p>De PBS op de Pi is daar ideaal voor: die draait altijd en is geen lid van de cluster. Neem niet de PBS-VM,
              want die draait op de cluster zelf.</p>
            {#if data.qnetd?.length > 1}
              <label class="pick">Machine voor de QDevice
                <select bind:value={qhost}>{#each data.qnetd as q (q.host)}<option value={q.host}>{q.name} ({q.host})</option>{/each}</select>
              </label>
            {/if}
            <ol>
              <li>Op {data.qnetd?.find((q) => q.host === qhost)?.name || 'de Pi'}: <CopyCmd cmd="apt install -y corosync-qnetd" /></li>
              <li>Op elke node van de cluster ({c.nodes.map((n) => n.name).join(', ')}): <CopyCmd cmd="apt install -y corosync-qdevice" /></li>
              <li>Op één node. Het vraagt eenmalig het root-wachtwoord van de Pi, dus root moet daar via SSH met een wachtwoord
                mogen inloggen (PermitRootLogin yes, achteraf mag dat weer uit):
                <CopyCmd cmd={`pvecm qdevice setup ${qhost || '<IP van de Pi>'}`} /></li>
              <li>Controle: <CopyCmd cmd="pvecm status" /> toont dan een regel Qdevice. Hier staat binnen 2 minuten
                "QDevice: Connected".</li>
            </ol>
          </details>
        {/if}
      {/if}
      {#if c.ha.length}
        <span class="lbl">HA</span>
        <table class="tbl">
          <tbody>
            {#each c.ha as h (h.sid)}
              <tr><td>{h.sid}</td><td class={HA[h.state] || ''}>{h.state}</td><td class="m">{h.node || ''}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
      {#if c.ha_error}<p class="m small">HA: {c.ha_error}</p>{/if}
      {#if c.replication.length}
        <span class="lbl">Replicatie</span>
        <table class="tbl">
          <tbody>
            {#each c.replication as r (`${r.node}/${r.id}`)}
              <tr>
                <td>{r.id}</td><td class="m">{r.node} → {r.target}</td><td class="m">{sync(r.last_sync)}</td>
                <td class:e={r.fail_count} class:g={!r.fail_count}>{r.fail_count ? `${r.fail_count}× mislukt` : 'ok'}</td>
              </tr>
              {#if r.error}<tr><td colspan="4" class="e small">{r.error}</td></tr>{/if}
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  {/each}
</div>

<style>
  .head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding: 10px 0 }
  .head .hint { flex: 1; min-width: 240px; font-size: 12px; margin: 0 }
  .when { color: var(--dim); font-size: 12px }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(420px, 100%), 1fr)); gap: 12px }
  .host { border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; background: var(--fill); border-left: 3px solid var(--line-2) }
  .host.lv-ok { border-left-color: var(--ok) }
  .host.lv-err { border-left-color: var(--err) }
  .hh { display: flex; gap: 8px; align-items: baseline; margin-bottom: 6px }
  .hh b { color: var(--text-h); font-weight: 500 }
  .hh small, .m { color: var(--muted); font-size: 11.5px }
  .right { margin-left: auto }
  .pill { font-size: 11px; padding: 1px 8px; border-radius: 8px; background: var(--fill-h); color: var(--muted) }
  .pill.lv-ok { color: var(--ok) }
  .pill.lv-err { color: var(--err) }
  .nodes { display: flex; flex-wrap: wrap; gap: 6px; margin: 4px 0 6px }
  .node { font-size: 12px; padding: 2px 8px; border-radius: 8px; border: 1px solid var(--line-2); display: flex; gap: 6px; align-items: center }
  .node.off { color: var(--err); border-color: rgba(255, 110, 110, .4) }
  .node small { color: var(--muted); font-size: 10.5px }
  .node.odd small { color: var(--mid) }
  .node.odd { border-color: var(--mid) }
  .votes { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-size: 12px; margin: 4px 0 }
  .votes .lbl { margin: 0 }
  .pill.w { color: var(--mid) }
  .qd { font-size: 12px; margin: 4px 0 8px; border: 1px dashed var(--line-2); border-radius: 8px; padding: 6px 10px }
  .qd summary { cursor: pointer; color: var(--mid) }
  .qd p { margin: 6px 0; line-height: 1.5 }
  .qd ol { margin: 6px 0; padding-left: 18px }
  .qd li { margin: 6px 0 }
  .pick { display: flex; gap: 8px; align-items: center; margin: 6px 0 }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--err) }
  .dot.on { background: var(--ok) }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12px }
  .tbl td { padding: 4px 6px; border-top: 1px solid var(--line) }
  .g { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .small { font-size: 11.5px; margin: 2px 0 }
</style>
