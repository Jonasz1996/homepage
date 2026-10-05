<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'

  // Clusterstatus van Proxmox: quorum, nodes, HA-resources en replicatie.
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
  const HA = { started: 'g', stopped: '', ignored: '', disabled: '', request_stop: 'w', migrate: 'w', relocate: 'w',
               error: 'e', fence: 'e', freeze: 'w', recovery: 'e' }
</script>

<div class="head">
  <span class="hint">Quorum, welke nodes corosync ziet, HA-resources en replicatie, elke 2 minuten via de Proxmox-API.
    Een melding als de cluster zijn quorum verliest, een node wegvalt, een HA-resource in error staat of een replicatie mislukt.</span>
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
            <span class="node" class:off={!n.online} title={n.ip || ''}><i class="dot" class:on={n.online}></i>{n.name}</span>
          {/each}
        </div>
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
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--err) }
  .dot.on { background: var(--ok) }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12px }
  .tbl td { padding: 4px 6px; border-top: 1px solid var(--line) }
  .g { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .small { font-size: 11.5px; margin: 2px 0 }
</style>
