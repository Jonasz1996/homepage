<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'

  // Netwerkkaart: internet → OPNsense → Proxmox-nodes → CT/VM → services, met NPM ertussen.
  // Klik op een node, CT/VM, OPNsense of NPM en je ziet wat er allemaal mee uitvalt.
  let data = $state.raw(null)
  let error = $state('')
  let sel = $state(null) // { kind: 'node' | 'guest' | 'opnsense' | 'npm', id, name }

  async function load() {
    try { data = await api('/netmap'); error = '' } catch (e) { error = e.message }
  }
  onMount(() => { load(); return poll(load, 30000) })

  let services = $derived(data?.services || [])
  let onGuest = $derived.by(() => {
    const m = {}
    for (const s of services) if (s.guest) (m[s.guest] ||= []).push(s)
    return m
  })
  let onNode = $derived.by(() => {
    const m = {}
    for (const s of services) if (!s.guest && s.node) (m[s.node] ||= []).push(s)
    return m
  })
  let loose = $derived(services.filter((s) => !s.guest && !s.node))

  // Wat er uitvalt: de rechtstreeks getroffen services, plus alles wat daarop "draait" (parent), keten na keten.
  function withDependents(ids) {
    const out = new Set(ids)
    let grew = true
    while (grew) {
      grew = false
      for (const s of services) if (s.parent_id && out.has(s.parent_id) && !out.has(s.id)) { out.add(s.id); grew = true }
    }
    return out
  }
  let hit = $derived.by(() => {
    if (!sel || !data) return null
    let guests = []
    let direct = []
    if (sel.kind === 'opnsense') {
      guests = data.guests.map((g) => g.id)
      direct = services.map((s) => s.id)
    } else if (sel.kind === 'npm') {
      direct = services.filter((s) => s.via_npm).map((s) => s.id)
    } else if (sel.kind === 'node') {
      guests = data.guests.filter((g) => g.node === sel.id).map((g) => g.id)
      direct = services.filter((s) => s.node === sel.id).map((s) => s.id)
    } else if (sel.kind === 'guest') {
      guests = [sel.id]
      direct = services.filter((s) => s.guest === sel.id).map((s) => s.id)
    }
    const svc = withDependents(direct)
    return { guests: new Set(guests), services: svc, up: services.filter((s) => svc.has(s.id) && s.status === 'up').length }
  })
  const pick = (kind, id, name) => (sel = sel?.kind === kind && sel.id === id ? null : { kind, id, name })
  const dim = (on) => hit && !on
  const pctOf = (a, b) => (b ? Math.round((a / b) * 100) : null)
  const SVC = { up: 'up', down: 'down' }
  let opn = $derived(data?.opnsense?.[0])
  let npm = $derived(data?.npm?.[0])
</script>

{#if error}<p class="err">{error}</p>{/if}
{#if data}
  <p class="hint">Klik op een node, CT/VM, OPNsense of NPM: je ziet meteen wat er mee uitvalt. Services komen bij een
    CT/VM via "draait op", het IP (SSH-import van Proxmox), de NPM-host van hun domein of dezelfde naam.</p>
  {#each data.errors as e}<p class="e small">{e}</p>{/each}

  <div class="chain">
    <span class="box">🌐 internet</span>
    <i class="ln"></i>
    {#if opn}
      <button class="box {SVC[opn.status] || ''}" class:sel={sel?.kind === 'opnsense'} onclick={() => pick('opnsense', opn.id, opn.name)}>
        <i class="dot {SVC[opn.status] || ''}"></i>{opn.name}<small>firewall</small></button>
    {:else}<span class="box muted">router</span>{/if}
    <i class="ln"></i>
    {#if npm}
      <button class="box {SVC[npm.status] || ''}" class:sel={sel?.kind === 'npm'} onclick={() => pick('npm', npm.id, npm.name)}>
        <i class="dot {SVC[npm.status] || ''}"></i>{npm.name}<small>{data.npm_hosts} hosts</small></button>
    {/if}
  </div>

  {#if sel && hit}
    <div class="impact">
      <span><b>Valt {sel.name} uit</b>, dan gaan mee: {hit.guests.size} CT/VM en {hit.services.size} services
        ({hit.up} nu up).</span>
      <button class="mini" onclick={() => (sel = null)}>✕</button>
    </div>
  {/if}

  <div class="grid">
    {#each data.nodes as n (n.id)}
      {@const nodeHit = hit && sel?.kind === 'node' && sel.id === n.name}
      <div class="node" class:sel={nodeHit} class:dim={hit && !nodeHit && sel?.kind === 'node'}>
        <button class="nh" onclick={() => pick('node', n.name, n.name)}>
          <i class="dot" class:up={n.status === 'online'} class:down={n.status !== 'online'}></i>
          <b>{n.name}</b>
          <small>{n.status === 'online' ? `cpu ${Math.round((n.cpu || 0) * 100)}% · ram ${pctOf(n.mem, n.maxmem) ?? '—'}%` : 'offline'}</small>
        </button>
        {#if onNode[n.name]?.length}
          <div class="chips direct">
            {#each onNode[n.name] as s (s.id)}
              <span class="chip {SVC[s.status] || ''}" class:hit={hit?.services.has(s.id)} class:dim={dim(hit?.services.has(s.id))} title={s.how}>
                <i class="dot {SVC[s.status] || ''}"></i>{s.name}</span>
            {/each}
          </div>
        {/if}
        {#each data.guests.filter((g) => g.node === n.name) as g (g.id)}
          {@const on = hit?.guests.has(g.id)}
          <div class="guest" class:hit={on} class:dim={dim(on)}>
            <button class="gh" class:sel={sel?.kind === 'guest' && sel.id === g.id} onclick={() => pick('guest', g.id, `${g.name} (${g.vmid})`)}>
              <i class="dot" class:up={g.status === 'running'}></i>
              <span class="vm">{g.vmid}</span><span class="gn">{g.name}</span>
              <small>{g.type === 'qemu' ? 'VM' : 'CT'}{g.ip ? ` · ${g.ip}` : ''}{g.status !== 'running' ? ` · ${g.status}` : ''}</small>
            </button>
            {#if onGuest[g.id]?.length}
              <div class="chips">
                {#each onGuest[g.id] as s (s.id)}
                  <span class="chip {SVC[s.status] || ''}" class:hit={hit?.services.has(s.id)} title={s.how}>
                    <i class="dot {SVC[s.status] || ''}"></i>{s.name}{#if s.via_npm}<em title="via NPM">⇄</em>{/if}</span>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {:else}
      <p class="hint">Nog geen Proxmox-nodes: voeg een tegel van type <b>proxmox</b> toe.</p>
    {/each}
  </div>

  {#if loose.length}
    <div class="node loose">
      <span class="lbl">niet op de kaart ({loose.length})</span>
      <p class="hint small">Geen CT/VM gevonden. Zet "draait op" in de service, of importeer de CT's en VM's met ⟳ pve in de
        terminal zodat hun IP's gekend zijn.</p>
      <div class="chips">
        {#each loose as s (s.id)}
          <span class="chip {SVC[s.status] || ''}" class:hit={hit?.services.has(s.id)} class:dim={dim(hit?.services.has(s.id))}>
            <i class="dot {SVC[s.status] || ''}"></i>{s.name}{#if s.via_npm}<em title="via NPM">⇄</em>{/if}</span>
        {/each}
      </div>
    </div>
  {/if}
{:else if !error}
  <p class="hint">Laden…</p>
{/if}

<style>
  .chain { display: flex; align-items: center; flex-wrap: wrap; gap: 0; margin: 8px 0 12px }
  .box { all: unset; cursor: pointer; display: inline-flex; gap: 6px; align-items: center; padding: 6px 12px; border-radius: 10px;
         border: 1px solid var(--line-2); background: var(--fill); font-size: 13px; color: var(--text-h) }
  span.box { cursor: default }
  .box small { color: var(--muted); font-size: 11px }
  .box.down { border-color: rgba(255, 110, 110, .5) }
  .box.sel, .gh.sel, .node.sel { outline: 2px solid var(--err); outline-offset: 1px }
  .ln { width: 28px; height: 1px; background: var(--line-2); flex: none }
  .impact { display: flex; gap: 8px; align-items: center; justify-content: space-between; padding: 8px 12px; margin-bottom: 10px; border-radius: 10px;
            border: 1px solid rgba(255, 110, 110, .4); background: rgba(255, 110, 110, .06); font-size: 13px }
  .impact b { color: var(--err); font-weight: 500 }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(340px, 100%), 1fr)); gap: 12px; position: relative }
  .node { border: 1px solid var(--line); border-radius: 12px; padding: 8px 10px; background: var(--fill); min-width: 0 }
  .node.loose { margin-top: 12px }
  .nh { all: unset; cursor: pointer; display: flex; gap: 8px; align-items: baseline; width: 100%; padding: 2px 0 6px;
        border-bottom: 1px solid var(--line); margin-bottom: 4px }
  .nh b { color: var(--text-h); font-weight: 500 }
  .nh small, .gh small { color: var(--muted); font-size: 11px; margin-left: auto; white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .guest { padding: 3px 0 3px 10px; border-left: 1px solid var(--line-2); margin-left: 3px }
  .gh { all: unset; cursor: pointer; display: flex; gap: 6px; align-items: baseline; width: 100%; font-size: 12.5px; border-radius: 6px; padding: 1px 4px; min-width: 0 }
  .gh:hover, .nh:hover, .box:hover { background: var(--fill-h) }
  .vm { color: var(--muted); font-size: 11px; min-width: 32px }
  .gn { color: var(--text-h); white-space: nowrap; overflow: hidden; text-overflow: ellipsis }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; padding: 3px 0 2px 42px }
  .chips.direct { padding-left: 0; margin-bottom: 4px }
  .chip { display: inline-flex; gap: 5px; align-items: center; font-size: 11.5px; padding: 1px 7px; border-radius: 7px;
          border: 1px solid var(--line-2); color: var(--text) }
  .chip.down { color: var(--err); border-color: rgba(255, 110, 110, .4) }
  .chip em { font-style: normal; color: var(--muted) }
  .chip.hit, .guest.hit .gh { background: rgba(255, 110, 110, .14); border-color: rgba(255, 110, 110, .6) }
  .dim { opacity: .35 }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--line-2); flex: none; display: inline-block }
  .dot.ok, .dot.up { background: var(--ok) }
  .dot.err, .dot.down { background: var(--err) }
  .e { color: var(--err) }
  .small { font-size: 12px; margin: 2px 0 6px }
  @media (max-width: 640px) {
    .ln { width: 12px }
    .chips { padding-left: 10px }
  }
</style>
