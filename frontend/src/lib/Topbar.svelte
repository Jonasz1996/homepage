<script>
  import { dash } from './dash.svelte.js'
  import { storm } from './fx.js'
  import { layer } from './nav.js'
  import { byId, MENUS, WINDOWS } from './windows.js'
  import Notifications from './Notifications.svelte'

  // De titelbalk: Aandacht (wat nu mis is, het enige getal dat telt), Meldingen (gebeurtenissen) en drie menu's met
  // leesbare namen. Op de gsm staan de drie menu's samen achter ☰.
  let { clock, zonder = false, onlogout } = $props()

  let open = $state(null) // 'infra', 'beheer', 'instellingen' of 'alles' (☰ op de gsm)
  let place = $state({ top: 56, right: 12 })

  // Rood als een WAN-gateway of tunnel niet in orde is, oranje bij problemen.
  let netLevel = $derived.by(() => {
    const net = dash.net
    if (!net) return ''
    const gws = net.gateways.flatMap((g) => g.items.map((i) => i.level))
    const tus = net.tunnels.flatMap((t) => t.items.map((i) => i.status))
    if (gws.includes('err') || tus.some((x) => x === 'down' || x === 'inactive') || net.public_ip.error) return 'err'
    if (gws.includes('warn') || tus.includes('degraded')) return 'warn'
    return gws.length || tus.length || net.public_ip.ip ? 'ok' : ''
  })

  // Wat er per venster in het menu naast de naam staat. Rood en oranje tellen ook mee in Aandacht; hier zie je waar.
  let badges = $derived.by(() => {
    const h = dash.health, c = dash.cron, u = dash.updates
    return {
      health: h.err + h.warn ? { n: h.err + h.warn, lv: h.err ? 'err' : 'warn' } : null,
      cron: c.fout + c.gemist ? { n: c.fout + c.gemist, lv: c.fout ? 'err' : 'warn', title: `${c.fout} mislukt, ${c.gemist} niet gelopen` } : null,
      updates: u.total ? { n: u.total, lv: u.security ? 'warn' : '', title: u.security ? `${u.security} beveiligingsupdates` : '' } : null,
      network: netLevel ? { dot: netLevel } : null,
    }
  })
  let att = $derived(dash.att.counts.err + dash.att.counts.warn)

  // Met een probleem opent het venster meteen op dat probleem (zoals de oude knoppen deden).
  function startOf(id) {
    if (id === 'cron' && dash.cron.fout + dash.cron.gemist) return { filter: 'probleem' }
    if (id === 'health' && dash.health.problems?.length) return { tab: 'homepage' }
    if (id === 'logs') return { keep: true }
    return {}
  }

  const items = (menu) => WINDOWS.filter((w) => w.menu === menu)

  function toggle(e, which) {
    if (open === which) return (open = null)
    const btn = e.currentTarget
    const bar = btn.closest('.bar')
    const card = btn.closest('.card')
    // Onder de titelbalk, rechts uitgelijnd op de knop (op de gsm op de rand van de kaart).
    const right = which === 'alles' || !card ? 12 : Math.max(12, card.getBoundingClientRect().right - btn.getBoundingClientRect().right)
    place = { top: (bar?.offsetHeight || 50) + 6, right }
    open = which
  }

  $effect(() => {
    if (!open) return
    const release = layer(() => (open = null))
    const key = (e) => { if (e.key === 'Escape') open = null }
    const away = (e) => { if (!e.target.closest?.('.dd, .mbtn')) open = null }
    addEventListener('keydown', key)
    addEventListener('pointerdown', away, true)
    return () => { release(); removeEventListener('keydown', key); removeEventListener('pointerdown', away, true) }
  })

  // De focus eerst terug op de menuknop (het menu-item verdwijnt): een venster dat nu opent, geeft ze bij het sluiten
  // daaraan terug. Niet bij een groot venster: dat neemt de focus niet, en een Enter of spatie zou het menu erachter
  // openen.
  function shut(big = false) {
    if (!big) document.querySelector('.mbtn.on')?.focus({ preventScroll: true })
    open = null
  }
  function go(id) {
    shut(!!byId[id]?.big)
    dash.open(id, startOf(id))
  }
  function toggleEdit() {
    shut()
    dash.editing = !dash.editing
  }
  function toggleFx() {
    dash.setFx(!dash.fx)
    if (dash.fx) storm()
  }
  function logout() {
    shut()
    onlogout()
  }
</script>

{#snippet entry(w)}
  <button class="it" role="menuitem" onclick={() => go(w.id)} title={badges[w.id]?.title || undefined}>
    <span class="nm">{w.label}{#if badges[w.id]?.n}<b class="n {badges[w.id].lv}">{badges[w.id].n}</b>{/if}{#if badges[w.id]?.dot}<i class="nd {badges[w.id].dot}"></i>{/if}</span>
    {#if w.code}<code>{w.code}</code>{/if}
    <small>{w.hint}</small>
  </button>
{/snippet}

{#snippet menu(id)}
  {#each items(id) as w (w.id)}{@render entry(w)}{/each}
  {#if id === 'beheer'}
    <button class="it" role="menuitem" class:sel={dash.editing} onclick={toggleEdit}>
      <span class="nm">{dash.editing ? '✓ Bewerken stoppen' : 'Dashboard bewerken'}</span><code>✎</code>
      <small>tegels, groepen en pagina's; importeren, exporteren, versies</small>
    </button>
  {:else if id === 'instellingen'}
    <button class="it" role="menuitemcheckbox" onclick={toggleFx} aria-checked={dash.fx}>
      <span class="nm">Effecten: {dash.fx ? 'aan' : 'uit'}</span>
      <small>bewegende achtergrond, gloed, scanlijnen, vuur en bliksem</small>
    </button>
    {#if !zonder}
      <button class="it" role="menuitem" onclick={logout} title="Uitloggen">
        <span class="nm">Uitloggen</span><code>⏻</code>
        <small>deze sessie beëindigen</small>
      </button>
    {/if}
  {/if}
{/snippet}

<span class="clock">{clock}</span>
{#if dash.where?.outside}
  <button class="mini buiten" onclick={() => dash.open('security', { tab: 'outside' })}
          title="Je bent van buitenaf verbonden ({dash.where.why}): terminal, updates, acties en downloads staan uit, tenzij je ze aanzet">buiten</button>
{/if}
<button class="mini att" class:bad={dash.att.counts.err} class:warn={!dash.att.counts.err && att} onclick={() => dash.open('attention')}
        title="Aandacht: alles wat nu mis is, en welke functies nog ingesteld moeten worden">!<span class="ml">Aandacht</span>{#if att}<b class="n">{att}</b>{/if}</button>
<Notifications />
{#each MENUS as m (m.id)}
  <button class="mini mbtn wide" class:on={open === m.id} onclick={(e) => toggle(e, m.id)} aria-haspopup="menu" aria-expanded={open === m.id}
          title="{m.label}: {m.hint}">{m.label} <span class="car">▾</span></button>
{/each}
<button class="mini mbtn burger" class:on={open === 'alles'} onclick={(e) => toggle(e, 'alles')} aria-label="Menu" aria-haspopup="menu"
        aria-expanded={open === 'alles'}>☰</button>
{#if dash.editing}
  <button class="mini on" onclick={() => (dash.editing = false)} title="Bewerken stoppen">✓ klaar</button>
{/if}

{#if open}
  <div class="dd card" class:all={open === 'alles'} style:top="{place.top}px" style:right="{place.right}px" role="menu"
       aria-label={open === 'alles' ? 'Menu' : MENUS.find((m) => m.id === open)?.label}>
    {#if open === 'alles'}
      {#each MENUS as m (m.id)}
        <span class="sec">{m.label}</span>
        {@render menu(m.id)}
      {/each}
    {:else}
      {@render menu(open)}
    {/if}
  </div>
{/if}

<style>
  .clock { color: var(--text); margin-right: 4px }
  .buiten { color: var(--mid); border-color: rgba(255, 190, 90, .45) }
  .ml { margin-left: 6px }
  .n { margin-left: 6px; color: var(--text-h); font-size: 11px; font-weight: 500 }
  .att.bad { border-color: rgba(229, 139, 139, .5) }
  .att.bad .n, .n.err { color: var(--err) }
  .att.warn .n, .n.warn { color: var(--mid) }
  .car { color: var(--muted); font-size: 10px; margin-left: 2px }
  .burger { display: none; padding: 3px 10px }
  .nd { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin: 0 0 1px 7px; vertical-align: middle }
  .nd.ok { background: var(--ok) }
  .nd.warn { background: var(--mid) }
  .nd.err { background: var(--err); box-shadow: 0 0 6px var(--err) }
  /* Het menu hangt onder de titelbalk; de kaart is de referentie (de titelbalk zelf knipt af). */
  .dd {
    position: absolute; z-index: 10; width: min(360px, calc(100% - 24px)); max-height: min(75vh, 640px); overflow: auto;
    padding: 6px; display: flex; flex-direction: column; gap: 2px; white-space: normal; text-align: left;
    background: rgba(18, 18, 18, .97); border: 1px solid var(--line-2); box-shadow: 0 12px 40px rgba(0, 0, 0, .6)
  }
  .sec { flex: none; font-size: 11.5px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); padding: 10px 10px 2px }
  .sec:first-child { padding-top: 4px }
  .it {
    all: unset; box-sizing: border-box; cursor: pointer; display: grid; grid-template-columns: 1fr auto; column-gap: 10px;
    padding: 8px 10px; border-radius: 9px; min-height: 44px; flex: none
  }
  .it:hover, .it:focus-visible { background: var(--fill-h) }
  .it:focus-visible { outline: 2px solid #fff; outline-offset: -2px }
  .it.sel { background: var(--fill) }
  .nm { color: var(--text-h); font-size: 13.5px }
  .it code { color: var(--muted); font-size: 11.5px; align-self: center }
  .it small { grid-column: 1 / -1; color: var(--muted); font-size: 12px; margin-top: 2px; line-height: 1.4 }
  @media (max-width: 760px) {
    .wide, .ml { display: none }
    .burger { display: inline-block }
  }
  @media (max-width: 560px) {
    .clock { display: none }
  }
</style>
