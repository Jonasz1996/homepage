<script>
  import { bolt, boom, sparkle } from './fx.js'
  import { api } from './api.js'
  import { dash } from './dash.svelte.js'
  import { layer } from './nav.js'
  import { byId, NOTIFICATION_SOURCES, sourceWindow } from './windows.js'

  // Eigen meldingencentrum: de bel in de titelbalk met het aantal ongelezen gebeurtenissen, uitklapbaar paneel.
  // Wat nu mis is, staat onder Aandacht; hier staan de gebeurtenissen, de tijdlijn is het archief.
  // Het aantal komt mee met het samenvattende verzoek van het dashboard; de lijst zelf pas als je de bel opent.
  let data = $state({ unread: 0, items: [] })
  let loading = $state(false)
  // "wis gelezen" laat staan wat nog niet op je gsm is, tot het verstuurd is: zo wist niemand "Login vanaf nieuw IP"
  // voor jij het ziet. Hoeveel er bleven staan.
  let kept = $state(0)
  let bell = $state()
  let top = $state(56)

  const fmt = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  let unread = $derived(dash.notif.unread)

  async function load() {
    loading = true
    try {
      data = await api('/notifications')
      dash.notif = { unread: data.unread, newest: data.items[0] || null }
    } catch { /* volgende poging */ } finally { loading = false }
  }

  // Nieuwe storing binnen: een bliksem op het belletje (niet bij het eerste laden).
  let seen = null
  $effect(() => {
    const n = dash.notif.newest
    if (seen !== null && n && n.id > seen && !n.read && n.level === 'err') bolt(bell)
    if (n) seen = Math.max(seen ?? 0, n.id)
    else seen ??= 0
  })

  // Openen: de lijst laden, onder de titelbalk tonen, en terug of Escape sluit het paneel.
  $effect(() => {
    if (!dash.notifOpen) return
    kept = 0
    const bar = bell?.closest('.bar')
    if (bar) top = bar.offsetHeight + 6
    load()
    const release = layer(() => (dash.notifOpen = false))
    const key = (e) => { if (e.key === 'Escape') dash.notifOpen = false }
    const away = (e) => { if (!e.target.closest?.('.npanel, .bell')) dash.notifOpen = false }
    addEventListener('keydown', key)
    addEventListener('pointerdown', away, true)
    return () => { release(); removeEventListener('keydown', key); removeEventListener('pointerdown', away, true) }
  })

  const clickable = (n) => NOTIFICATION_SOURCES.includes(n.source) || !!n.service_id
  // Eerst de focus terug op de bel: een venster dat nu opent, geeft ze bij het sluiten daaraan terug. Niet bij een
  // groot venster: dat neemt de focus niet, en een Enter of spatie zou de bel erachter openen.
  function closePanel(big = false) {
    if (!big) bell?.focus({ preventScroll: true })
    dash.notifOpen = false
  }
  function pick(n) {
    if (!clickable(n)) return
    closePanel(!!byId[sourceWindow(n.source)?.id]?.big)
    if (!n.read) api(`/notifications/${n.id}/read`, { method: 'POST' }).then(() => dash.refresh(['meldingen'])).catch(() => {})
    dash.openNotification(n)
  }
  function go(id) {
    closePanel()
    dash.open(id)
  }

  async function readAll() {
    sparkle()
    try { await api('/notifications/read-all', { method: 'POST' }) } catch { /* volgende poging */ }
    await load()
    // Een overzicht dat al onderweg was, telt nog de oude stand: daarna meteen opnieuw.
    dash.refresh(['meldingen'])
  }

  async function clearRead() {
    boom(undefined, 0.8)
    try { kept = (await api('/notifications', { method: 'DELETE' })).kept || 0 } catch { /* volgende poging */ }
    await load()
    dash.refresh(['meldingen'])
  }
</script>

<button bind:this={bell} class="mini bell" class:has={unread > 0} onclick={() => (dash.notifOpen = !dash.notifOpen)}
        aria-label="Meldingen" aria-expanded={dash.notifOpen} title="Meldingen: gebeurtenissen">
  ◉<span class="ml">Meldingen</span>{#if unread > 0}<b>{unread}</b>{/if}
</button>
{#if dash.notifOpen}
  <div class="npanel card" style:top="{top}px" role="dialog" aria-label="Meldingen">
    <div class="head">
      <span>meldingen</span>
      <button class="mini" onclick={readAll}>alles gelezen</button>
      <button class="mini x" onclick={clearRead}>wis gelezen</button>
    </div>
    {#if kept}<p class="kept">{kept} {kept === 1 ? 'melding is' : 'meldingen zijn'} nog niet naar je gsm gestuurd: {kept === 1 ? 'die blijft' : 'die blijven'} staan tot dat gebeurd is.</p>{/if}
    <div class="items">
      {#each data.items as n (n.id)}
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div class="n {n.level}" class:unread={!n.read} class:go={clickable(n)} role={clickable(n) ? 'button' : undefined}
             tabindex={clickable(n) ? 0 : undefined} onclick={() => pick(n)} onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); pick(n) } }}>
          <div class="t"><span class="lvl">{n.level}</span>{n.title}</div>
          {#if n.body}<div class="b">{n.body}</div>{/if}
          <div class="ts">{fmt(n.ts)} · {n.source}{#if n.source === 'rapport'} · <u>volledig rapport</u>{/if}</div>
        </div>
      {:else}
        <p class="empty">{loading ? 'Laden…' : 'Geen meldingen.'}</p>
      {/each}
    </div>
    <div class="foot">
      <button class="lnk" onclick={() => go('history')} title="Alles wat er gebeurde: storingen, herstarts, back-ups">tijdlijn (archief)</button>
      <button class="lnk" onclick={() => go('webhooks')} title="Meldingen van Proxmox, PBS, Uptime Kuma, ... ontvangen">webhooks</button>
      <button class="lnk" onclick={() => go('webpush')} title="Meldingen op je gsm, ook als het dashboard dicht is (web push)">op je gsm</button>
    </div>
  </div>
{/if}

<style>
  .bell { color: var(--muted) }
  .bell.has { color: var(--mid) }
  .bell b { margin-left: 5px; color: var(--text-h); font-size: 11px }
  .ml { margin-left: 6px }
  /* Onder de titelbalk, tegen de rechterrand van de kaart (die is de referentie, niet de knop). */
  .npanel {
    position: absolute; right: 12px; width: min(400px, calc(100% - 24px)); z-index: 10;
    white-space: normal; padding: 10px; color: var(--text); text-align: left; background: rgba(18, 18, 18, .97)
  }
  .head { display: flex; gap: 6px; align-items: center; margin-bottom: 8px; font-size: 12px; color: var(--muted) }
  .head span { flex: 1 }
  .kept { margin: 0 0 8px; font-size: 11.5px; color: var(--muted) }
  .items { max-height: 60vh; overflow: auto }
  .n {
    padding: 8px 10px; margin-bottom: 6px; border-radius: 8px; background: var(--fill);
    border: 1px solid rgba(255, 255, 255, .06); border-left: 3px solid var(--line-2); font-size: 12.5px; color: var(--muted)
  }
  /* Ongelezen: helder en met een gekleurde rand; gelezen blijft goed leesbaar, alleen rustiger. */
  .n.unread { color: var(--text); background: rgba(255, 255, 255, .07) }
  .n.unread .t { color: var(--text-h) }
  .n.go { cursor: pointer }
  .n.go:hover { background: var(--fill-h) }
  .n.unread.ok { border-left-color: var(--ok) }
  .n.unread.warn { border-left-color: var(--mid) }
  .n.unread.err { border-left-color: var(--err) }
  .lvl { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); margin-right: 8px }
  .n.warn .lvl { color: var(--mid) }
  .n.err .lvl { color: var(--err) }
  .n.ok .lvl { color: var(--ok) }
  .b { white-space: pre-line; margin-top: 3px }
  .ts { color: var(--dim); font-size: 11.5px; margin-top: 4px }
  .empty { color: var(--muted); font-size: 12.5px; margin: 6px }
  .foot { display: flex; gap: 14px; flex-wrap: wrap; padding: 8px 4px 2px; border-top: 1px solid var(--line); margin-top: 4px }
  .lnk { background: none; border: 0; padding: 4px 0; font: inherit; font-size: 12px; color: var(--muted); cursor: pointer; text-decoration: underline; text-underline-offset: 3px }
  .lnk:hover { color: var(--text-h) }
  @media (max-width: 760px) { .ml { display: none } }
</style>
