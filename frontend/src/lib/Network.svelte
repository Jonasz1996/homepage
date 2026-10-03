<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Internet: publiek IP, WAN-gateways (OPNsense), Cloudflare-tunnels en Wake-on-LAN.
  let { onclose, onchanged } = $props()

  let data = $state(null)
  let error = $state('')
  let busy = $state(false)
  let msg = $state('')

  async function load() {
    try { data = await api('/network'); error = '' } catch (e) { error = e.message }
  }
  async function refresh() {
    busy = true
    try { data = await api('/network/refresh', { method: 'POST' }); error = ''; onchanged?.(data) }
    catch (e) { error = e.message } finally { busy = false }
  }
  onMount(load)

  async function wake(w) {
    if (!confirm(`${w.name} wekken met Wake-on-LAN?`)) return
    try {
      const r = await withReauth(() => api(`/services/${w.service_id}/wol`, { method: 'POST' }))
      msg = `✓ ${r.message}`
    } catch (e) { msg = `✕ ${e.message}` }
  }

  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '—')
  function ago(ts) {
    if (!ts) return ''
    const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
    if (m < 60) return `${Math.max(m, 0)} min`
    if (m < 48 * 60) return `${Math.floor(m / 60)} u`
    return `${Math.floor(m / 1440)} dagen`
  }
  const TUN = { healthy: 'ok', degraded: 'w', down: 'e', inactive: 'e' }
  const STATE = { up: 'aan', down: 'uit / onbereikbaar', unknown: 'geen check' }
  let empty = $derived(data && !data.public_ip.ip && !data.gateways.length && !data.tunnels.length && !data.wol.length)
</script>

<Modal title="ip -br addr && cloudflared tunnel list" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if data}
    <div class="top">
      <div class="ip">
        <small>publiek IP</small>
        <b>{data.public_ip.ip || '—'}</b>
        <small>{#if data.public_ip.error}<span class="e">{data.public_ip.error}</span>
          {:else if data.public_ip.since}sinds {when(data.public_ip.since)} ({ago(data.public_ip.since)}){/if}</small>
      </div>
      <button class="mini" disabled={busy} onclick={refresh}>{busy ? 'bezig…' : 'vernieuwen'}</button>
    </div>
    {#if data.public_ip.history?.length}
      <details class="hist">
        <summary>vorige IP's ({data.public_ip.history.length})</summary>
        {#each data.public_ip.history as h}
          <div class="ln"><span>{h.ip}</span><small>{when(h.since)} – {when(h.until)}</small></div>
        {/each}
      </details>
    {/if}

    {#each data.gateways as g (g.service_id)}
      <span class="lbl">WAN · {g.service}</span>
      {#if g.error}<p class="e small">{g.error}</p>{/if}
      <div class="cards">
        {#each g.items as gw}
          <div class="c {gw.level === 'ok' ? 'ok-b' : gw.level === 'err' ? 'e-b' : 'w-b'}">
            <b>{gw.name}</b>
            <span class:e={gw.level === 'err'} class:w={gw.level === 'warn'} class:g={gw.level === 'ok'}>{gw.label}</span>
            <small>{gw.delay_ms != null ? `${gw.delay_ms.toFixed(1)} ms` : '—'}{gw.loss_pct ? ` · ${gw.loss_pct.toFixed(0)}% verlies` : ''}{gw.monitor ? ` · naar ${gw.monitor}` : ''}</small>
          </div>
        {/each}
      </div>
    {/each}

    {#each data.tunnels as t (t.service_id)}
      <span class="lbl">Cloudflare-tunnels · {t.service}</span>
      {#if t.error}<p class="e small">{t.error}</p>{/if}
      <div class="cards">
        {#each t.items as tu}
          <div class="c {TUN[tu.status] === 'ok' ? 'ok-b' : TUN[tu.status] === 'w' ? 'w-b' : 'e-b'}">
            <b>{tu.name}</b>
            <span class={TUN[tu.status] === 'ok' ? 'g' : TUN[tu.status]}>{tu.status}</span>
            <small>{tu.connections} verbinding{tu.connections === 1 ? '' : 'en'}{tu.colos.length ? ` · ${tu.colos.join(', ')}` : ''}{tu.version ? ` · ${tu.version}` : ''}</small>
          </div>
        {/each}
      </div>
    {/each}

    {#if data.wol.length}
      <span class="lbl">Wake-on-LAN</span>
      {#each data.wol as w (w.service_id)}
        <div class="ln wl">
          <span>{w.name} <small>{w.mac}</small></span>
          <small class:e={w.status === 'down'} class:g={w.status === 'up'}>{STATE[w.status] || w.status}</small>
          <button class="mini" onclick={() => wake(w)}>wekken</button>
        </div>
      {/each}
      {#if msg}<p class="small" class:e={msg.startsWith('✕')} class:g={!msg.startsWith('✕')}>{msg}</p>{/if}
    {/if}

    {#if empty}
      <p class="hint">Nog niets te tonen. Voeg een tegel van type <b>opnsense</b> (WAN-status) of <b>cloudflared</b>
        (tunnels) toe, en zet bij een node onder bewerken een <b>MAC-adres</b> voor Wake-on-LAN.</p>
    {/if}
    <p class="hint small">WAN en tunnels elke 2 minuten, het publieke IP elke 5 minuten. Een melding komt pas als een
      nieuwe toestand twee keer na elkaar gezien wordt.</p>
  {:else}
    <p class="hint">laden…</p>
  {/if}
</Modal>

<style>
  .top { display: flex; align-items: center; gap: 12px }
  .ip { flex: 1 }
  .ip b { display: block; font-size: 22px; font-weight: 500; color: var(--text-h); letter-spacing: .02em }
  .ip small { color: var(--muted); font-size: 11.5px }
  .hist { margin: 6px 0 0; font-size: 12px; color: var(--muted) }
  .hist summary { cursor: pointer }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px }
  .c { padding: 10px 12px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08);
       border-left: 3px solid #666; display: flex; flex-direction: column; gap: 2px; font-size: 12.5px }
  .c b { color: var(--text-h); font-weight: 500 }
  .c small { color: var(--dim); font-size: 11.5px }
  .ok-b { border-left-color: var(--ok) }
  .w-b { border-left-color: var(--mid) }
  .e-b { border-left-color: var(--err) }
  .ln { display: flex; gap: 10px; align-items: center; justify-content: space-between; font-size: 12.5px; padding: 5px 0;
        border-bottom: 1px solid rgba(255, 255, 255, .05) }
  .ln small { color: var(--dim) }
  .wl span { flex: 1 }
  .g { color: var(--ok) !important }
  .w { color: var(--mid) !important }
  .e { color: var(--err) !important }
  .small { font-size: 11.5px; margin-top: 10px }
</style>
