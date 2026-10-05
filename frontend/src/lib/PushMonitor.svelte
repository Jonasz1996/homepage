<script>
  import { onMount } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import { rel } from './cronfmt.js'
  import CopyCmd from './CopyCmd.svelte'

  // Push-monitor (zoals in Uptime Kuma): een script roept het geheime adres aan. Blijft dat langer stil dan het
  // interval, dan gaat de tegel down.
  let { service } = $props()
  let data = $state(null)
  let error = $state('')
  let busy = $state(false)

  async function load() {
    try { data = await api(`/services/${service.id}/push`); error = '' } catch (e) { error = e.message }
  }
  onMount(() => {
    load()
    return poll(load, 15000)
  })

  async function act(path, method = 'POST', body) {
    busy = true
    try {
      data = await withReauth(() => api(`/services/${service.id}/push${path}`, { method, body }))
      error = ''
    } catch (e) { error = e.message } finally { busy = false }
  }
  function rotate() {
    if (!confirm('Een nieuw adres maken? Het huidige werkt dan meteen niet meer: pas je scripts aan.')) return
    act('/rotate')
  }
  async function setOutside(e) {
    const el = e.currentTarget
    await act('', 'PATCH', { outside: el.checked })
    // Geannuleerd of mislukt: het vinkje terug zoals op de server.
    el.checked = !!data?.outside
  }

  let url = $derived(data?.path ? location.origin + data.path : '')
  let every = $derived(Number(service.check?.interval) || 60)
  const per = (s) => (s % 3600 === 0 ? `${s / 3600} u` : s % 60 === 0 ? `${s / 60} min` : `${s} s`)
  // Een cronregel die past bij het interval: zo vaak of iets vaker.
  let when = $derived.by(() => {
    const m = Math.max(1, Math.floor(every / 60))
    if (m < 60) {
      const d = [30, 20, 15, 12, 10, 6, 5, 4, 3, 2, 1].find((x) => x <= m)
      return d === 1 ? '* * * * *' : `*/${d} * * * *`
    }
    const h = Math.floor(m / 60)
    if (h >= 24) return '0 3 * * *'
    const d = [12, 8, 6, 4, 3, 2, 1].find((x) => x <= h)
    return d === 1 ? '0 * * * *' : `0 */${d} * * *`
  })
  let slug = $derived((service.name || 'tegel').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'tegel')
  let curl = $derived(`curl -fsS -m 10 "${url}?status=up&msg=OK"`)
  let cron = $derived(`${when} /pad/naar/script.sh && curl -fsS -m 10 "${url}?status=up" || curl -fsS -m 10 "${url}?status=down&msg=fout"`)
  let ha = $derived(`rest_command:\n  push_${slug}:\n    url: "${url}?status=up&msg=OK"\n    method: get\n# in een automatisering: action: rest_command.push_${slug}`)
</script>

<div class="pm">
  <div class="top">
    <span class="lbl">push-monitor</span>
    <small class="st">verwacht elke {per(every)}</small>
    <span class="sp"></span>
    {#if data?.path}<button class="mini" disabled={busy} onclick={rotate}>nieuw adres</button>{/if}
  </div>
  {#if error}<p class="err">{error}</p>{/if}

  {#if data && !data.path}
    <p class="hint small">Een script, een automatisering in Home Assistant of een back-up roept een geheim adres aan.
      Blijft dat langer dan {per(every)} stil, of meldt het status=down, dan gaat deze tegel down.</p>
    <button class="mini" disabled={busy} onclick={() => act('')}>push-adres maken</button>
  {:else if data}
    <CopyCmd cmd={url} />
    <div class="last">
      {#if data.last_at}
        <span>laatste signaal {rel(data.last_at)}</span>
        <span class:g={data.last_ok} class:e={!data.last_ok}>{data.last_ok ? 'up' : 'down'}</span>
        {#if data.last_msg}<span class="m">{data.last_msg}</span>{/if}
        {#if data.last_ping != null}<span class="m">{data.last_ping} ms</span>{/if}
        <span class="m">{data.count} {data.count === 1 ? 'signaal' : 'signalen'}</span>
      {:else}
        <span class="m">nog geen signaal</span>
      {/if}
    </div>
    <label class="chk"><input type="checkbox" checked={data.outside} disabled={busy} onchange={setOutside} />
      ook van buitenaf (via Cloudflare)</label>
    {#if data.outside}
      <p class="hint small">Zet dan in Cloudflare Access of Authentik een uitzondering voor /api/push/*.</p>
    {/if}
    <details>
      <summary class="small">voorbeelden</summary>
      <span class="small m">Eén signaal (status=up of down, msg en ping in ms mogen erbij, zoals in Kuma):</span>
      <CopyCmd cmd={curl} />
      <span class="small m">Cron: up als het script lukt, anders down:</span>
      <CopyCmd cmd={cron} />
      <span class="small m">Home Assistant (configuration.yaml):</span>
      <CopyCmd cmd={ha} />
      <p class="hint small">Het pad werkt op elk adres van het dashboard, ook het interne.</p>
    </details>
  {/if}
</div>

<style>
  .pm { margin: 8px 0; display: flex; flex-direction: column; gap: 4px }
  .pm > button, .chk { align-self: flex-start }
  .top { display: flex; gap: 8px; align-items: center; flex-wrap: wrap }
  .top .lbl { margin: 0 }
  .st { color: var(--muted); font-size: 11.5px }
  .sp { flex: 1 }
  .last { display: flex; gap: 8px; flex-wrap: wrap; align-items: baseline; font-size: 12.5px }
  .last .m { overflow-wrap: anywhere }
  .m { color: var(--muted) }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .small { font-size: 12px; margin: 2px 0 }
  .chk input { width: auto }
  details { margin-top: 2px }
  summary { cursor: pointer; color: var(--muted) }
  details > span { display: block; margin-top: 6px }
</style>
