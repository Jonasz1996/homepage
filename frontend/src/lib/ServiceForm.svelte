<script>
  import { boom } from './fx.js'
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import { iconIsMono, iconUrl } from './icons.js'
  import Modal from './Modal.svelte'

  // service = bestaande service, of null voor een nieuwe in groupId.
  let { service = null, groupId, groups, services = [], onclose, onsaved } = $props()

  // Formulier start met de huidige waarden; wijzigingen daarna komen van de gebruiker.
  const s = untrack(() => service) || {}
  let name = $state(s.name || '')
  let url = $state(s.url || '')
  let icon = $state(s.icon || '')
  let description = $state(s.description || '')
  let group_id = $state(s.group_id || untrack(() => groupId))
  let type = $state(s.type || 'link')
  const c0 = s.check || {}
  let checkType = $state(c0.type || '')
  let checkTarget = $state(c0.target || '')
  let checkInterval = $state(c0.interval || 60)
  let checkInsecure = $state(!!c0.insecure)
  let keyword = $state(c0.keyword || '')
  let keywordAbsent = $state(!!c0.keyword_absent)
  let jsonPath = $state(c0.json_path || '')
  let jsonValue = $state(c0.json_value ?? '')
  let dnsServer = $state(c0.dns_server || '')
  let dnsExpect = $state(c0.expect || '')
  let dnsRecord = $state(c0.record || 'A')
  // Wanneer down, hoe melden, en de HTTP-opties (wat Uptime Kuma ook kon).
  let downAfter = $state(c0.down_after || 3)
  let retryInterval = $state(c0.retry_interval || '')
  let remindHours = $state(c0.remind_hours || 0)
  let notifyMode = $state(c0.notify || 'push')
  let paused = $state(!!c0.paused)
  let certNotify = $state(c0.cert_notify !== false)
  let accept = $state(c0.accept || (c0.expect_status ? String(c0.expect_status) : ''))
  let followRedirects = $state(c0.follow_redirects !== false)
  let sameHost = $state(!!c0.same_host)
  let checkTimeout = $state(c0.timeout || '')
  let method = $state(c0.method || 'GET')
  let reqBody = $state(c0.body || '')
  let bodyType = $state(c0.body_type || 'json')
  let headersText = $state(Object.entries(c0.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'))
  // Container (via een Portainer-tegel) en de API van de tegel zelf.
  let portainerId = $state(c0.portainer_id ?? null)
  let containerName = $state(c0.container || '')
  let apiPath = $state(c0.path || '')
  let portainers = $derived(services.filter((x) => x.type === 'portainer' && x.id !== s.id))
  let containers = $state.raw([])
  let containersError = $state('')
  $effect(() => {
    const pid = portainerId
    containers = []
    containersError = ''
    if (checkType !== 'container' || !pid) return
    api(`/services/${pid}/containers`).then((r) => { if (pid === portainerId) containers = r })
      .catch((e) => { if (pid === portainerId) containersError = e.message })
  })
  function pickPortainer() {
    // Een container hangt af van zijn Portainer: valt die uit, dan één melding in plaats van één per container.
    if (portainerId && !parentId) parentId = portainerId
  }
  let parentId = $state(s.parent_id ?? null)
  // Kandidaten voor "hangt af van": alles behalve zichzelf.
  let parents = $derived(services.filter((x) => x.id !== s.id).sort((a, b) => a.name.localeCompare(b.name)))
  // MAC-adres (Wake-on-LAN) en de Zabbix-hosts hebben een eigen veld; de rest van config staat als JSON.
  const { mac: initialMac, zabbix: initialZabbix, ...restConfig } = s.config || {}
  let mac = $state(initialMac || '')
  let zabbixHosts = $state(initialZabbix || '')
  let zabbix = $state.raw(null)
  api('/zabbix').then((r) => (zabbix = r)).catch(() => {})
  let configText = $state(Object.keys(restConfig).length ? JSON.stringify(restConfig, null, 2) : '')
  let secretKeys = $state([...(s.secret_keys || [])])
  let removed = $state([])
  let newSecrets = $state([])
  let error = $state('')
  let busy = $state(false)
  let iconBroken = $state(false)

  let integrations = $state([])
  api('/integrations').then((r) => (integrations = r)).catch(() => {})
  let integ = $derived(integrations.find((i) => i.name === type))
  // API uit API-beheer: dan komen adres en sleutels daarvandaan.
  let apiId = $state(s.api_id ?? null)
  let apis = $state([])
  api('/apis').then((r) => (apis = r.apis)).catch(() => {})
  let apiSel = $derived(apis.find((a) => a.id === apiId))
  let apiCats = $derived.by(() => {
    const m = new Map()
    for (const a of apis) { if (!m.has(a.category)) m.set(a.category, []); m.get(a.category).push(a) }
    return [...m]
  })

  let preview = $derived(iconUrl(icon))
  $effect(() => { preview; iconBroken = false })

  function headersObj() {
    const out = {}
    for (const line of headersText.split('\n')) {
      if (!line.trim()) continue
      const i = line.indexOf(':')
      if (i < 1) throw new Error(`Header "${line.trim()}" is geen Naam: waarde`)
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
    }
    return out
  }

  function buildCheck() {
    const t = checkType
    const withTarget = ['http', 'tcp', 'ping', 'dns'].includes(t)
    const json = (t === 'http' || t === 'api') && jsonPath.trim()
    const secs = Number(checkTimeout)
    const c = {
      type: t,
      interval: Math.max(15, Number(checkInterval) || 60),
      ...(withTarget && checkTarget.trim() ? { target: checkTarget.trim() } : {}),
      ...(Number(downAfter) !== 3 ? { down_after: Number(downAfter) } : {}),
      ...(Number(retryInterval) ? { retry_interval: Number(retryInterval) } : {}),
      ...(Number(remindHours) ? { remind_hours: Number(remindHours) } : {}),
      ...(notifyMode !== 'push' ? { notify: notifyMode } : {}),
      ...(paused ? { paused: true } : {}),
      ...(json ? { json_path: jsonPath.trim(), json_value: String(jsonValue).trim() || null } : {}),
      ...((t === 'http' || t === 'api') && secs ? { timeout: secs } : {}),
    }
    if (t === 'http') {
      const headers = headersObj()
      Object.assign(c, {
        ...(checkInsecure ? { insecure: true } : {}),
        ...(keyword.trim() ? { keyword: keyword.trim(), keyword_absent: keywordAbsent } : {}),
        ...(accept.trim() ? { accept: accept.replace(/\s/g, '') } : {}),
        ...(!followRedirects ? { follow_redirects: false } : {}),
        ...(sameHost ? { same_host: true } : {}),
        ...(!certNotify ? { cert_notify: false } : {}),
        ...(method !== 'GET' ? { method } : {}),
        ...(method === 'POST' && reqBody.trim() ? { body: reqBody, body_type: bodyType } : {}),
        ...(Object.keys(headers).length ? { headers } : {}),
      })
    } else if (t === 'dns') {
      Object.assign(c, {
        ...(dnsServer.trim() ? { dns_server: dnsServer.trim() } : {}),
        ...(dnsExpect.trim() ? { expect: dnsExpect.trim() } : {}),
        ...(dnsRecord !== 'A' ? { record: dnsRecord } : {}),
        ...(c0.dns_port ? { dns_port: c0.dns_port } : {}),
      })
    } else if (t === 'container') {
      if (!portainerId || !containerName.trim()) throw new Error('Kies een Portainer-tegel en een container')
      Object.assign(c, { portainer_id: portainerId, container: containerName.trim(),
        ...(c0.env != null && c0.portainer_id === portainerId ? { env: c0.env } : {}) })
    } else if (t === 'api') {
      if (apiPath.trim()) c.path = apiPath.trim()
    }
    return c
  }

  function buildBody() {
    let config = {}
    if (configText.trim()) {
      try { config = JSON.parse(configText) } catch { throw new Error('Instellingen zijn geen geldige JSON') }
    }
    delete config.mac
    delete config.zabbix
    if (zabbixHosts.trim()) config.zabbix = zabbixHosts.trim()
    if (mac.trim()) {
      if (!/^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$/i.test(mac.trim())) throw new Error('MAC-adres klopt niet (bv. aa:bb:cc:dd:ee:ff)')
      config.mac = mac.trim()
    }
    const check = checkType ? buildCheck() : {}
    const secrets = {}
    for (const k of removed) secrets[k] = null
    for (const row of newSecrets) if (row.key.trim() && row.value) secrets[row.key.trim()] = row.value
    return {
      group_id, name, url: url || null, icon: icon || null, description: description || null,
      type: apiId ? (apiSel?.kind || type) : type === 'rest' || !type ? 'link' : type, api_id: apiId,
      check, config, parent_id: parentId || null,
      secrets: Object.keys(secrets).length ? secrets : null,
    }
  }

  async function save(e) {
    e.preventDefault()
    busy = true
    error = ''
    try {
      const body = buildBody()
      // Een ander adres of type voor een service met geheimen vraagt een recente 2FA.
      if (service) await withReauth(() => api(`/services/${service.id}`, { method: 'PATCH', body }))
      else await api('/services', { method: 'POST', body })
      onsaved()
      onclose()
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function del() {
    if (!confirm(`'${service.name}' verwijderen?`)) return
    await api(`/services/${service.id}`, { method: 'DELETE' })
    boom()
    onsaved()
    onclose()
  }
</script>

<Modal title={service ? `edit ${service.name}` : 'service --new'} {onclose} wide>
  <form onsubmit={save}>
    <div class="grid">
      <div>
        <label class="lbl" for="sf-name">Naam</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="sf-name" bind:value={name} maxlength="80" required autofocus />
      </div>
      <div>
        <label class="lbl" for="sf-group">Groep</label>
        <select id="sf-group" bind:value={group_id}>
          {#each groups as g (g.id)}<option value={g.id}>{g.label}</option>{/each}
        </select>
      </div>
      <div class="full">
        <label class="lbl" for="sf-url">URL</label>
        <input id="sf-url" type="url" bind:value={url} placeholder="https://proxmox50.jbogaert.be" />
      </div>
      <div class="full">
        <label class="lbl" for="sf-desc">Omschrijving</label>
        <input id="sf-desc" bind:value={description} maxlength="255" />
      </div>
      <div class="full">
        <label class="lbl" for="sf-icon">Icoon</label>
        <div class="row nowrap">
          <span class="prev">
            {#if preview && !iconBroken}
              <img src={preview} alt="" class:mono={iconIsMono(icon)} onerror={() => (iconBroken = true)} />
            {:else}?{/if}
          </span>
          <input id="sf-icon" bind:value={icon} placeholder="proxmox.png, sh-adguard-home, mdi-server of een URL" />
        </div>
        <p class="help">
          Namen uit <a href="https://dashboardicons.com" target="_blank" rel="noopener">dashboardicons.com</a>,
          <code>sh-</code> voor selfh.st, <code>mdi-</code> of <code>si-</code> voor Material en Simple Icons.
        </p>
      </div>
    </div>

    <details class="adv" open={!!checkType}>
      <summary>Monitoring</summary>
      <div class="grid">
        <div>
          <label class="lbl" for="sf-ct">Check</label>
          <select id="sf-ct" bind:value={checkType}>
            <option value="">geen</option>
            <option value="http">HTTP(S)</option>
            <option value="ping">ping</option>
            <option value="tcp">TCP-poort</option>
            <option value="dns">DNS</option>
            <option value="push">push (een script meldt zich)</option>
            <option value="container">Docker-container (via Portainer)</option>
            <option value="api">API van de tegel</option>
          </select>
        </div>
        <div>
          <label class="lbl" for="sf-ci">{checkType === 'push' ? 'Verwacht een signaal elke (seconden)' : 'Interval (seconden)'}</label>
          <input id="sf-ci" type="text" inputmode="numeric" bind:value={checkInterval} disabled={!checkType} />
        </div>
        {#if !['push', 'container', 'api'].includes(checkType)}
          <div class="full">
            <label class="lbl" for="sf-target">Doel</label>
            <input id="sf-target" bind:value={checkTarget} disabled={!checkType}
                   placeholder={checkType === 'tcp' ? 'leeg = host en poort uit de URL, of 192.168.0.10:22' : checkType === 'ping' ? 'leeg = host uit de URL, of 192.168.0.10' : checkType === 'dns' ? 'leeg = naam uit de URL' : 'leeg = de URL hierboven'} />
          </div>
        {/if}
      </div>
      {#if checkType === 'http'}
        <label class="chk tls"><input type="checkbox" bind:checked={checkInsecure} /> certificaatfouten negeren (zelfondertekend, bv. Proxmox op :8006)</label>
        <div class="grid">
          <div>
            <label class="lbl" for="sf-kw">Woord op de pagina (optioneel)</label>
            <input id="sf-kw" bind:value={keyword} placeholder="bv. Jellyfin" />
            <label class="chk"><input type="checkbox" bind:checked={keywordAbsent} disabled={!keyword.trim()} /> mag er juist niet staan</label>
          </div>
          <div>
            <label class="lbl" for="sf-jp">JSON-veld (optioneel)</label>
            <div class="row nowrap">
              <input id="sf-jp" bind:value={jsonPath} placeholder="status.health" />
              <input bind:value={jsonValue} placeholder="= ok" aria-label="Verwachte waarde" disabled={!jsonPath.trim()} />
            </div>
          </div>
          <div>
            <label class="lbl" for="sf-acc">Goede statuscodes</label>
            <input id="sf-acc" bind:value={accept} placeholder="leeg = alles onder 400, of 200-299,401" />
          </div>
          <div>
            <label class="lbl" for="sf-to">Time-out (seconden)</label>
            <input id="sf-to" type="text" inputmode="numeric" bind:value={checkTimeout} placeholder="10" />
          </div>
        </div>
        <label class="chk"><input type="checkbox" bind:checked={followRedirects} /> doorverwijzingen volgen</label>
        <label class="chk"><input type="checkbox" bind:checked={sameHost} /> down als hij naar een andere host doorverwijst (bv. de loginpagina van Authentik)</label>
        <label class="chk"><input type="checkbox" bind:checked={certNotify} /> melding als het certificaat bijna verloopt</label>
        <details class="req" open={method !== 'GET' || !!headersText.trim()}>
          <summary>verzoek: methode, body, headers</summary>
          <div class="grid">
            <div>
              <label class="lbl" for="sf-m">Methode</label>
              <select id="sf-m" bind:value={method}><option>GET</option><option>HEAD</option><option>POST</option></select>
            </div>
            {#if method === 'POST'}
              <div>
                <label class="lbl" for="sf-bt">Body als</label>
                <select id="sf-bt" bind:value={bodyType}><option value="json">JSON</option><option value="form">formulier</option><option value="text">tekst</option></select>
              </div>
              <div class="full">
                <label class="lbl" for="sf-body">Body</label>
                <textarea id="sf-body" bind:value={reqBody} rows="3" placeholder={'{"ping": true}'}></textarea>
              </div>
            {/if}
            <div class="full">
              <label class="lbl" for="sf-h">Headers (één per regel)</label>
              <textarea id="sf-h" bind:value={headersText} rows="2" placeholder="Accept: application/json"></textarea>
              <p class="help">Geen wachtwoorden of tokens hier: die komen in de export en de versies. Gebruik daarvoor de check "API van de tegel", met de versleutelde sleutels.</p>
            </div>
          </div>
        </details>
      {:else if checkType === 'dns'}
        <div class="grid">
          <div>
            <label class="lbl" for="sf-dns">DNS-server (IP)</label>
            <input id="sf-dns" bind:value={dnsServer} placeholder="leeg = systeem, bv. IP van AdGuard" />
          </div>
          <div>
            <label class="lbl" for="sf-exp">Verwacht IP (optioneel)</label>
            <input id="sf-exp" bind:value={dnsExpect} placeholder="192.168.0.245" />
          </div>
          <div>
            <label class="lbl" for="sf-rec">Record</label>
            <select id="sf-rec" bind:value={dnsRecord}><option value="A">A (IPv4)</option><option value="AAAA">AAAA (IPv6)</option></select>
          </div>
        </div>
      {:else if checkType === 'container'}
        <div class="grid">
          <div>
            <label class="lbl" for="sf-pt">Portainer-tegel</label>
            <select id="sf-pt" bind:value={portainerId} onchange={pickPortainer}>
              <option value={null}>kies…</option>
              {#each portainers as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
            </select>
          </div>
          <div>
            <label class="lbl" for="sf-cn">Container</label>
            <input id="sf-cn" bind:value={containerName} list="sf-containers" placeholder="bv. jellyfin" autocomplete="off" />
            <datalist id="sf-containers">{#each containers as c}<option value={c.name}>{c.state}</option>{/each}</datalist>
          </div>
        </div>
        {#if !portainers.length}<p class="help">Nog geen tegel van type portainer: maak die eerst (Integratie en API).</p>{/if}
        {#if containersError}<p class="help">Containers ophalen lukt niet: {containersError}</p>{/if}
        <p class="help">Down als de container stopt of unhealthy is. Hij hangt af van zijn Portainer-tegel, dus valt Portainer uit, dan krijg je één melding.</p>
      {:else if checkType === 'api'}
        <div class="grid">
          <div class="full">
            <label class="lbl" for="sf-ap">Pad (optioneel)</label>
            <input id="sf-ap" bind:value={apiPath} placeholder="leeg = de standaardcall van de integratie, of bv. /api/v3/system/status" />
          </div>
          <div>
            <label class="lbl" for="sf-jp2">JSON-veld (optioneel)</label>
            <div class="row nowrap">
              <input id="sf-jp2" bind:value={jsonPath} placeholder="status" />
              <input bind:value={jsonValue} placeholder="= ok" aria-label="Verwachte waarde" disabled={!jsonPath.trim()} />
            </div>
          </div>
          <div>
            <label class="lbl" for="sf-to2">Time-out (seconden)</label>
            <input id="sf-to2" type="text" inputmode="numeric" bind:value={checkTimeout} placeholder="8" />
          </div>
        </div>
        <p class="help">Roept de API van deze tegel aan met zijn eigen versleutelde sleutels (Integratie en API hieronder): zo kan je ook achter een login checken.{#if !apiId && !integ} Deze tegel heeft nog geen integratie of API.{/if}</p>
      {:else if checkType === 'push'}
        <p class="help">Een script, cronjob of automatisering roept een adres van het dashboard aan. Blijft dat uit, of meldt het <code>status=down</code>, dan gaat de tegel down. {service ? 'Het adres maak je in het mini dashboard (klik de tegel open).' : 'Sla de tegel eerst op; het adres maak je daarna in het mini dashboard (klik de tegel open).'}</p>
      {/if}
      {#if checkType}
        <div class="grid">
          <div>
            <label class="lbl" for="sf-da">Down na</label>
            <select id="sf-da" bind:value={downAfter}>
              {#each [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] as n}<option value={n}>{n} mislukte check{n === 1 ? '' : 's'} op rij</option>{/each}
            </select>
          </div>
          <div>
            <label class="lbl" for="sf-ri">Bij twijfel opnieuw na (s)</label>
            <input id="sf-ri" type="text" inputmode="numeric" bind:value={retryInterval} placeholder="leeg = gewoon interval" disabled={checkType === 'push'} />
          </div>
          <div>
            <label class="lbl" for="sf-nm">Melden</label>
            <select id="sf-nm" bind:value={notifyMode}>
              <option value="push">hier en op je gsm</option>
              <option value="centrum">alleen hier (🔔)</option>
              <option value="uit">niet (alleen de tijdlijn)</option>
            </select>
          </div>
          <div>
            <label class="lbl" for="sf-rh">Zolang down, herinneren</label>
            <select id="sf-rh" bind:value={remindHours}>
              <option value={0}>nooit</option><option value={1}>elk uur</option>
              <option value={4}>elke 4 uur</option><option value={24}>elke dag</option>
            </select>
          </div>
        </div>
        <label class="chk"><input type="checkbox" bind:checked={paused} /> check gepauzeerd (stilzetten of meldingen uitzetten vraagt je 2FA)</label>
      {/if}
      <div class="dep">
        <label class="lbl" for="sf-parent">Hangt af van (draait op)</label>
        <select id="sf-parent" bind:value={parentId}>
          <option value={null}>niets</option>
          {#each parents as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
        </select>
        <p class="help">Valt dit uit, dan krijg je één melding voor alles wat ervan afhangt, en onderhoud geldt voor allemaal.</p>
      </div>
      <div class="dep">
        <label class="lbl" for="sf-mac">MAC-adres voor Wake-on-LAN (optioneel)</label>
        <input id="sf-mac" bind:value={mac} placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" />
        <p class="help">Dan kan je de machine wekken vanuit het mini dashboard, het netwerkoverzicht (<code>net</code>) of met <code>Ctrl+K</code> → "wekken".</p>
      </div>
      {#if (zabbix?.configured || zabbixHosts) && type !== 'zabbix'}
        <div class="dep">
          <label class="lbl" for="sf-zabbix">Zabbix-hosts</label>
          <input id="sf-zabbix" bind:value={zabbixHosts} list="sf-zabbix-hosts" placeholder="automatisch (op IP, DNS-naam of naam)" autocomplete="off" />
          <datalist id="sf-zabbix-hosts">{#each zabbix?.hosts || [] as h}<option value={h}></option>{/each}</datalist>
          <p class="help">Leeg = automatisch. Of zelf kiezen met de naam in Zabbix, meerdere met komma's (<code>pve50, plex</code>), of <code>-</code> om Zabbix bij deze tegel uit te zetten.</p>
        </div>
      {/if}
      {#if checkType}
        <p class="help">Down na {downAfter} mislukte check{Number(downAfter) === 1 ? '' : 's'} op rij{Number(retryInterval) ? `; na een eerste fout opnieuw na ${retryInterval} s` : ''}. Bij HTTPS wordt ook het certificaat gevolgd (melding 14 en 3 dagen vooraf).</p>
      {/if}
    </details>

    <details class="adv" open={type !== 'link' || secretKeys.length > 0 || !!apiId}>
      <summary>Integratie en API</summary>
      <div class="grid">
        <div class="full">
          <label class="lbl" for="sf-api">API (uit API-beheer)</label>
          <select id="sf-api" bind:value={apiId}>
            <option value={null}>geen: eigen instellingen hieronder</option>
            {#each apiCats as [cat, list] (cat)}
              <optgroup label={cat}>{#each list as a (a.id)}<option value={a.id}>{a.name} · {a.kind_label}</option>{/each}</optgroup>
            {/each}
          </select>
          {#if apiSel}
            <p class="help">Adres, sleutels en calls komen van <b>{apiSel.name}</b> ({apiSel.url}). Instellingen hieronder, zoals
              <code>node</code>, vullen aan; aanpassen doe je in <code>api</code> in de titelbalk.</p>
          {:else}
            <p class="help">Stel API's één keer in via <code>api</code> in de titelbalk en kies ze hier. Of vul hieronder een type en sleutels in voor alleen deze tegel.</p>
          {/if}
        </div>
        {#if !apiId}
        <div class="full">
          <label class="lbl" for="sf-type">Type</label>
          <input id="sf-type" bind:value={type} list="sf-types" />
          <datalist id="sf-types">
            <option value="link">gewone snelkoppeling</option>
            {#each integrations as i}<option value={i.name}>{i.label}</option>{/each}
          </datalist>
          {#if integ}
            <div class="help ihelp">
              <b>{integ.label}</b>, instellingen:
              {#each Object.entries(integ.config) as [k, v]}<div><code>{k}</code> {v}</div>{/each}
              geheimen:
              {#each Object.entries(integ.secrets) as [k, v]}<div><code>{k}</code> {v}</div>{/each}
            </div>
          {:else if type && type !== 'link'}
            <p class="help">Voor dit type is er nog geen integratie; de tegel werkt als gewone snelkoppeling.</p>
          {/if}
        </div>
        {/if}
        <div class="full">
          <label class="lbl" for="sf-config">Instellingen (JSON, niet geheim)</label>
          <textarea id="sf-config" bind:value={configText} placeholder={'{\n  "url": "https://192.168.0.50:8006",\n  "node": "pve50"\n}'}></textarea>
        </div>
      </div>
      {#if !apiId}
      <span class="lbl">Geheimen (versleuteld bewaard, nooit zichtbaar in de browser)</span>
      {#each secretKeys as k (k)}
        <div class="row secret">
          <code class:gone={removed.includes(k)}>{k} = ••••••</code>
          {#if removed.includes(k)}
            <button type="button" class="mini" onclick={() => (removed = removed.filter((x) => x !== k))}>Herstel</button>
          {:else}
            <button type="button" class="mini x" onclick={() => (removed = [...removed, k])}>Wis</button>
          {/if}
        </div>
      {/each}
      {#each newSecrets as row, i}
        <div class="row nowrap secret">
          <input bind:value={row.key} placeholder="naam, bv. password" />
          <input type="password" bind:value={row.value} placeholder="waarde" autocomplete="new-password" />
          <button type="button" class="mini x" onclick={() => newSecrets.splice(i, 1)}>✕</button>
        </div>
      {/each}
      <button type="button" class="mini" onclick={() => newSecrets.push({ key: '', value: '' })}>+ geheim</button>
      {/if}
    </details>

    <p class="err">{error}</p>
    <div class="row">
      <button class="btn" disabled={busy}>Opslaan</button>
      <button type="button" class="btn alt" onclick={onclose}>Annuleren</button>
      {#if service}<button type="button" class="btn alt danger right" onclick={del}>Verwijderen</button>{/if}
    </div>
  </form>
</Modal>

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px }
  .full { grid-column: 1 / -1 }
  .nowrap { flex-wrap: nowrap }
  .prev {
    width: 40px; height: 40px; flex: none; display: grid; place-items: center; border-radius: 8px;
    background: rgba(255, 255, 255, .06); color: var(--muted)
  }
  .prev img { max-width: 30px; max-height: 30px }
  .prev img.mono { filter: invert(.85) }
  .help { margin: 6px 0 0; font-size: 11.5px; color: var(--muted); line-height: 1.5 }
  .adv { margin-top: 16px; border: 1px solid var(--line); border-radius: 12px; background: rgba(255, 255, 255, .03); padding: 0 14px 14px }
  .adv summary { cursor: pointer; padding: 12px 0 0; color: var(--text); list-style: none }
  .adv summary::before { content: "▸ "; color: var(--dim) }
  .adv[open] summary::before { content: "▾ " }
  .secret { margin-bottom: 6px }
  .tls { margin-top: 10px }
  .req { margin-top: 8px }
  .req summary { cursor: pointer; color: var(--muted); font-size: 12.5px }
  .dep { margin-top: 10px }
  .ihelp div { padding-left: 10px }
  .ihelp code { color: #d6e6ff }
  .secret code { font-size: 12.5px; color: #d6e6ff }
  .secret code.gone { text-decoration: line-through; color: var(--dim) }
  .right { margin-left: auto }
  @media (max-width: 560px) { .grid { grid-template-columns: 1fr } }
</style>
