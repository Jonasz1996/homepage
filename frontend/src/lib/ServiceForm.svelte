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
  let checkType = $state(s.check?.type || '')
  let checkTarget = $state(s.check?.target || '')
  let checkInterval = $state(s.check?.interval || 60)
  let checkInsecure = $state(!!s.check?.insecure)
  let keyword = $state(s.check?.keyword || '')
  let keywordAbsent = $state(!!s.check?.keyword_absent)
  let jsonPath = $state(s.check?.json_path || '')
  let jsonValue = $state(s.check?.json_value ?? '')
  let dnsServer = $state(s.check?.dns_server || '')
  let dnsExpect = $state(s.check?.expect || '')
  let parentId = $state(s.parent_id ?? null)
  // Kandidaten voor "hangt af van": alles behalve zichzelf.
  let parents = $derived(services.filter((x) => x.id !== s.id).sort((a, b) => a.name.localeCompare(b.name)))
  // MAC-adres (Wake-on-LAN) heeft een eigen veld; de rest van config staat als JSON.
  const { mac: initialMac, ...restConfig } = s.config || {}
  let mac = $state(initialMac || '')
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

  let preview = $derived(iconUrl(icon))
  $effect(() => { preview; iconBroken = false })

  function buildBody() {
    let config = {}
    if (configText.trim()) {
      try { config = JSON.parse(configText) } catch { throw new Error('Instellingen zijn geen geldige JSON') }
    }
    delete config.mac
    if (mac.trim()) {
      if (!/^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$/i.test(mac.trim())) throw new Error('MAC-adres klopt niet (bv. aa:bb:cc:dd:ee:ff)')
      config.mac = mac.trim()
    }
    const check = checkType
      ? {
          type: checkType,
          target: checkTarget || null,
          interval: Math.max(15, Number(checkInterval) || 60),
          ...(checkType === 'http' && checkInsecure ? { insecure: true } : {}),
          ...(checkType === 'http' && keyword.trim() ? { keyword: keyword.trim(), keyword_absent: keywordAbsent } : {}),
          ...(checkType === 'http' && jsonPath.trim() ? { json_path: jsonPath.trim(), json_value: String(jsonValue).trim() } : {}),
          ...(checkType === 'dns' && dnsServer.trim() ? { dns_server: dnsServer.trim() } : {}),
          ...(checkType === 'dns' && dnsExpect.trim() ? { expect: dnsExpect.trim() } : {}),
        }
      : {}
    const secrets = {}
    for (const k of removed) secrets[k] = null
    for (const row of newSecrets) if (row.key.trim() && row.value) secrets[row.key.trim()] = row.value
    return {
      group_id, name, url: url || null, icon: icon || null, description: description || null,
      type: type || 'link', check, config, parent_id: parentId || null,
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
          </select>
        </div>
        <div>
          <label class="lbl" for="sf-ci">Interval (seconden)</label>
          <input id="sf-ci" type="text" inputmode="numeric" bind:value={checkInterval} disabled={!checkType} />
        </div>
        <div class="full">
          <label class="lbl" for="sf-target">Doel</label>
          <input id="sf-target" bind:value={checkTarget} disabled={!checkType}
                 placeholder={checkType === 'tcp' ? 'leeg = host en poort uit de URL, of 192.168.0.10:22' : checkType === 'ping' ? 'leeg = host uit de URL, of 192.168.0.10' : checkType === 'dns' ? 'leeg = naam uit de URL' : 'leeg = de URL hierboven'} />
        </div>
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
        </div>
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
        </div>
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
      <p class="help">Een service is pas down na 3 mislukte checks op rij. Bij HTTPS wordt ook het certificaat gevolgd (melding 14 en 3 dagen vooraf).</p>
    </details>

    <details class="adv" open={type !== 'link' || secretKeys.length > 0}>
      <summary>Integratie en API</summary>
      <div class="grid">
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
        <div class="full">
          <label class="lbl" for="sf-config">Instellingen (JSON, niet geheim)</label>
          <textarea id="sf-config" bind:value={configText} placeholder={'{\n  "url": "https://192.168.0.50:8006",\n  "node": "pve50"\n}'}></textarea>
        </div>
      </div>
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
  .dep { margin-top: 10px }
  .ihelp div { padding-left: 10px }
  .ihelp code { color: #d6e6ff }
  .secret code { font-size: 12.5px; color: #d6e6ff }
  .secret code.gone { text-decoration: line-through; color: var(--dim) }
  .right { margin-left: auto }
  @media (max-width: 560px) { .grid { grid-template-columns: 1fr } }
</style>
