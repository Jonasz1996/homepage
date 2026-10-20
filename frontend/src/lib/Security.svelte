<script>
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Beveiliging: waar je ingelogd bent, wat er gebeurd is (auditlog) en je wachtwoord.
  let { onclose } = $props()

  let tab = $state('sessions')
  let sessions = $state([])
  let audit = $state([])
  let more = $state(false)
  let filter = $state('')
  let error = $state('')
  let pw = $state({ current: '', new: '', again: '' })
  let pwMsg = $state('')
  let sso = $state(null)
  let ssoSecret = $state('')
  let ssoMsg = $state('')

  async function loadSessions() {
    try { sessions = await api('/auth/sessions'); error = '' } catch (e) { error = e.message }
  }
  async function loadAudit(append = false) {
    const p = new URLSearchParams({ limit: 100 })
    if (filter) p.set('action', filter)
    if (append && audit.length) p.set('before_id', audit[audit.length - 1].id)
    try {
      const r = await api('/auth/audit?' + p)
      audit = append ? [...audit, ...r.items] : r.items
      more = r.more
      error = ''
    } catch (e) {
      error = e.message
    }
  }

  $effect(() => {
    if (tab === 'sessions') loadSessions()
    else if (tab === 'audit') { filter; loadAudit() }
    else if (tab === 'sso') loadSso()
  })

  async function revoke(s) {
    try {
      await withReauth(() => api(`/auth/sessions/${s.id}`, { method: 'DELETE' }))
      await loadSessions()
    } catch (e) { error = e.message }
  }
  async function revokeOthers() {
    if (!confirm('Alle andere apparaten afmelden?')) return
    try {
      await withReauth(() => api('/auth/sessions/revoke-others', { method: 'POST' }))
      await loadSessions()
    } catch (e) { error = e.message }
  }
  async function loadSso() {
    try { sso = await api('/auth/oidc/settings'); ssoSecret = ''; error = '' } catch (e) { error = e.message }
  }
  async function saveSso(e) {
    e.preventDefault()
    ssoMsg = ''
    const body = { ...sso, client_secret: ssoSecret ? ssoSecret : null }
    for (const k of ['has_secret', 'redirect_uri']) delete body[k]
    try {
      sso = await withReauth(() => api('/auth/oidc/settings', { method: 'PUT', body }))
      ssoSecret = ''
      ssoMsg = sso.enabled ? 'Opgeslagen. Op het loginscherm staat nu een knop.' : 'Opgeslagen (staat uit).'
      error = ''
    } catch (err) { error = err.message }
  }
  async function changePw(e) {
    e.preventDefault()
    pwMsg = ''
    if (pw.new !== pw.again) { error = 'De nieuwe wachtwoorden zijn niet gelijk'; return }
    try {
      await api('/auth/password', { method: 'POST', body: { current: pw.current, new: pw.new } })
      pw = { current: '', new: '', again: '' }
      pwMsg = 'Wachtwoord gewijzigd. Andere apparaten zijn afgemeld.'
      error = ''
    } catch (err) { error = err.message }
  }

  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  function ago(ts) {
    const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
    if (m < 6) return 'nu actief'
    if (m < 60) return `${m} min geleden`
    if (m < 48 * 60) return `${Math.floor(m / 60)} u geleden`
    return `${Math.floor(m / 1440)} dagen geleden`
  }
  // Vlag-emoji uit een landcode (BE → 🇧🇪).
  const flag = (cc) => (cc ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '')
  function device(ua) {
    if (!ua) return 'onbekend apparaat'
    const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows'
      : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : ''
    const br = /wv\)/.test(ua) ? 'app' : /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox'
      : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ''
    return [br, os].filter(Boolean).join(' op ') || ua.slice(0, 60)
  }

  const LABELS = {
    login: 'ingelogd', login_failed: 'login mislukt', login_failed_totp: 'login mislukt (2FA)', logout: 'uitgelogd',
    setup: 'account aangemaakt', totp_enabled: '2FA ingeschakeld', reauth_failed: 'bevestiging mislukt',
    password_changed: 'wachtwoord gewijzigd', session_revoked: 'sessie afgemeld', sessions_revoked: 'andere sessies afgemeld',
    integration_action: 'actie', integration_action_failed: 'actie mislukt', service_deleted: 'service verwijderd',
    service_secrets_changed: 'geheimen gewijzigd', import: 'import', npm_import: 'NPM-import',
    ssh_defaults_changed: 'standaard SSH-login gewijzigd', ssh_hosts_imported: 'SSH-hosts uit Proxmox', ssh_snippets_changed: 'snippets gewijzigd',
    cron_monitor: 'cronjob bewaken aan/uit', cron_run: 'cronjob zelf gestart', cron_job_changed: 'cronjob aangepast',
    ssh_open: 'terminal geopend', ssh_close: 'terminal gesloten', ssh_key_added: 'SSH-sleutel toegevoegd',
    ssh_key_deleted: 'SSH-sleutel verwijderd', ssh_host_added: 'SSH-host toegevoegd', ssh_host_changed: 'SSH-host gewijzigd',
    ssh_host_deleted: 'SSH-host verwijderd', ssh_hostkey_accepted: 'hostsleutel aanvaard',
    ssh_hostkey_mismatch: 'hostsleutel klopt niet!', ssh_hostkey_forgotten: 'hostsleutel vergeten',
    syslog_rollout: 'rsyslog uitgerold', login_failed_oidc: 'login via Authentik mislukt', oidc_settings_changed: 'Authentik-instellingen gewijzigd', maintenance: 'onderhoud', revision_restored: 'versie teruggezet',
    page_deleted: 'pagina verwijderd', group_deleted: 'groep verwijderd', log_rule_added: 'logregel toegevoegd',
    log_rule_changed: 'logregel gewijzigd', log_rule_deleted: 'logregel verwijderd', wol: 'Wake-on-LAN',
  }
  const BAD = /failed|mismatch|revoked|deleted/
  const detail = (d) => Object.entries(d || {}).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join('  ')
</script>

<Modal title="cat /var/log/auth.log" {onclose} wide>
  <div class="tabs">
    <button class="mini" class:on={tab === 'sessions'} onclick={() => (tab = 'sessions')}>sessies</button>
    <button class="mini" class:on={tab === 'audit'} onclick={() => (tab = 'audit')}>auditlog</button>
    <button class="mini" class:on={tab === 'password'} onclick={() => (tab = 'password')}>wachtwoord</button>
    <button class="mini" class:on={tab === 'sso'} onclick={() => (tab = 'sso')}>authentik</button>
  </div>
  <p class="err">{error}</p>

  {#if tab === 'sessions'}
    {#each sessions as s (s.id)}
      <div class="sess" class:me={s.current}>
        <div class="who">
          <b>{flag(s.country)} {device(s.user_agent)}</b>
          <small>{s.ip || '?'}{s.country ? ` · ${s.country}` : ''} · ingelogd {when(s.created_at)}</small>
        </div>
        <span class="seen" class:live={s.current}>{s.current ? 'dit apparaat' : ago(s.last_seen_at)}</span>
        {#if !s.current}<button class="mini x" onclick={() => revoke(s)}>afmelden</button>{/if}
      </div>
    {/each}
    {#if sessions.length > 1}
      <div class="row foot"><button class="btn alt" onclick={revokeOthers}>Alle andere apparaten afmelden</button></div>
    {/if}
    <p class="hint">Land komt van Cloudflare. Een onbekend apparaat? Meld het af en wijzig je wachtwoord.</p>
  {:else if tab === 'audit'}
    <div class="row">
      <select bind:value={filter} aria-label="Soort">
        <option value="">alles</option>
        <option value="login">logins</option>
        <option value="login_failed">mislukte logins</option>
        <option value="integration_action">acties</option>
        <option value="ssh">terminal en sleutels</option>
        <option value="session">sessies</option>
      </select>
    </div>
    <table class="tbl">
      <thead><tr><th>tijd</th><th>wat</th><th>ip</th><th>details</th></tr></thead>
      <tbody>
        {#each audit as a (a.id)}
          <tr>
            <td class="nw">{when(a.ts)}</td>
            <td class:bad={BAD.test(a.action)}>{LABELS[a.action] || a.action}</td>
            <td class="nw m">{a.ip || ''}</td>
            <td class="m">{detail(a.detail)}</td>
          </tr>
        {:else}
          <tr><td colspan="4" class="m">Niets gevonden.</td></tr>
        {/each}
      </tbody>
    </table>
    {#if more}<button class="mini more" onclick={() => loadAudit(true)}>meer laden</button>{/if}
  {:else if tab === 'sso'}
    {#if sso}
      <form onsubmit={saveSso}>
        <label class="chk"><input type="checkbox" bind:checked={sso.enabled} /> inloggen via Authentik toestaan</label>
        <label class="lbl" for="oi-iss">Issuer (OpenID Configuration Issuer van de provider)</label>
        <input id="oi-iss" bind:value={sso.issuer} placeholder="https://auth.jbogaert.be/application/o/homepage/" />
        <div class="two">
          <div>
            <label class="lbl" for="oi-id">Client ID</label>
            <input id="oi-id" bind:value={sso.client_id} autocomplete="off" />
          </div>
          <div>
            <label class="lbl" for="oi-sec">Client secret {sso.has_secret ? '(ingesteld, leeg = behouden)' : ''}</label>
            <input id="oi-sec" type="password" bind:value={ssoSecret} autocomplete="new-password" />
          </div>
          <div>
            <label class="lbl" for="oi-lbl">Opschrift van de knop</label>
            <input id="oi-lbl" bind:value={sso.label} maxlength="40" />
          </div>
          <div>
            <label class="lbl" for="oi-claim">Gebruikersnaam uit claim</label>
            <input id="oi-claim" bind:value={sso.username_claim} />
          </div>
        </div>
        <label class="chk"><input type="checkbox" bind:checked={sso.require_mfa} /> Authentik moet 2FA melden (amr-claim), anders weigeren</label>
        <label class="chk"><input type="checkbox" bind:checked={sso.insecure} /> zelfondertekend certificaat aanvaarden</label>
        <p class="hint">Redirect-URI om in Authentik in te vullen: <code class="uri">{sso.redirect_uri}</code><br />
          Alleen bestaande gebruikers kunnen zo inloggen: de gebruikersnaam bij Authentik moet dezelfde zijn als hier.
          Je eigen wachtwoord en 2FA blijven ook gewoon werken.</p>
        {#if ssoMsg}<p class="ok">{ssoMsg}</p>{/if}
        <div class="row foot"><button class="btn">Opslaan</button></div>
      </form>
    {/if}
  {:else}
    <form onsubmit={changePw}>
      <label class="lbl" for="pw-cur">Huidig wachtwoord</label>
      <input id="pw-cur" type="password" bind:value={pw.current} autocomplete="current-password" required />
      <label class="lbl" for="pw-new">Nieuw wachtwoord (minstens 12 tekens)</label>
      <input id="pw-new" type="password" bind:value={pw.new} autocomplete="new-password" minlength="12" required />
      <label class="lbl" for="pw-again">Nog eens</label>
      <input id="pw-again" type="password" bind:value={pw.again} autocomplete="new-password" minlength="12" required />
      {#if pwMsg}<p class="ok">{pwMsg}</p>{/if}
      <div class="row foot"><button class="btn">Wachtwoord wijzigen</button></div>
    </form>
  {/if}
</Modal>

<style>
  .tabs { display: flex; gap: 6px }
  .sess { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border-radius: 10px; background: var(--fill);
          border: 1px solid rgba(255, 255, 255, .08); margin-bottom: 6px }
  .sess.me { border-color: rgba(143, 214, 164, .45) }
  .who { flex: 1; min-width: 0 }
  .who b { display: block; font-weight: 500; color: var(--text-h); font-size: 13px }
  .who small { color: var(--muted); font-size: 11.5px }
  .seen { color: var(--muted); font-size: 12px; white-space: nowrap }
  .seen.live { color: var(--ok) }
  .foot { margin-top: 12px }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 10px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05); vertical-align: top; word-break: break-word }
  .nw { white-space: nowrap }
  .m { color: var(--muted) }
  .bad { color: var(--err) }
  .more { margin-top: 10px }
  select { width: auto }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px }
  .chk { display: flex; gap: 8px; align-items: center; font-size: 12.5px; color: var(--text); margin: 10px 0 }
  .chk input { width: auto }
  .uri { color: var(--ok); word-break: break-all }
  @media (max-width: 560px) { .two { grid-template-columns: 1fr } }
</style>
