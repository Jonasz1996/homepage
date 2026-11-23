<script>
  import { onMount } from 'svelte'
  import { api, ApiError, requestReauth, withReauth } from './api.js'
  import { ask } from './dialog.svelte.js'
  import Modal from './Modal.svelte'
  import { forgetWall } from './wall.js'

  // Instellingen → Fabrieksreset: alles wissen en terug naar de eerste start. Eerst een back-up aanbieden, dan de
  // zin WIS ALLES laten typen, dan nog eens vragen. Alleen thuis (de server weigert het van buitenaf hoe dan ook).
  let { onclose } = $props()

  let info = $state(null)
  let error = $state('')
  let busy = $state('')
  let backedUp = $state(false)
  let skip = $state(false)
  let zin = $state('')

  onMount(async () => {
    try { info = await api('/fabrieksreset') } catch (e) { error = e.message }
  })

  const n = (x) => Number(x || 0).toLocaleString('nl-BE')
  const when = (iso) => new Date(iso).toLocaleString('nl-BE', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
  const mb = (b) => (b / 1048576).toLocaleString('nl-BE', { maximumFractionDigits: 1 }) + ' MB'

  // Binair, dus niet via api(): zelf ophalen en als bestand bewaren. Vraagt de server een verse 2FA: één keer vragen.
  async function getBackup() {
    const once = async () => {
      const r = await fetch('/api/fabrieksreset/backup', { headers: { 'X-Requested-With': 'homepage' }, credentials: 'same-origin' })
      if (!r.ok) {
        let msg = `Mislukt (fout ${r.status})`
        try { msg = (await r.json()).detail || msg } catch { /* geen JSON */ }
        throw new ApiError(msg, r.status)
      }
      const name = /filename="?([^";]+)/.exec(r.headers.get('content-disposition') || '')?.[1] || 'homepage-voor-reset.dump'
      return { blob: await r.blob(), name }
    }
    busy = 'backup'; error = ''
    try {
      let res
      try { res = await once() } catch (e) {
        if (!(e instanceof ApiError && e.status === 403 && e.message === 'reauth_required')) throw e
        await requestReauth()
        res = await once()
      }
      const a = document.createElement('a')
      a.href = URL.createObjectURL(res.blob)
      a.download = res.name
      document.body.append(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(a.href), 10000)
      backedUp = true
    } catch (e) {
      error = e.message
    } finally {
      busy = ''
    }
  }

  // Via api(): een gewone downloadlink werkt zonder login niet op http://IP (zie PageView).
  async function exportYaml() {
    try {
      const text = await api('/export')
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/yaml' }))
      a.download = 'homepage-export.yaml'
      document.body.append(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(a.href), 1000)
      backedUp = true
    } catch (e) { error = e.message }
  }

  async function wipe() {
    if (zin.trim().toUpperCase() !== info.zin) return
    const ok = await ask('Echt alles wissen? Tegels, pagina\'s, API\'s en geheimen, SSH, geschiedenis, meldingen, instellingen en je account. Dit kan je niet ongedaan maken, alleen met een back-up terugzetten.',
      { ok: 'Alles wissen', danger: true })
    if (!ok) return
    busy = 'reset'; error = ''
    try {
      const r = await withReauth(() => api('/fabrieksreset', { method: 'POST', body: { zin: zin.trim() } }))
      try { if (r.setup_code) sessionStorage.setItem('hp-setup-code', r.setup_code) } catch { /* privévenster */ }
      forgetWall()
      location.replace('/')
    } catch (e) {
      error = e.message
      busy = ''
    }
  }
</script>

<Modal title="fabrieksreset" {onclose}>
  <p class="hint">Het hele dashboard wissen en opnieuw beginnen zoals na de installatie: account aanmaken, 2FA, en dan
    een leeg dashboard met de eerste stappen. De container zelf blijft zoals hij is.</p>

  {#if error}<p class="err">{error}</p>{/if}

  {#if info && !info.thuis}
    <p class="warn">Je bent nu van buitenaf verbonden. Een fabrieksreset kan alleen thuis (op het LAN of via VPN), ook
      met een echte login.</p>
  {:else if info}
    <h3 class="h">Wat weg gaat</h3>
    <ul class="list">
      <li>{n(info.telling.paginas)} pagina's met {n(info.telling.tegels)} tegels, hun checks, notities en API-velden</li>
      <li>{n(info.telling.apis)} API's met hun sleutels, {n(info.telling.ssh_hosts)} SSH-hosts met sleutels en logins</li>
      <li>alle geschiedenis: {n(info.telling.checks)} checks, {n(info.telling.logregels)} logregels, {n(info.telling.meldingen)} meldingen, tijdlijn, metingen</li>
      <li>cronjobs, zelfherstel, webhooks, gsm's, onderhoud, instellingen van buitenaf en aanmelden, de achtergrond</li>
      <li>je account, 2FA en alle sessies (ook op je andere toestellen)</li>
    </ul>
    <p class="hint small">Wat blijft: de bestanden op de container (<code>/etc/homepage</code> met secret.key en de
      setup-code, de dagelijkse back-ups in <code>{info.backup_dir}</code>). Op je machines blijft alles staan
      (rsyslog, cronjobs zelf, SSH-sleutels in authorized_keys).</p>

    <h3 class="h">1. Eerst een back-up</h3>
    {#if info.laatste_backup}
      <p class="hint small">Laatste dagelijkse back-up op de container: {info.laatste_backup.name}
        ({when(info.laatste_backup.at)}, {mb(info.laatste_backup.size)}).</p>
    {:else}
      <p class="hint small">Op de container staat nog geen dagelijkse back-up.</p>
    {/if}
    <div class="row">
      {#if info.backup_download}
        <button class="btn" disabled={!!busy} onclick={getBackup}>
          {busy === 'backup' ? 'Back-up maken…' : 'Volledige back-up downloaden'}
        </button>
      {/if}
      <button class="btn alt" disabled={!!busy} onclick={exportYaml}>Alleen de tegels (YAML)</button>
    </div>
    <p class="hint small">De volledige back-up is een pg_dump zoals de dagelijkse (alles behalve de logregels, geheimen
      versleuteld): terugzetten gaat zoals in het noodplan (Infrastructuur → Noodplan, sectie 8), met dezelfde
      <code>/etc/homepage/secret.key</code>. De YAML met alleen de tegels kan je na de reset gewoon importeren (zonder
      geheimen).</p>
    {#if backedUp}<p class="ok small">Back-up gedownload.</p>{/if}
    <label class="chk"><input type="checkbox" bind:checked={skip} /> ik heb een back-up, of ik wil er geen</label>

    <h3 class="h">2. Bevestigen</h3>
    <label class="lbl" for="fr-zin">typ {info.zin}</label>
    <form class="row" onsubmit={(e) => { e.preventDefault(); wipe() }}>
      <input id="fr-zin" bind:value={zin} autocomplete="off" spellcheck="false" placeholder={info.zin} disabled={!(backedUp || skip)} />
      <button class="btn danger" disabled={!!busy || !(backedUp || skip) || zin.trim().toUpperCase() !== info.zin}>
        {busy === 'reset' ? 'Wissen…' : 'Alles wissen'}
      </button>
    </form>
  {:else if !error}
    <p class="hint">Laden…<span class="cur"></span></p>
  {/if}
</Modal>

<style>
  .h { margin: 18px 0 4px; font-size: 14px; color: var(--text-h) }
  .list { margin: 6px 0; padding-left: 18px; font-size: 13px; line-height: 1.7; color: var(--text) }
  .small { font-size: 12px; margin-top: 6px }
  .warn { color: var(--mid); font-size: 13px; line-height: 1.6 }
  form.row input { flex: 1 }
  .btn.danger { background: #8a3b3b; color: #fff }
  .btn.danger:hover:not(:disabled) { background: #a84a4a }
</style>
