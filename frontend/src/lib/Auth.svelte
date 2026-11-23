<script>
  import { api } from './api.js'
  import Card from './Card.svelte'
  import CopyCmd from './CopyCmd.svelte'

  let { auth, ondone } = $props()

  // "Kan niet inloggen?": een eigen scherm op de inlogpagina. De server geeft voor elke login een code (ook als het
  // account niet bestaat, zodat dit niets verraadt); de beheerder plakt die in homepage-beheer herstel.
  let kwijt = $state(false)
  let kwijtLogin = $state('')
  let verzoek = $state(null)

  let mode = $derived(
    auth.setup_required ? 'setup'
      : auth.user?.nieuw_wachtwoord ? 'nieuw'
      : auth.user && !auth.user.totp_enabled ? 'enroll'
      : kwijt ? 'kwijt'
      : 'login'
  )

  let username = $state('')
  let password = $state('')
  let password2 = $state('')
  // Na een fabrieksreset (Fabrieksreset.svelte) geeft de server de setup-code mee aan wie de reset deed.
  const RESET_KEY = 'hp-setup-code'
  const fromReset = (() => {
    try { return sessionStorage.getItem(RESET_KEY) || '' } catch { return '' /* privévenster */ }
  })()
  let token = $state(fromReset)
  let code = $state('')
  let needCode = $state(false)
  let busy = $state(false)
  let error = $state('')
  let enroll = $state(null)

  // Inloggen via Authentik: knop als het aan staat; een fout komt terug als ?login_error=...
  let sso = $state({ enabled: false, label: 'Authentik' })
  api('/auth/oidc').then((r) => (sso = r)).catch(() => {})
  const params = new URLSearchParams(location.search)
  if (params.has('login_error')) {
    error = params.get('login_error')
    history.replaceState(null, '', location.pathname)
  }

  async function run(fn) {
    busy = true
    error = ''
    try {
      await fn()
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  const setup = () => run(async () => {
    if (password !== password2) throw new Error('Wachtwoorden zijn niet gelijk')
    await api('/auth/setup', { method: 'POST', body: { token, username, password } })
    try { sessionStorage.removeItem(RESET_KEY) } catch { /* */ }
    ondone()
  })

  const login = () => run(async () => {
    const r = await api('/auth/login', {
      method: 'POST',
      body: { username, password, code: needCode ? code : null },
    })
    if (r.code_required) {
      needCode = true
      return
    }
    ondone()
  })

  const vraagCode = () => run(async () => {
    verzoek = await api('/auth/herstel', { method: 'POST', body: { login: kwijtLogin } })
  })

  function openKwijt() {
    kwijt = true
    kwijtLogin = kwijtLogin || username
    verzoek = null
    error = ''
  }

  function terugNaarLogin() {
    kwijt = false
    verzoek = null
    error = ''
  }

  const fmtTijd = (t) => new Date(t).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })

  const newPassword = () => run(async () => {
    if (password !== password2) throw new Error('Wachtwoorden zijn niet gelijk')
    await api('/auth/password/nieuw', { method: 'POST', body: { new: password } })
    password = password2 = ''
    ondone()
  })

  const enable = () => run(async () => {
    await api('/auth/totp/enable', { method: 'POST', body: { code } })
    ondone()
  })

  $effect(() => {
    if (mode === 'enroll' && !enroll) run(async () => (enroll = await api('/auth/totp/enroll')))
  })

  const titles = { setup: 'setup', nieuw: 'passwd', enroll: '2fa --enroll', kwijt: 'herstel', login: 'login' }
</script>

<main class="wrap">
  <Card title={titles[mode]} glow>
    <div class="body">
      {#if mode === 'setup'}
        <h1>Eerste account</h1>
        {#if fromReset}
          <p class="hint">
            Fabrieksreset klaar: het dashboard is leeg. Maak opnieuw een account aan; de setup-code staat al ingevuld.
            Daarna stel je 2FA in en kies je hoe je verder wil (importeren, Proxmox, achtergrond, ...).
          </p>
        {:else}
          <p class="hint">
            Vul de setup-code in die het installatiescript toonde
            (ook te vinden in <code>/etc/homepage/setup-token</code>).
          </p>
        {/if}
        <form onsubmit={(e) => { e.preventDefault(); setup() }}>
          <label class="lbl" for="t">Setup-code</label>
          <input id="t" bind:value={token} autocomplete="off" required />
          <label class="lbl" for="u">Gebruikersnaam</label>
          <input id="u" bind:value={username} autocomplete="username" required />
          <label class="lbl" for="p">Wachtwoord (minstens 12 tekens)</label>
          <input id="p" type="password" bind:value={password} autocomplete="new-password" minlength="12" required />
          <label class="lbl" for="p2">Herhaal wachtwoord</label>
          <input id="p2" type="password" bind:value={password2} autocomplete="new-password" required />
          <p class="err">{error}</p>
          <button class="btn" disabled={busy}>Account aanmaken</button>
        </form>
      {:else if mode === 'nieuw'}
        <h1>Kies een nieuw wachtwoord</h1>
        <p class="hint">
          Je bent ingelogd met een tijdelijk wachtwoord. Kies nu je eigen wachtwoord; daarna stel je 2FA opnieuw in
          met je authenticator-app.
        </p>
        <form onsubmit={(e) => { e.preventDefault(); newPassword() }}>
          <label class="lbl" for="np">Nieuw wachtwoord (minstens 12 tekens)</label>
          <input id="np" type="password" bind:value={password} autocomplete="new-password" minlength="12" required />
          <label class="lbl" for="np2">Herhaal wachtwoord</label>
          <input id="np2" type="password" bind:value={password2} autocomplete="new-password" required />
          <p class="err">{error}</p>
          <button class="btn" disabled={busy}>Opslaan en verder</button>
        </form>
      {:else if mode === 'kwijt'}
        <h1>Toegang herstellen</h1>
        {#if !verzoek}
          <p class="hint">
            Geef je login in. Je krijgt een code die je aan je systeembeheerder geeft; die herstelt er je account mee.
          </p>
          <form onsubmit={(e) => { e.preventDefault(); vraagCode() }}>
            <label class="lbl" for="hl">Gebruikersnaam of e-mail</label>
            <!-- svelte-ignore a11y_autofocus -->
            <input id="hl" bind:value={kwijtLogin} autocomplete="username" maxlength="254" autofocus required />
            <p class="err">{error}</p>
            <div class="row">
              <button class="btn" disabled={busy}>Code aanvragen</button>
              <button type="button" class="btn alt" onclick={terugNaarLogin}>Terug</button>
            </div>
          </form>
        {:else}
          <p class="hint">
            Je aanvraag is genoteerd. Bestaat er een account met deze login, dan kan je beheerder het met deze code
            herstellen.
          </p>
          <label class="lbl" for="hc">Je code</label>
          <pre id="hc" class="code">{verzoek.code}</pre>
          <p class="hint">
            Vraag aan je systeembeheerder om je account te herstellen door dit commando uit te voeren (als root in de
            container van het dashboard):
          </p>
          <CopyCmd cmd={verzoek.commando} />
          <p class="hint">
            Je krijgt dan een tijdelijk wachtwoord (1 uur geldig) waarmee je de toegang tot je account herstelt. Log
            ermee in, kies een nieuw wachtwoord en stel daarna 2FA opnieuw in. De code geldt één keer, tot
            {fmtTijd(verzoek.geldig_tot)}.
          </p>
          <div class="row">
            <button type="button" class="btn" onclick={terugNaarLogin}>Naar inloggen</button>
          </div>
        {/if}
      {:else if mode === 'enroll'}
        <h1>Twee-staps-verificatie</h1>
        <p class="hint">
          Scan de QR-code met je authenticator-app (Aegis, 2FAS, Google Authenticator, Vaultwarden...)
          en vul de code van 6 cijfers in. Dit is verplicht omdat het dashboard van buitenaf bereikbaar is.
        </p>
        {#if enroll}
          <div class="qr">{@html enroll.qr_svg}</div>
          <label class="lbl" for="s">Of typ deze sleutel over</label>
          <pre id="s">{enroll.secret}</pre>
        {/if}
        <form onsubmit={(e) => { e.preventDefault(); enable() }}>
          <label class="lbl" for="c">Code</label>
          <input id="c" bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="6" required />
          <p class="err">{error}</p>
          <button class="btn" disabled={busy}>Activeren</button>
        </form>
      {:else}
        <h1>Inloggen</h1>
        <p class="hint">homepage<span class="cur"></span></p>
        <form onsubmit={(e) => { e.preventDefault(); login() }}>
          {#if !needCode}
            <label class="lbl" for="u">Gebruikersnaam</label>
            <input id="u" bind:value={username} autocomplete="username" required />
            <label class="lbl" for="p">Wachtwoord</label>
            <input id="p" type="password" bind:value={password} autocomplete="current-password" required />
          {:else}
            <label class="lbl" for="c">Code uit je authenticator-app</label>
            <!-- svelte-ignore a11y_autofocus -->
            <input id="c" bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus required />
          {/if}
          <p class="err">{error}</p>
          <div class="row">
            <button class="btn" disabled={busy}>{needCode ? 'Bevestigen' : 'Inloggen'}</button>
            {#if needCode}
              <button type="button" class="btn alt" onclick={() => { needCode = false; code = ''; error = '' }}>Terug</button>
            {/if}
          </div>
        </form>
        {#if sso.enabled && !needCode}
          <div class="or"><span>of</span></div>
          <a class="btn alt sso" href="/api/auth/oidc/start">Inloggen met {sso.label}</a>
        {/if}
        {#if !needCode}
          <a class="linkbtn" href="#herstel" onclick={(e) => { e.preventDefault(); openKwijt() }}>
            Wachtwoord vergeten of kan niet inloggen?
          </a>
        {/if}
      {/if}
    </div>
  </Card>
</main>

<style>
  .wrap { max-width: 460px; margin: min(12vh, 120px) auto 40px; padding: 0 14px }
  .qr { display: flex; justify-content: center; margin: 6px 0 4px }
  .qr :global(svg) { width: 220px; height: 220px }
  form .btn { margin-top: 4px }
  .or { display: flex; align-items: center; gap: 10px; color: var(--dim); font-size: 11.5px; margin: 16px 0 10px }
  .or::before, .or::after { content: ''; flex: 1; height: 1px; background: var(--line) }
  .sso { display: block; text-align: center; text-decoration: none }
  .linkbtn { display: block; width: fit-content; margin: 14px auto 0; color: var(--dim); font-size: 12px;
             text-decoration: underline; cursor: pointer }
  .linkbtn:hover { color: var(--text-h) }
  .code { font-size: 20px; letter-spacing: 1px; text-align: center; color: var(--text-h); user-select: all }
</style>
