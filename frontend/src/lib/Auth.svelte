<script>
  import { api } from './api.js'
  import Card from './Card.svelte'

  let { auth, ondone } = $props()

  let mode = $derived(
    auth.setup_required ? 'setup' : auth.user && !auth.user.totp_enabled ? 'enroll' : 'login'
  )

  let username = $state('')
  let password = $state('')
  let password2 = $state('')
  let token = $state('')
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

  const enable = () => run(async () => {
    await api('/auth/totp/enable', { method: 'POST', body: { code } })
    ondone()
  })

  $effect(() => {
    if (mode === 'enroll' && !enroll) run(async () => (enroll = await api('/auth/totp/enroll')))
  })

  const titles = { setup: 'setup', enroll: '2fa --enroll', login: 'login' }
</script>

<main class="wrap">
  <Card title={titles[mode]} glow>
    <div class="body">
      {#if mode === 'setup'}
        <h1>Eerste account</h1>
        <p class="hint">
          Vul de setup-code in die het installatiescript toonde
          (ook te vinden in <code>/etc/homepage/setup-token</code>).
        </p>
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
</style>
