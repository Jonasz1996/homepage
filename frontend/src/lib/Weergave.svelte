<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import { dash } from './dash.svelte.js'
  import Modal from './Modal.svelte'
  import { applyWall, shrink } from './wall.js'

  // Instellingen → Weergave: een eigen achtergrond (uploaden of van een adres), met of zonder de effecten van aiverslag
  // erboven. Geldt voor elk toestel. Of de effecten bewegen, blijft per toestel (Effecten in het menu).
  let { onclose } = $props()

  let cfg = $state(null)
  let url = $state('')
  let busy = $state(false)
  let error = $state('')
  let file = $state()
  let saveTimer

  onMount(async () => {
    try { cfg = await api('/achtergrond') } catch (e) { error = e.message }
  })

  async function run(fn) {
    busy = true; error = ''
    try {
      cfg = await fn()
      applyWall(cfg)
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  const upload = (f) => run(async () => api('/achtergrond/beeld', { method: 'POST', body: await shrink(f) }))
  const fetchUrl = () => run(() => api('/achtergrond/url', { method: 'POST', body: { url: url.trim() } }))
  const remove = () => run(() => api('/achtergrond/beeld', { method: 'DELETE' }))

  function pick(e) {
    const f = e.currentTarget.files?.[0]
    e.currentTarget.value = ''
    if (f) upload(f)
  }

  // Schuiven en vinkjes: meteen tonen, kort daarna bewaren.
  function change() {
    applyWall(cfg)
    clearTimeout(saveTimer)
    saveTimer = setTimeout(() => {
      const { effecten, dimmen, vervagen } = cfg
      api('/achtergrond', { method: 'PUT', body: { effecten, dimmen: +dimmen, vervagen: +vervagen } })
        .then((r) => { cfg = r; applyWall(r) })
        .catch((e) => { error = e.message })
    }, 400)
  }

  const when = (iso) => new Date(iso).toLocaleString('nl-BE', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
</script>

<Modal title="weergave" {onclose}>
  <h3 class="h">Achtergrond</h3>
  <p class="hint">Een eigen foto of afbeelding achter het dashboard, op elk toestel. Kies of de effecten van aiverslag
    (de radiale gloed, scanlijnen en zwevende punten) erboven komen of niet.</p>

  {#if cfg}
    {#if cfg.beeld}
      <div class="pv" style="background-image: url(&quot;{cfg.beeld.url}&quot;)">
        <span>{cfg.beeld.bron ? 'van ' + cfg.beeld.bron : 'geüpload'} · {when(cfg.beeld.sinds)}</span>
      </div>
    {:else}
      <p class="hint">Nu: de gewone achtergrond van aiverslag.</p>
    {/if}

    <span class="lbl">afbeelding uploaden</span>
    <div class="row">
      <input bind:this={file} type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif" hidden onchange={pick} />
      <button class="btn" disabled={busy} onclick={() => file.click()}>Kies een afbeelding…</button>
      {#if cfg.beeld}<button class="btn alt danger" disabled={busy} onclick={remove}>Terug naar standaard</button>{/if}
    </div>

    <label class="lbl" for="wg-url">of van een adres</label>
    <form class="row" onsubmit={(e) => { e.preventDefault(); if (url.trim()) fetchUrl() }}>
      <input id="wg-url" type="url" placeholder="https://…/achtergrond.jpg" bind:value={url} />
      <button class="btn alt" disabled={busy || !url.trim()}>Ophalen</button>
    </form>
    <p class="hint small">Het dashboard haalt de afbeelding één keer op en bewaart ze zelf (werkt ook met een adres op je
      LAN). PNG, JPEG, WebP, GIF of AVIF.</p>

    {#if busy}<p class="hint">Bezig…<span class="cur"></span></p>{/if}
    {#if error}<p class="err">{error}</p>{/if}

    {#if cfg.beeld}
      <span class="lbl">effecten erboven</span>
      <label class="chk"><input type="checkbox" bind:checked={cfg.effecten} onchange={change} />
        gloed, scanlijnen en zwevende punten over de afbeelding</label>
      {#if cfg.effecten && !dash.fx}
        <p class="hint small">Op dit toestel staan de effecten uit (menu → Effecten): dan zie je ze hier ook niet.</p>
      {/if}

      <label class="lbl" for="wg-dim">dimmen: {cfg.dimmen}%</label>
      <input id="wg-dim" class="rng" type="range" min="0" max="90" step="5" bind:value={cfg.dimmen} oninput={change} />
      <label class="lbl" for="wg-blur">vervagen: {cfg.vervagen} px</label>
      <input id="wg-blur" class="rng" type="range" min="0" max="20" step="1" bind:value={cfg.vervagen} oninput={change} />
      <p class="hint small">Dimmen houdt de tegels leesbaar op een drukke of lichte foto.</p>
    {/if}
  {:else if !error}
    <p class="hint">Laden…<span class="cur"></span></p>
  {:else}
    <p class="err">{error}</p>
  {/if}
</Modal>

<style>
  .h { margin: 0 0 4px; font-size: 14px; color: var(--text-h) }
  .pv { height: 150px; border-radius: 10px; border: 1px solid var(--line-2); background: center/cover no-repeat;
        display: flex; align-items: flex-end; margin-bottom: 6px; overflow: hidden }
  .pv span { font-size: 11.5px; padding: 4px 8px; background: rgba(0, 0, 0, .65); color: var(--muted); width: 100%;
             overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  form.row input { flex: 1 }
  .rng { width: 100%; accent-color: #bbb }
  .small { font-size: 12px; margin-top: 6px }
</style>
