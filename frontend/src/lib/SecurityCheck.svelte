<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'

  // Veiligheidscheck (hw → beveiliging): 2FA, secret.key, kopie buiten de container, sessies van buitenaf,
  // wat er van buitenaf mag, het slot voor het dashboard, de SSH-sleutel en de rechten van de Proxmox-tokens.
  let { onfix } = $props()
  let data = $state(null)
  let error = $state('')
  let busy = $state(false)

  async function load() {
    busy = true
    try { data = await api('/security/check'); error = '' } catch (e) { error = e.message } finally { busy = false }
  }
  onMount(load)

  async function saved() {
    if (!confirm('Heb je /etc/homepage/secret.key op een veilige plek buiten de container bewaard (bv. in je wachtwoordkluis)?')) return
    try { await withReauth(() => api('/security/secret-key-saved', { method: 'POST' })); await load() } catch (e) { error = e.message }
  }

  const ICON = { ok: '✓', info: 'i', warn: '!', err: '✕' }
  const FIX = { security: 'openen', net: 'openen', api: 'API-beheer', 'ssh-keys': 'sleutels', health: 'openen' }
  const flag = (cc) => (cc ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '')
  let counts = $derived(data ? data.checks.reduce((a, c) => ({ ...a, [c.level]: (a[c.level] || 0) + 1 }), {}) : {})
</script>

<div class="head">
  <span class="hint">Wat er aan de beveiliging van het dashboard nog beter kan.
    {#if data}{counts.ok || 0} in orde{counts.warn ? `, ${counts.warn} opletten` : ''}{counts.err ? `, ${counts.err} probleem` : ''}.{/if}</span>
  <button class="mini" disabled={busy} onclick={load}>{busy ? 'bezig…' : '⟳ opnieuw'}</button>
</div>
{#if error}<p class="err">{error}</p>{/if}
{#each data?.checks || [] as c (c.key)}
  <div class="chk lv-{c.level}">
    <span class="ic" aria-hidden="true">{ICON[c.level]}</span>
    <div class="tx">
      <b>{c.title}</b>
      <p>{c.text}</p>
      {#if c.key === 'tokens'}
        {#each c.items as t}<div class="sub lv-{t.level}"><i></i><span><b>{t.name}</b> {t.text}</span></div>{/each}
      {:else if c.key === 'sessions'}
        {#each c.items as s}<div class="sub"><span>{flag(s.country)} {s.ip}{s.country ? ` · ${s.country}` : ''} · {s.user_agent}</span></div>{/each}
      {/if}
    </div>
    {#if c.fix?.action === 'secret_saved'}
      <button class="mini" onclick={saved}>ik heb een kopie</button>
    {:else if c.fix?.window}
      <button class="mini" onclick={() => onfix?.(c.fix)}>{FIX[c.fix.window] || 'openen'}</button>
    {/if}
  </div>
{/each}

<style>
  .head { display: flex; gap: 10px; align-items: center; margin-bottom: 8px }
  .head .hint { flex: 1; margin: 0 }
  .chk { display: flex; gap: 12px; align-items: flex-start; padding: 10px 12px; border: 1px solid var(--line);
         border-left: 3px solid var(--ok); border-radius: 10px; margin-bottom: 6px; background: var(--fill) }
  .chk.lv-info { border-left-color: var(--line-2) }
  .chk.lv-warn { border-left-color: var(--mid) }
  .chk.lv-err { border-left-color: var(--err) }
  .ic { width: 18px; height: 18px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; flex-shrink: 0;
        color: var(--ok); border: 1px solid currentColor; margin-top: 1px }
  .lv-info .ic { color: var(--muted) }
  .lv-warn .ic { color: var(--mid) }
  .lv-err .ic { color: var(--err) }
  .tx { flex: 1; min-width: 0 }
  .tx b { color: var(--text-h); font-weight: 500; font-size: 13px }
  .tx p { margin: 2px 0 0; color: var(--text); font-size: 12.5px; line-height: 1.5 }
  .sub { display: flex; gap: 8px; align-items: baseline; font-size: 12px; color: var(--muted); margin-top: 4px }
  .sub b { font-size: 12px }
  .sub i { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); flex-shrink: 0 }
  .sub.lv-info i { background: var(--muted) }
  .sub.lv-warn i { background: var(--mid) }
  .sub.lv-err i { background: var(--err) }
  .chk > .mini { flex-shrink: 0 }
</style>
