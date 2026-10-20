<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'
  import Modal from './Modal.svelte'

  // Openstaande updates: nodes en PBS via hun API, machines en containers via SSH, Docker via Portainer.
  let { onclose, onchanged } = $props()

  let data = $state(null)
  let error = $state('')
  let open = $state({})
  let onlyOpen = $state(true)

  async function load() {
    try {
      const was = data?.running
      data = await api('/updates')
      error = ''
      if (was && !data.running) onchanged?.()
    } catch (e) { error = e.message }
  }
  onMount(() => { load(); return poll(() => data?.running && load(), 4000) })

  async function refresh() {
    try {
      await api('/updates/refresh', { method: 'POST' })
      await load()
    } catch (e) { error = e.message }
  }

  const KIND = { node: 'node', pbs: 'PBS', host: 'machine', ct: 'container', docker: 'docker' }
  const when = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : 'nog nooit')
  let shown = $derived((data?.targets || []).filter((t) => !onlyOpen || t.count || t.error))
</script>

<Modal title="apt list --upgradable" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if data}
    <div class="top">
      <div class="sum">
        <b>{data.total}</b> update{data.total === 1 ? '' : 's'} open
        {#if data.security}<span class="sec">· {data.security} beveiliging</span>{/if}
        <small>laatst gecontroleerd {when(data.checked_at)}</small>
      </div>
      <label class="chk"><input type="checkbox" bind:checked={onlyOpen} /> alleen met updates</label>
      <button class="mini" disabled={data.running} onclick={refresh}>{data.running ? 'bezig…' : 'nu controleren'}</button>
    </div>

    {#each shown as t (t.key)}
      <div class="tg" class:bad={t.error}>
        <button class="hd" onclick={() => (open[t.key] = !open[t.key])} disabled={!t.count}>
          <span class="nm"><b>{t.name}</b><small>{KIND[t.kind] || t.kind}{t.node ? ` op ${t.node}` : ''}{t.vmid ? ` · ${t.vmid}` : ''}</small></span>
          {#if t.error}<span class="msg">{t.error}</span>
          {:else}
            <span class="cnt" class:zero={!t.count}>{t.count ? `${t.count}${t.kind === 'docker' ? ' verouderd' : ''}` : 'bijgewerkt'}</span>
            {#if t.security}<span class="sec">{t.security} beveiliging</span>{/if}
            {#if t.count}<span class="ar">{open[t.key] ? '▾' : '▸'}</span>{/if}
          {/if}
        </button>
        {#if open[t.key] && t.count}
          <table class="pk">
            <tbody>
              {#each t.packages as p}
                <tr class:s={p.sec}><td>{p.n}</td><td class="m">{p.from || ''}</td><td>{p.to || ''}</td></tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    {:else}
      <p class="hint">
        {#if data.targets.length}Alles is bijgewerkt.{:else}Nog niets om op te volgen. Updates komen van <b>proxmox</b>-, <b>PBS</b>- en
          <b>portainer</b>-tegels, en van SSH-hosts waarbij je in de terminal <i>updates opvolgen</i> aanzet (op een Proxmox-node
          kan dat meteen voor alle containers).{/if}
      </p>
    {/each}
    <p class="hint small">Elke 6 uur gecontroleerd. Installeren doe je zelf, bv. via de terminal; daarna verschijnt het op de tijdlijn.</p>
  {:else}
    <p class="hint">laden…</p>
  {/if}
</Modal>

<style>
  .top { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 10px }
  .sum { flex: 1; font-size: 13px }
  .sum b { font-size: 18px; color: var(--text-h); font-weight: 500 }
  .sum small { display: block; color: var(--dim); font-size: 11px }
  .chk { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center }
  .chk input { width: auto }
  .sec { color: var(--mid); font-size: 12px }
  .tg { border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08); margin-bottom: 6px }
  .tg.bad { border-color: rgba(229, 139, 139, .3) }
  .hd { all: unset; box-sizing: border-box; width: 100%; display: flex; gap: 12px; align-items: center; padding: 8px 12px; cursor: pointer }
  .hd:disabled { cursor: default }
  .hd:focus-visible { outline: 1px solid var(--line-2) }
  .nm { flex: 1; min-width: 0 }
  .nm b { font-weight: 500; color: var(--text-h); font-size: 13px; margin-right: 8px }
  .nm small { color: var(--dim); font-size: 11.5px }
  .msg { color: var(--err); font-size: 12px; text-align: right }
  .cnt { color: var(--text-h); font-size: 12.5px }
  .cnt.zero { color: var(--ok) }
  .ar { color: var(--muted); font-size: 11px }
  .pk { width: 100%; border-collapse: collapse; font-size: 12px; margin: 0 0 6px }
  .pk td { padding: 3px 12px; border-top: 1px solid rgba(255, 255, 255, .05); white-space: nowrap }
  .pk td:first-child { width: 40%; white-space: normal; overflow-wrap: anywhere }
  .pk tr.s td:first-child { color: var(--mid) }
  .m { color: var(--dim) }
  .small { font-size: 11.5px; margin-top: 10px }
</style>
