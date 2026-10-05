<script>
  import { onMount, untrack } from 'svelte'
  import { api, poll } from './api.js'
  import { AREA, FIX_LABEL } from './attention.js'
  import Modal from './Modal.svelte'

  // Aandacht: alles wat nu mis is, gesorteerd op ernst (tabblad nu), en per functie of ze werkt,
  // half ingesteld is of nog niet (tabblad instellingen). Elke knop opent het venster dat het oplost.
  let { tab: startTab = 'nu', data: initial = null, onclose, onfix, onchanged } = $props()
  let tab = $state(untrack(() => startTab) || 'nu')
  let data = $state.raw(untrack(() => initial))
  let setup = $state.raw(null)
  let error = $state('')
  let busy = $state('')
  let showIgnored = $state(false)
  let hideOk = $state(false)

  async function load() {
    try { data = await api('/attention'); onchanged?.(data); error = '' } catch (e) { error = e.message }
  }
  async function loadSetup() {
    busy = 'setup'
    try { setup = await api('/attention/setup'); error = '' } catch (e) { error = e.message } finally { busy = '' }
  }
  async function ignore(i, on = true) {
    busy = i.key
    try {
      data = await api('/attention/ignore', { method: 'PUT', body: { key: i.key, sig: on ? i.sig : null } })
      onchanged?.(data)
    } catch (e) { error = e.message } finally { busy = '' }
  }
  $effect(() => { if (tab === 'instellingen' && !setup) untrack(loadSetup) })
  onMount(() => {
    load()
    return poll(load, 60000)
  })

  const LEVEL = { err: 'probleem', warn: 'opletten', info: 'ter info' }
  const STATE = { ok: 'werkt', half: 'half', none: 'nog niet' }
  let summary = $derived.by(() => {
    if (!data) return ''
    const c = data.counts
    const parts = [c.err && `${c.err} probleem${c.err > 1 ? 'en' : ''}`, c.warn && `${c.warn} om op te letten`,
                   c.info && `${c.info} ter info`].filter(Boolean)
    return parts.length ? `${parts.join(', ')}.` : 'Alles in orde.'
  })
  let groups = $derived((setup?.groups || []).map((g) => ({ ...g, rows: hideOk ? g.rows.filter((r) => r.state !== 'ok') : g.rows }))
    .filter((g) => g.rows.length))
</script>

<Modal title="systemctl --failed" {onclose} wide>
  <div class="tabs">
    <button class="mini" class:on={tab === 'nu'} onclick={() => (tab = 'nu')}>nu{#if data?.counts.err + data?.counts.warn}<b class="n" class:e={data.counts.err}>{data.counts.err + data.counts.warn}</b>{/if}</button>
    <button class="mini" class:on={tab === 'instellingen'} onclick={() => (tab = 'instellingen')}>instellingen{#if setup?.counts.half + setup?.counts.none}<b class="n">{setup.counts.half + setup.counts.none}</b>{/if}</button>
  </div>
  {#if error}<p class="err">{error}</p>{/if}

  {#if tab === 'nu'}
    {#if !data}
      <p class="hint">Laden…</p>
    {:else}
      <p class="hint top">{summary}{data.items.length ? ' Elke knop opent het venster waar je het oplost.' : ' Niets dat nu je aandacht vraagt.'}</p>
      {#each data.items as i (i.key)}
        <div class="it lv-{i.level}">
          <span class="dot" title={LEVEL[i.level]}></span>
          <div class="tx">
            <b>{i.title}</b> <span class="area">{AREA[i.area] || i.area}</span>
            {#if i.text}<p>{i.text}</p>{/if}
          </div>
          <div class="btns">
            {#if i.fix}<button class="mini" onclick={() => onfix(i.fix)}>{FIX_LABEL[i.fix.window] || 'openen'}</button>{/if}
            <button class="mini dim" disabled={busy === i.key} onclick={() => ignore(i)} title="Verbergen tot het verandert of opgelost is">negeren</button>
          </div>
        </div>
      {/each}
      {#if data.ignored.length}
        <button class="mini more" onclick={() => (showIgnored = !showIgnored)}>{showIgnored ? '▾' : '▸'} genegeerd ({data.ignored.length})</button>
        {#if showIgnored}
          {#each data.ignored as i (i.key)}
            <div class="it ign lv-{i.level}">
              <span class="dot"></span>
              <div class="tx"><b>{i.title}</b> <span class="area">{AREA[i.area] || i.area}</span>{#if i.text}<p>{i.text}</p>{/if}</div>
              <div class="btns"><button class="mini" disabled={busy === i.key} onclick={() => ignore(i, false)}>terugzetten</button></div>
            </div>
          {/each}
        {/if}
      {/if}
    {/if}
  {:else}
    <div class="head">
      <p class="hint">
        {#if setup}
          {setup.counts.ok} werken{setup.counts.half ? `, ${setup.counts.half} half ingesteld` : ''}{setup.counts.none ? `, ${setup.counts.none} nog niet` : ''}{setup.counts.optional ? `, ${setup.counts.optional} optioneel nog niet` : ''}.
        {:else}Nakijken: de API's van je tegels en de rechten van je Proxmox-tokens…{/if}
      </p>
      <label class="chk"><input type="checkbox" bind:checked={hideOk} /> verberg wat werkt</label>
      <button class="mini" disabled={busy === 'setup'} onclick={loadSetup}>{busy === 'setup' ? 'bezig…' : '⟳ opnieuw'}</button>
    </div>
    {#each groups as g (g.key)}
      <h3>{g.title}</h3>
      {#each g.rows as r (r.key)}
        <div class="row st-{r.state}" class:opt={r.optional && r.state === 'none'}>
          <span class="st">{r.optional && r.state === 'none' ? 'optioneel' : STATE[r.state]}</span>
          <div class="tx">
            <b>{r.title}</b>
            <p>{r.text}</p>
            {#if r.todo.length}<ul>{#each r.todo as t}<li>{t}</li>{/each}</ul>{/if}
          </div>
          {#if r.fix}<button class="mini" onclick={() => onfix(r.fix)}>{FIX_LABEL[r.fix.window] || 'openen'}</button>{/if}
        </div>
      {/each}
    {/each}
  {/if}
</Modal>

<style>
  .tabs { display: flex; gap: 6px; margin-bottom: 12px }
  .n { margin-left: 5px; color: var(--mid); font-size: 11px; font-weight: 500 }
  .n.e { color: var(--err) }
  .top { margin: 0 0 10px }
  .it, .row { display: flex; gap: 12px; align-items: flex-start; padding: 9px 12px; border: 1px solid var(--line);
              border-radius: 10px; margin-bottom: 6px; background: var(--fill) }
  .dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; background: var(--muted) }
  .lv-err .dot { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .lv-warn .dot { background: var(--mid) }
  .it.lv-err { border-left: 3px solid var(--err) }
  .it.lv-warn { border-left: 3px solid var(--mid) }
  .it.ign { opacity: .6 }
  .tx { flex: 1; min-width: 0 }
  .tx b { color: var(--text-h); font-weight: 500; font-size: 13px }
  .tx p { margin: 2px 0 0; font-size: 12.5px; line-height: 1.5; overflow-wrap: anywhere }
  .area { font-size: 10.5px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: var(--muted);
          white-space: nowrap }
  .btns { display: flex; gap: 6px; flex-shrink: 0 }
  .dim { color: var(--muted) }
  .more { margin: 6px 0 }
  .head { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 4px }
  .head .hint { flex: 1; margin: 0; min-width: 200px }
  .chk { font-size: 12px; color: var(--muted); display: flex; gap: 5px; align-items: center }
  h3 { margin: 14px 0 6px; color: var(--text-h); font-weight: 500; font-size: 13px }
  .st { width: 66px; flex-shrink: 0; font-size: 11px; text-align: center; padding: 2px 0; border-radius: 6px;
        border: 1px solid currentColor; margin-top: 1px }
  .st-ok .st { color: var(--ok) }
  .st-half .st { color: var(--mid) }
  .st-none .st { color: var(--err) }
  .opt .st { color: var(--muted) }
  .row.st-half { border-left: 3px solid var(--mid) }
  .row.st-none:not(.opt) { border-left: 3px solid var(--err) }
  ul { margin: 4px 0 0; padding-left: 18px; font-size: 12.5px; color: var(--text) }
  li { margin: 2px 0; overflow-wrap: anywhere }
  .row > .mini { flex-shrink: 0 }
  @media (max-width: 560px) {
    .it, .row { flex-wrap: wrap }
    .btns { width: 100%; justify-content: flex-end }
    .st { width: auto; padding: 2px 6px }
  }
</style>
