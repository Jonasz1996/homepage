<script>
  import { onDestroy, untrack } from 'svelte'
  import { api, ApiError, poll, withReauth } from './api.js'
  import { ask } from './dialog.svelte.js'
  import ProefPlan from './ProefPlan.svelte'

  // Eén run van een nieuwe service (maken, opruimen of ongedaan maken), stap per stap. Loopt hij nog, dan kijkt dit
  // elke 1,5 s opnieuw. undo: bij een run die halverwege stopte de knoppen om weg te halen wat hij al maakte.
  // onfinish(run): de run is klaar of gestopt. onundo(run): ongedaan maken is gestart (dat is een nieuwe run).
  let { run: start, undo = false, onfinish = null, onundo = null } = $props()

  let run = $state(untrack(() => start))
  let stop = null

  function follow() {
    stop?.()
    stop = poll(async () => {
      try {
        const r = await api(`/nieuweservice/runs/${run.id}`)
        run = r
        if (r.status !== 'bezig') {
          stop?.()
          stop = null
          onfinish?.(r)
        }
      } catch { /* de volgende keer opnieuw */ }
    }, 1500)
  }
  if (untrack(() => start.status) === 'bezig') follow()
  onDestroy(() => stop?.())

  const ICON = { wacht: '○', bezig: '✱', ok: '✓', fout: '✕', overgeslagen: '–', onbekend: '?' }
  const WORD = { wacht: 'wacht', bezig: 'bezig…', ok: 'gelukt', fout: 'mislukt', overgeslagen: 'overgeslagen', onbekend: 'onbekend' }
  const STATUS = { bezig: 'bezig', klaar: 'klaar', gestopt: 'gestopt', onderbroken: 'onderbroken', ongedaan: 'ongedaan gemaakt' }
  const KIND = { maken: 'maken', opruimen: 'opruimen', ongedaan: 'ongedaan maken' }
  const labels = (items) => items.map((c) => c.label || c.kind).join(', ')
  let failed = $derived(run.steps?.find((s) => s.status === 'fout' && s.fatal !== false) || run.steps?.find((s) => s.status === 'onbekend'))
  let level = $derived(run.status === 'klaar' ? (run.warning ? 'w' : 'g') : run.status === 'bezig' ? '' : 'e')

  // Ongedaan maken: eerst de proef (wat er weg zou gaan), dan pas uitvoeren.
  let plan = $state(null)
  let busy = $state(false)
  let error = $state('')
  let note = $state('')
  async function undoProef() {
    busy = true
    error = ''
    try { plan = (await api(`/nieuweservice/runs/${run.id}/ongedaan/proef`, { method: 'POST' })).plan } catch (e) { error = e.message } finally { busy = false }
  }
  async function undoRun() {
    if (!(await ask(`Wat deze run maakte weer weghalen? ${plan.steps.length} stappen.`, { ok: 'Ongedaan maken', danger: true }))) return
    busy = true
    error = ''
    note = ''
    try {
      const r = await withReauth(() => api(`/nieuweservice/runs/${run.id}/ongedaan`, { method: 'POST', body: { plan_hash: plan.hash } }))
      plan = null
      onundo?.(r.run)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.message === 'plan_veranderd') {
        await undoProef()
        note = 'Het plan is intussen veranderd: hier is het nieuwe.'
      } else if (e instanceof ApiError && e.status === 409 && e.message === 'bezig') {
        error = 'Er loopt al iets: wacht tot het klaar is.'
      } else error = e.message
    } finally { busy = false }
  }
</script>

<div class="run">
  <div class="head"><b>{run.fqdn || '?'}</b> · {KIND[run.kind] || run.kind} · <span class={level}>{STATUS[run.status] || run.status}</span></div>
  <ol class="steps">
    {#each run.steps || [] as s (s.nr)}
      <li>
        <span class="ic {s.status}" class:pulse={s.status === 'bezig'}>{ICON[s.status] || '?'}</span>
        <div class="t">
          <span>{s.title}</span> <small class="st {s.status}">{WORD[s.status] || s.status}</small>
          {#if s.detail}<div class="d">{s.detail}</div>{/if}
        </div>
      </li>
    {/each}
  </ol>
  {#if run.status === 'gestopt' && failed}
    <div class="box e">Gestopt bij stap {failed.nr} ({failed.title}): {failed.detail}</div>
  {:else if run.status === 'onderbroken'}
    <div class="box e">Onderbroken: de homepage herstartte tijdens stap {failed?.nr ?? '?'}. Wat die stap deed, is niet
      zeker: de proef van ongedaan maken kijkt het na.</div>
  {/if}
  {#if run.warning}
    <div class="box w">{run.kind === 'maken' ? 'Back-up niet ingesteld' : 'Let op'}: {run.warning}</div>
  {/if}
  {#if run.kind === 'maken' && run.created?.length && run.status !== 'klaar'}
    <div class="made">Al gemaakt: {labels(run.created)}</div>
  {:else if run.kind !== 'maken' && run.removed?.length}
    <div class="made">{run.status === 'klaar' ? 'Weg' : 'Al verwijderd'}: {labels(run.removed)}</div>
  {/if}

  {#if undo && run.can_undo}
    <div class="btns">
      <button class="mini" disabled={busy} onclick={undoProef}>proef van ongedaan maken</button>
      {#if plan?.steps?.length}<button class="mini x" disabled={busy} onclick={undoRun}>ongedaan maken</button>{/if}
    </div>
    {#if note}<p class="hint small">{note}</p>{/if}
    {#if error}<p class="err">{error}</p>{/if}
    {#if plan}<ProefPlan {plan} onclose={() => (plan = null)} />{/if}
  {/if}
</div>

<style>
  .run { margin: 8px 0; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); font-size: 12.5px }
  .head { color: var(--muted); overflow-wrap: anywhere }
  .head b { color: var(--text-h); font-weight: 500 }
  .steps { list-style: none; padding: 0; margin: 8px 0 4px }
  .steps li { display: grid; grid-template-columns: 1.4em minmax(0, 1fr); gap: 4px; padding: 2px 0 }
  .ic { color: var(--muted) }
  .ic.ok { color: var(--ok) }
  .ic.fout { color: var(--err) }
  .ic.onbekend, .ic.bezig { color: var(--mid) }
  .pulse { animation: p 1s ease-in-out infinite }
  @keyframes p { 50% { opacity: .3 } }
  .t { min-width: 0 }
  .st { color: var(--muted); font-size: 11.5px }
  .st.fout { color: var(--err) }
  .d { color: var(--muted); font-size: 11.5px; overflow-wrap: anywhere }
  .box { margin: 6px 0; padding: 6px 8px; border-radius: 8px; border: 1px solid var(--line-2); overflow-wrap: anywhere }
  .made { color: var(--muted); margin-top: 4px; overflow-wrap: anywhere }
  .btns { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px }
  .small { font-size: 12px; margin: 4px 0 }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .w { color: var(--mid) }
</style>
