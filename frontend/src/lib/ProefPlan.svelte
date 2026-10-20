<script>
  // Proefmodus: wat een actie zou doen, zonder het te doen. Per stap de machine, via SSH of welke API, als wie,
  // het commando of de call, en wat er gebeurt als die stap mislukt. Het plan komt van de backend (app/proef.py).
  let { plan, onclose = null } = $props()

  const VIA = { ssh: 'SSH', 'proxmox-api': 'Proxmox-API', 'portainer-api': 'Portainer-API', 'adguard-api': 'AdGuard-API',
                'pbs-api': 'PBS-API', api: 'API', dashboard: 'dashboard' }
  const mark = (ok) => (ok === true ? '✓' : ok === false ? '✕' : '?')
  const when = (ts) => {
    const d = new Date(ts)
    return isNaN(d) ? '' : d.toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  }
</script>

<div class="proef">
  <div class="top">
    <span class="tag">proef</span>
    <span class="sub">er is niets uitgevoerd · {when(plan.at)}</span>
    {#if onclose}<button class="mini x" onclick={onclose} title="sluiten">✕</button>{/if}
  </div>
  <div class="title">{plan.title}</div>

  {#if plan.checks?.length}
    <ul class="checks">
      {#each plan.checks as c, i (i)}
        <li class:g={c.ok === true} class:e={c.ok === false} class:w={c.ok === null}>
          <span class="mk">{mark(c.ok)}</span> {c.what}{#if c.detail}<small>: {c.detail}</small>{/if}
        </li>
      {/each}
    </ul>
  {/if}

  {#if plan.steps?.length}
    <ol class="steps">
      {#each plan.steps as s (s.nr)}
        <li>
          <div class="m"><b>{s.machine}</b> · {VIA[s.via] || s.via}{#if s.who}{` · als ${s.who}`}{/if}</div>
          {#if s.when}<div class="note">alleen {s.when}</div>{/if}
          <code>{s.call}</code>
          {#if s.data}<code class="data">{JSON.stringify(s.data)}</code>{/if}
          {#if s.script}<details><summary>volledig commando</summary><code>{s.script}</code></details>{/if}
          {#if s.wait}<div class="note">wacht: {s.wait}</div>{/if}
          {#if s.on_fail}<div class="note">als dit mislukt: {s.on_fail}</div>{/if}
          {#if s.note}<div class="note w">let op: {s.note}</div>{/if}
        </li>
      {/each}
    </ol>
  {:else}
    <p class="none">Er zou niets gebeuren.</p>
  {/if}

  {#if plan.skipped?.length}
    <div class="sec">Niet gedaan</div>
    <ul class="list">{#each plan.skipped as x, i (i)}<li><b>{x.what}</b>: {x.why}</li>{/each}</ul>
  {/if}
  {#if plan.after?.length}
    <div class="sec">Daarna</div>
    <ul class="list">{#each plan.after as a, i (i)}<li>{a}</li>{/each}</ul>
  {/if}
  {#if plan.warnings?.length}
    <ul class="list w">{#each plan.warnings as w, i (i)}<li>{w}</li>{/each}</ul>
  {/if}
</div>

<style>
  .proef { margin: 8px 0; padding: 10px 12px; border-radius: 10px; border: 1px dashed var(--line-2);
           background: rgba(0, 0, 0, .25); font-size: 12.5px }
  .top { display: flex; gap: 8px; align-items: center }
  .tag { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; padding: 1px 7px; border-radius: 6px;
         border: 1px solid var(--mid); color: var(--mid) }
  .sub { color: var(--muted); font-size: 11.5px; flex: 1 }
  .x { flex-shrink: 0 }
  .title { color: var(--text-h); margin: 6px 0 4px }
  .checks, .list { list-style: none; padding: 0; margin: 4px 0 }
  .checks li, .list li { padding: 1px 0 }
  .mk { display: inline-block; width: 1.2em }
  .checks small { color: var(--muted) }
  .steps { padding-left: 20px; margin: 6px 0 }
  .steps li { margin: 0 0 8px }
  .m { color: var(--muted) }
  .m b { font-weight: 500; color: var(--text-h) }
  code { display: block; margin: 3px 0; padding: 5px 8px; border-radius: 6px; background: rgba(0, 0, 0, .3);
         border: 1px solid var(--line); white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; color: var(--text-h) }
  code.data { color: var(--muted) }
  .note { color: var(--muted); font-size: 11.5px }
  summary { color: var(--muted); font-size: 11.5px; cursor: pointer }
  .sec { color: var(--muted); font-size: 11.5px; margin-top: 6px }
  .none { color: var(--muted); margin: 6px 0 }
  .g { color: var(--ok) }
  .e { color: var(--err) }
  .w { color: var(--mid) }
</style>
