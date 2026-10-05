<script>
  import { api } from './api.js'
  import { bytes } from './format.js'
  import CopyCmd from './CopyCmd.svelte'

  // Eén node 's nachts uit: welke VM's en CT's waarheen, of het past en wat het bespaart. Alleen advies.
  let hours = $state(8)
  let start = $state(23)
  let data = $state.raw(null)
  let error = $state('')
  let busy = $state(false)
  let open = $state('')

  async function load() {
    busy = true
    try { data = await api(`/capacity/nightly?hours=${hours}`); error = ''; open = data.best || '' } catch (e) { error = e.message } finally { busy = false }
  }
  const pad = (h) => String(h).padStart(2, '0')
  let wake = $derived((start + hours) % 24)
  let day = $derived(start + hours < 24 ? 'today' : 'tomorrow')
  let cron = $derived(`0 ${start} * * * /usr/sbin/rtcwake -m off -t $(date -d '${day} ${pad(wake)}:00' +\\%s)`)
  const kwh = (c) => `${c.kwh_year} kWh per jaar${c.eur_year != null ? ` (€ ${c.eur_year.toFixed(0)})` : ''}`
</script>

<div class="gh"><span class="lbl">Eén node 's nachts uit</span></div>
<p class="hint small">Welke node leeg kan als zijn VM's en CT's naar de andere nodes verhuizen: piek-RAM van de laatste 7 dagen,
  20% marge, passthrough en de Pi (ARM) apart. Alleen advies: het dashboard verhuist zelf niets.</p>
<div class="ctl">
  <label>uit van <select bind:value={start}>{#each [21, 22, 23, 0, 1] as h (h)}<option value={h}>{pad(h)}:00</option>{/each}</select></label>
  <label>uren <select bind:value={hours}>{#each [6, 7, 8, 9, 10] as h (h)}<option value={h}>{h}</option>{/each}</select></label>
  <button class="mini" disabled={busy} onclick={load}>{busy ? 'berekenen…' : data ? '⟳ opnieuw' : 'voorstel berekenen'}</button>
</div>
{#if error}<p class="err">{error}</p>{/if}
{#if data?.error}<p class="hint">{data.error}</p>{/if}
{#if data && !data.error}
  {#if !data.best}<p class="hint">Geen enkele node kan nu leeg: zie per node waarom.</p>{/if}
  {#each data.candidates as c (c.node)}
    <div class="cand" class:can={c.feasible} class:best={c.node === data.best}>
      <button class="ch" onclick={() => (open = open === c.node ? '' : c.node)} aria-expanded={open === c.node}>
        <b>{c.node}</b>
        <span class="pill" class:g={c.feasible}>{c.feasible ? (c.node === data.best ? 'beste keuze' : 'kan') : 'kan niet'}</span>
        <small>{c.guests} {c.guests === 1 ? 'gast' : 'gasten'} · {c.watts} W{c.estimated ? ' (geschat)' : ''}{c.feasible ? ` · bespaart ${kwh(c)}` : ''}</small>
        {#if !c.feasible}<small class="why">{c.why}</small>{/if}
      </button>
      {#if open === c.node}
        {#each c.blockers as b}<p class="e small">{b}</p>{/each}
        {#if c.feasible}
          {#if c.moves.length}
            <table class="tbl">
              <thead><tr><th>VM/CT</th><th>naar</th><th>RAM</th><th>let op</th></tr></thead>
              <tbody>
                {#each c.moves as m (m.vmid)}
                  <tr><td>{m.type} {m.vmid} {m.name}</td><td>{m.to}</td><td class="m">{m.need ? bytes(m.need) : '—'}</td>
                    <td class="m wrapcell">{m.notes.join('; ')}</td></tr>
                {/each}
              </tbody>
            </table>
          {/if}
          <ol class="steps">
            {#if c.moves.length}
              <li>Verhuis de gasten, op {c.node}, één per keer:
                {#each c.moves as m (m.vmid)}<CopyCmd cmd={m.command} />{/each}</li>
            {/if}
            <li>Zet {c.node} elke avond om {pad(start)}:00 uit en laat de BIOS hem om {pad(wake)}:00 weer aanzetten (RTC-wake; staat in
              de BIOS van de meeste HP's). In <code>crontab -e</code> op {c.node}:
              <CopyCmd cmd={cron} />
              Werkt RTC-wake niet, zet hem dan 's ochtends aan met Wake-on-LAN (net → wake-on-lan).</li>
            <li>{#if data.quorum_left}Met {c.node} uit heb je nog {data.nodes - 1} van de {data.nodes} stemmen: genoeg voor quorum. Zet 's
              nachts geen tweede node uit (een QDevice geeft extra marge, zie hw → cluster).{:else}Let op: met {c.node} uit verliest de cluster
              zijn quorum. Zet eerst een QDevice op (hw → cluster).{/if}</li>
          </ol>
          {#if c.after}<p class="hint small">Ruimte die daarna overblijft (RAM, na de marge): {Object.entries(c.after).map(([n, v]) => `${n} ${v} GB`).join(', ')}.</p>{/if}
        {/if}
      {/if}
    </div>
  {/each}
  {#if data.candidates.some((c) => c.estimated)}<p class="hint small">Geschat = geen meting uit Home Assistant voor die node; gerekend met
    25 W voor een oude desktop in rust.{data.price == null ? ' Zonder prijs per kWh (Home Assistant-tegel, instelling price) geen bedrag.' : ''}</p>{/if}
{/if}

<style>
  .gh { display: flex; gap: 8px; align-items: flex-end; margin-top: 14px }
  .gh .lbl { flex: 1; margin-bottom: 4px }
  .small { font-size: 11.5px; margin-top: 4px }
  .ctl { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 6px 0 }
  .ctl label { display: flex; gap: 6px; align-items: center; font-size: 12px; color: var(--muted) }
  .ctl select { width: auto; padding: 4px 8px }
  .cand { border: 1px solid var(--line); border-radius: 10px; margin: 6px 0; background: var(--fill); border-left: 3px solid var(--line-2) }
  .cand.can { border-left-color: var(--ok) }
  .ch { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; width: 100%; background: none; border: 0; padding: 8px 12px;
        cursor: pointer; text-align: left; font: inherit; color: inherit }
  .ch b { color: var(--text-h); font-weight: 500 }
  .ch small { color: var(--muted); font-size: 11.5px }
  .ch .why { color: var(--mid) }
  .pill { font-size: 11px; padding: 0 7px; border-radius: 8px; background: var(--fill-h); color: var(--muted) }
  .pill.g { color: var(--ok) }
  .cand > :not(.ch) { margin-left: 12px; margin-right: 12px }
  .tbl { width: calc(100% - 24px); border-collapse: collapse; font-size: 12.5px; margin-top: 2px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05) }
  .wrapcell { white-space: normal; font-size: 11.5px }
  .m { color: var(--muted) }
  .e { color: var(--err) }
  .steps { font-size: 12.5px; padding-left: 18px; margin: 8px 12px 10px }
  .steps li { margin: 8px 0; line-height: 1.5 }
  @media (max-width: 700px) {
    .tbl { display: block; overflow-x: auto }
  }
</style>
