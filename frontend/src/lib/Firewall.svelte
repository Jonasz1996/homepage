<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'

  // net → firewall: welk slot er voor het dashboard staat (Cloudflare Access of Authentik), en welke IP's en poorten
  // het dashboard echt gebruikt, voor een strakke regel tussen de VLAN's in OPNsense.
  let data = $state(null)
  let where = $state(null)
  let error = $state('')
  let copied = $state(false)

  onMount(async () => {
    try { [data, where] = await Promise.all([api('/network/ports'), api('/outside')]) } catch (e) { error = e.message }
  })

  const ACCESS = { 'cloudflare-access': 'Cloudflare Access', authentik: 'Authentik (forward-auth in NPM)' }
  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  const SCOPE = { 'ander netwerk': 'via de router', 'zelfde netwerk': 'zelfde netwerk', internet: 'internet', zelf: 'zelf', onbekend: '?' }
  let last = $derived(where?.seen?.last)
  let rule = $derived(data ? [
    `Alias homepage (Host(s)):        ${data.own_ip || '<IP van het dashboard>'}`,
    `Alias homepage_doelen (Host(s)): ${data.opnsense.hosts.join(' ') || '-'}`,
    `Alias homepage_tcp (Port(s)):    ${data.opnsense.tcp.join(' ') || '-'}`,
    ...(data.opnsense.udp.length ? [`Alias homepage_udp (Port(s)):    ${data.opnsense.udp.join(' ')}`] : []),
    '',
    `Regel op de interface van ${data.own_net || 'het netwerk van het dashboard'}:`,
    '  Pass  TCP  bron homepage → bestemming homepage_doelen, poort homepage_tcp',
    ...(data.opnsense.udp.length ? ['  Pass  UDP  bron homepage → bestemming homepage_doelen, poort homepage_udp'] : []),
    ...(data.opnsense.ping ? ['  Pass  ICMP bron homepage → bestemming homepage_doelen (ping-checks)'] : []),
    ...(data.internet ? ['  Pass  TCP  bron homepage → bestemming !RFC1918, poort 443 (internet: Cloudflare, RDAP, publiek IP)'] : []),
    '  Block any  bron homepage → bestemming je andere VLAN\'s (onder de regels hierboven)',
  ].join('\n') : '')
  async function copy() {
    try { await navigator.clipboard.writeText(rule); copied = true } catch { copied = false }
  }
</script>

{#if error}<p class="err">{error}</p>{/if}

<section class="box" class:good={last?.access} class:bad={last && !last.access}>
  <b>slot voor het dashboard</b>
  {#if !last}
    <p>Nog geen bezoek van buitenaf gezien. Bij het eerste bezoek via Cloudflare zie je hier of er een slot voor stond.</p>
  {:else if last.access}
    <p>✓ {ACCESS[last.access]} stond voor het laatste bezoek van buitenaf ({when(last.ts)}, {last.ip}{last.country ? ` · ${last.country}` : ''}).</p>
  {:else}
    <p>Het laatste bezoek van buitenaf ({when(last.ts)}, {last.ip}{last.country ? ` · ${last.country}` : ''}) kwam zonder slot
      binnen: iedereen op internet krijgt je loginscherm te zien.</p>
  {/if}
  {#if !last?.access}
    <p class="hint">Zet er een slot voor, zodat een aanvaller het loginscherm niet eens ziet: <b>Cloudflare Access</b>
      (Zero Trust → Access → Applications → Self-hosted, voor home.jbogaert.be, met je e-mailadres als regel) of de
      <b>forward-auth van Authentik</b> in NPM (Advanced bij de proxy host, met de nginx-config uit Authentik). Het dashboard
      herkent ze aan de headers <code>Cf-Access-Jwt-Assertion</code> en <code>X-authentik-username</code>.</p>
  {/if}
</section>

{#if data}
  <h3>wat het dashboard gebruikt</h3>
  <p class="hint">Uit je tegels, API-beheer, de SSH-hosts en de DNS-server van de container{data.own_ip ? ` (${data.own_ip})` : ''}.
    Wat <i>via de router</i> gaat, moet de firewall tussen de VLAN's doorlaten; de rest niet.</p>
  <div class="scroll">
    <table class="tbl">
      <thead><tr><th>doel</th><th>poorten</th><th>gebruikt door</th></tr></thead>
      <tbody>
        {#each data.rows as r (r.ip)}
          <tr class:dim={r.scope !== 'ander netwerk'}>
            <td class="nw"><b>{r.ip}</b> <span class="sc s-{r.scope.replace(' ', '-')}">{SCOPE[r.scope]}</span>
              {#if r.names.length}<br /><small>{r.names.join(', ')}{r.names_total > r.names.length ? ` +${r.names_total - r.names.length}` : ''}</small>{/if}</td>
            <td class="nw">{r.ports.join(' ')}</td>
            <td><small>{r.used_by.join(', ')}{r.used_total > r.used_by.length ? ` +${r.used_total - r.used_by.length}` : ''}</small></td>
          </tr>
        {:else}
          <tr><td colspan="3" class="m">Nog niets: voeg tegels, API's of SSH-hosts toe.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if data.unresolved.length}
    <p class="hint">Niet gevonden in DNS (dus ook niet in de lijst): {data.unresolved.map((u) => `${u.name} (${u.used_by.join(', ')})`).join('; ')}.</p>
  {/if}

  <h3>binnenkomend</h3>
  <ul class="in">
    {#each data.inbound as i}<li><b>{i.port}</b> van {i.from}: {i.why}</li>{/each}
  </ul>

  <h3>voorstel voor OPNsense <button class="mini" onclick={copy}>{copied ? '✓ gekopieerd' : 'kopieer'}</button></h3>
  <pre>{rule}</pre>
  <p class="hint">Firewall → Aliases voor de aliassen, Firewall → Rules → de interface van het dashboard voor de regels.
    Eén regel met aliassen laat elke poort uit de lijst toe naar elk doel uit de lijst: iets ruimer dan per paar, maar
    veel strakker dan alles. Kijk deze lijst opnieuw na als je tegels of hosts toevoegt.</p>
{/if}

<style>
  .box { padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: var(--fill); margin-bottom: 12px }
  .box.good { border-color: rgba(143, 214, 164, .45) }
  .box.bad { border-color: rgba(230, 181, 107, .55) }
  .box b, h3 { color: var(--text-h); font-weight: 500; font-size: 13px }
  .box p { margin: 4px 0 0; font-size: 12.5px }
  h3 { margin: 16px 0 4px; display: flex; gap: 10px; align-items: center }
  .scroll { overflow-x: auto }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid var(--line) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05); vertical-align: top }
  .tbl b { color: var(--text-h); font-weight: 500 }
  .tbl small { color: var(--muted); font-size: 11.5px }
  .tbl tr.dim td { opacity: .65 }
  .nw { white-space: nowrap }
  .m { color: var(--muted) }
  .sc { font-size: 10.5px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: var(--muted) }
  .sc.s-ander-netwerk { color: var(--mid); border-color: rgba(230, 181, 107, .5) }
  .in { margin: 4px 0; padding-left: 18px; font-size: 12.5px }
  pre { background: rgba(0, 0, 0, .35); border: 1px solid var(--line); border-radius: 8px; padding: 10px; font-size: 11.5px;
        overflow-x: auto; color: #d6e6ff; margin: 4px 0 }
</style>
