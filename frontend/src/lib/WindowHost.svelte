<script>
  import { dash } from './dash.svelte.js'
  import { byId } from './windows.js'
  import Lazy from './Lazy.svelte'

  // Alle vensters van het dashboard op één plek. Welk venster bij welke naam hoort, staat in windows.js; hier staat
  // alleen wat elk venster van het dashboard meekrijgt.
  let { onnews } = $props()

  const close = () => dash.close()
  const reload = () => dash.loadLayout()

  // Wat elk gewoon venster meekrijgt (m = het venster met zijn startpunt).
  function propsOf(m) {
    switch (m.id) {
      case 'attention':
        return { tab: m.tab, data: dash.att, onfix: (f) => dash.openFix(f), onchanged: (d) => (dash.att = d), onclose: close }
      case 'history':
        return { tab: m.tab, onclose: close }
      case 'network':
        return { initialTab: m.tab, initialQuery: m.q, onclose: close, onchanged: (d) => (dash.net = d) }
      case 'apis':
        return { onclose: () => { close(); reload(); dash.refresh(['widgets']) } }
      case 'webhooks':
        return { services: dash.services, onclose: close }
      case 'planned':
        return { services: dash.services, groups: dash.groupOptions, onclose: close }
      case 'configs':
        return { initialItem: m.item, onclose: close }
      case 'updates':
        return { onclose: close, onchanged: () => dash.refresh(['updates']) }
      case 'security':
        return { tab: m.tab, error: m.error, onclose: () => { close(); dash.refresh(['buiten']) } }
      case 'news':
        return { entries: m.entries, version: m.version ?? dash.version, onclose: () => { close(); onnews?.() } }
      case 'detail':
        return { service: m.service, groups: dash.groupOptions, onchanged: reload, onclose: close,
                 onterminal: (hostId) => dash.open('terminal', { hostId }),
                 onfiles: (hostId) => dash.open('terminal', { hostId, files: true }),
                 onedit: (svc) => dash.open('service', { service: svc }),
                 oncleanup: (svc) => dash.open('nieuweservice', { tab: 'opruimen', service: svc }) }
      case 'nieuweservice':
        return { tab: m.tab, service: m.service, groups: dash.groupOptions, services: dash.services, onclose: close,
                 ondone: () => { reload(); dash.refresh(['widgets', 'aandacht']) } }
      case 'service':
        return { service: m.service, groupId: m.groupId, groups: dash.groupOptions, services: dash.services, onclose: close,
                 onsaved: () => { reload(); setTimeout(() => dash.refresh(['widgets']), 300) } }
      case 'import':
        return { pages: dash.pages, onclose: close, ondone: reload }
      case 'revisions':
        return { onclose: close, ondone: reload }
      default:
        return { onclose: close }
    }
  }

  // De grote vensters: bovenaan ligt het laatst geopende.
  const z = (id) => 60 + Math.min(4, Math.max(0, dash.order.indexOf(id)))
  const bigOpen = (id) => !!dash.big[id]?.open
  const bigClose = (id) => () => dash.close(id)
</script>

{#if dash.modal && byId[dash.modal.id]?.load}
  <!-- Boven de grote vensters (60-64), ook als het venster zelf Window gebruikt (API-beheer). -->
  <div class="mw">
    {#key dash.modal}
      <Lazy load={byId[dash.modal.id].load} {...propsOf(dash.modal)} />
    {/key}
  </div>
{/if}

{#if dash.big.terminal?.used}
  <!-- xterm.js is groot: pas laden als je de terminal voor het eerst opent. -->
  <div class="bw" style:z-index={z('terminal')}>
    <Lazy load={byId.terminal.load} open={bigOpen('terminal')} request={dash.big.terminal.initial} services={dash.services}
          onclose={bigClose('terminal')} />
  </div>
{/if}
{#if dash.big.cron?.used}
  <div class="bw" style:z-index={z('cron')}>
    <Lazy load={byId.cron.load} open={bigOpen('cron')} initial={dash.big.cron.initial} onclose={bigClose('cron')}
          onterminal={(hostId) => dash.open('terminal', { hostId })} />
  </div>
{/if}
{#if dash.big.health?.used}
  <div class="bw" style:z-index={z('health')}>
    <Lazy load={byId.health.load} open={bigOpen('health')} initial={dash.big.health.initial} onclose={bigClose('health')}
          onfix={(f) => dash.openFix(f)} />
  </div>
{/if}
{#if dash.big.logs?.used}
  <div class="bw" style:z-index={z('logs')}>
    <Lazy load={byId.logs.load} open={bigOpen('logs')} initial={dash.big.logs.initial} onclose={bigClose('logs')} />
  </div>
{/if}

<style>
  /* Elk groot venster in een eigen laag, zodat het laatst geopende bovenaan ligt (onder de gewone vensters). */
  .bw { position: relative }
  .mw { position: relative; z-index: 65 }
</style>
