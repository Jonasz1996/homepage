// Gedeelde toestand van het hoofdscherm: de indeling, wat de server over je services en machines weet, de verbinding
// en welke vensters open staan. De onderdelen van het dashboard (titelbalk, tegels, zoekbalk, vensters) lezen hier.
import { api, ApiError } from './api.js'
import { fxEnabled, setFx } from './fx.js'
import { byId, resolve, sourceWindow } from './windows.js'

// Hoe vaak elk deel van /api/overzicht ververst. Eén klok, één verzoek: bij elke tik gaan de delen mee die aan de
// beurt zijn. Komt het tabblad terug in beeld, dan één verzoek met wat intussen verlopen is.
export const PARTS = {
  status: 30000, meldingen: 30000, widgets: 60000, zabbix: 60000,
  aandacht: 120000, cron: 120000, health: 120000, net: 120000, updates: 300000,
  // Van waar je verbonden bent: één keer bij het laden (en na het venster Van buitenaf). Elke vraag van buitenaf telt
  // op de server als een nieuw bezoek.
  buiten: Infinity,
}
// In hun eigen verzoek (zie #lanes).
const SLOW = new Set(['widgets', 'aandacht'])
const newLanes = () => ({ snel: { busy: false, again: null }, traag: { busy: false, again: null } })
const TICK = 30000
const RETRY = 15000

class Dash {
  layout = $state({ pages: [] })
  loaded = $state(false)
  layoutError = $state('')
  // Wordt bij elke verversing volledig vervangen, nooit aangepast: geen diepe proxy nodig.
  status = $state.raw({})
  widgets = $state.raw({})
  zbx = $state.raw({})
  updates = $state.raw({ total: 0, security: 0, by_service: {} })
  net = $state.raw(null)
  cron = $state.raw({ fout: 0, gemist: 0 })
  health = $state.raw({ err: 0, warn: 0 })
  att = $state.raw({ items: [], ignored: [], counts: { err: 0, warn: 0, info: 0 } })
  notif = $state.raw({ unread: 0, newest: null })
  where = $state.raw(null)
  version = $state.raw(null)

  // Verbinding met de homepage zelf: wanneer het laatst lukte, en sinds wanneer niet meer (null = in orde).
  lastOk = $state(null)
  offline = $state(null)
  offlineWhy = $state('')

  // Vensters: één gewoon venster tegelijk (modal), en de grote vensters die geladen blijven (big, in volgorde van
  // openen: het laatste ligt bovenaan).
  modal = $state(null)
  big = $state({})
  order = $state([])
  editing = $state(false)
  notifOpen = $state(false)
  // Alleen de tegels met een probleem tonen, over alle pagina's heen.
  problemsOnly = $state(false)
  // Effecten aan of uit (ook in fx.js en op <html> als class "calm", zie setFx).
  fx = $state(fxEnabled())

  setFx(on) {
    setFx(on)
    this.fx = fxEnabled()
  }

  pages = $derived(this.layout.pages || [])
  services = $derived(this.pages.flatMap((p) => p.groups.flatMap((g) => g.services)))
  groupOptions = $derived(this.pages.flatMap((p) => p.groups.map((g) => ({ id: g.id, label: `${p.name} / ${g.name}` }))))

  // --- Verversen ------------------------------------------------------------

  #last = {}
  #timer = null
  // Per start(): een antwoord dat binnenkomt na een stop (uitloggen), telt niet meer.
  #gen = 0
  // Twee rijen, elk met hoogstens één verzoek tegelijk: de tegels (en Aandacht, dat op de tegels wacht) apart, zodat
  // een integratie die niet antwoordt de status, de meldingen en de rest niet tot 8 s ophoudt.
  #lanes = newLanes()
  #failedAt = 0

  async loadLayout() {
    try {
      this.layout = await api('/layout')
      this.layoutError = ''
    } catch (e) {
      this.layoutError = e.message
    } finally {
      this.loaded = true
    }
  }

  /** Haalt de delen op die aan de beurt zijn (of precies deze, met force). */
  refresh(force = null) {
    if (!this.#gen) return Promise.resolve()
    const now = Date.now()
    const due = force || Object.keys(PARTS).filter((p) => !this.#last[p] || now - this.#last[p] >= PARTS[p] - 2000)
    return Promise.all([
      this.#fetch(this.#lanes.snel, due.filter((p) => !SLOW.has(p)), !!force),
      this.#fetch(this.#lanes.traag, due.filter((p) => SLOW.has(p)), !!force),
    ])
  }

  async #fetch(lane, parts, forced) {
    if (!parts.length) return
    if (lane.busy) {
      // Er loopt al een verzoek in deze rij: daarna meteen de gevraagde delen.
      if (forced) lane.again = [...new Set([...(lane.again || []), ...parts])]
      return
    }
    const gen = this.#gen
    const now = Date.now()
    lane.busy = true
    try {
      // Tegels met de hand ververst (na een wijziging aan een tegel of API): niet aansluiten bij een berekening die
      // nog loopt, die las misschien de tegel van ervoor.
      const vers = forced && parts.includes('widgets') ? '&vers=1' : ''
      const r = await api(`/overzicht?delen=${parts.join(',')}${vers}`)
      if (gen !== this.#gen) return
      this.#apply(r.delen || {})
      const failed = r.fouten || {}
      for (const p of parts) {
        // Een deel dat mislukte: bij de volgende tik opnieuw, niet pas na zijn eigen termijn.
        this.#last[p] = !failed[p] ? now : Number.isFinite(PARTS[p]) ? now - PARTS[p] + TICK : 0
      }
      this.lastOk = new Date()
      // Alleen als dit verzoek begon na de laatste mislukte: een traag antwoord van ervoor zegt niets over nu.
      if (now >= this.#failedAt) {
        this.offline = null
        this.offlineWhy = ''
      }
    } catch (e) {
      if (gen !== this.#gen) return
      // Uitgelogd: App.svelte toont het loginscherm. Anders is de homepage zelf (of de weg ernaartoe) weg.
      if (!(e instanceof ApiError && (e.status === 401 || e.status === 403))) {
        this.#failedAt = Date.now()
        this.offline ??= new Date()
        this.offlineWhy = e instanceof ApiError ? e.message : 'geen antwoord'
        this.#schedule(RETRY)
      }
    } finally {
      lane.busy = false
      const again = lane.again
      lane.again = null
      if (again && gen === this.#gen) this.refresh(again)
    }
  }

  /** "opnieuw proberen" in de balk Geen verbinding: alles meteen, behalve buiten als dat al bekend is. */
  retry() {
    return this.refresh(Object.keys(PARTS).filter((p) => p !== 'buiten' || !this.where))
  }

  #apply(d) {
    if ('status' in d) this.status = d.status
    if ('widgets' in d) this.widgets = d.widgets
    if ('zabbix' in d) this.zbx = d.zabbix?.services || {}
    if ('updates' in d) this.updates = d.updates
    if ('net' in d) this.net = d.net
    if ('cron' in d) this.cron = d.cron
    if ('health' in d) this.health = d.health
    if ('aandacht' in d) this.att = d.aandacht
    if ('meldingen' in d) this.notif = d.meldingen
    if ('buiten' in d) this.where = d.buiten
  }

  #schedule(ms) {
    clearTimeout(this.#timer)
    this.#timer = setTimeout(() => this.#tick(), ms)
  }

  #tick() {
    if (!document.hidden) this.refresh()
    this.#schedule(TICK)
  }

  /** Start het verversen; geeft een stopfunctie. */
  start() {
    const gen = ++this.#gen
    this.#last = {}
    this.#lanes = newLanes()
    this.#failedAt = 0
    this.loadLayout()
    this.#tick()
    const vis = () => { if (!document.hidden) this.refresh() }
    document.addEventListener('visibilitychange', vis)
    return () => {
      if (this.#gen === gen) this.#gen = gen + 1
      clearTimeout(this.#timer)
      document.removeEventListener('visibilitychange', vis)
    }
  }

  // --- Vensters ---------------------------------------------------------------

  /**
   * Opent een venster op naam (id uit windows.js, een andere naam, of fix.window van de server) met een startpunt:
   * tab, q, item, service, hostId, sub, job, filter, host, setup, keep, ...
   */
  open(name, opts = {}) {
    const r = typeof name === 'string' ? resolve(name) : name
    if (!r) return false
    const o = { ...r, ...opts }
    if (o.id === 'notifications') {
      this.notifOpen = true
      return true
    }
    const w = byId[o.id]
    if (!w) return false
    if (w.big) {
      // Een groot venster komt bovenop; een gewoon venster dat openstond, zou het bedekken: dat sluit.
      this.modal = null
      // Alleen dit venster bijwerken: met een nieuw big-object zouden de andere grote vensters hun startpunt opnieuw
      // krijgen (hun tab, filter of open vraag), ook als ze dicht zijn.
      const cur = this.big[o.id]
      const initial = bigStart(o, cur)
      if (cur) {
        cur.open = true
        cur.initial = initial
      } else {
        this.big[o.id] = { used: true, open: true, initial }
      }
      this.order = [...this.order.filter((x) => x !== o.id), o.id]
    } else {
      this.modal = o
    }
    return true
  }

  close(id) {
    if (byId[id]?.big) {
      if (this.big[id]) this.big[id].open = false
      this.order = this.order.filter((x) => x !== id)
    } else if (!id || this.modal?.id === id) {
      this.modal = null
    }
  }

  /** Een knop uit Aandacht, de instellingen-checklist of de veiligheidscheck: het venster dat het oplost. */
  openFix(fix) {
    if (!fix?.window) return this.open('attention')
    const svc = fix.service_id && this.services.find((s) => s.id === fix.service_id)
    if (fix.window === 'detail' || fix.window === 'edit') {
      if (svc) this.open(fix.window === 'detail' ? 'detail' : 'service', { service: svc })
      return
    }
    const opts = {}
    if (fix.tab) opts.tab = fix.tab
    if (fix.host_id) opts.hostId = fix.host_id
    if (fix.job) opts.job = fix.job
    else if (fix.filter) opts.filter = fix.filter
    if (!this.open(fix.window, opts)) this.open('attention')
  }

  /** Klik op een melding (in de bel of een pushbericht). */
  openNotification(n) {
    const w = sourceWindow(n.source)
    if (w) return this.open(w)
    if (n.service_id) {
      const s = this.services.find((x) => x.id === n.service_id)
      if (s) this.open('detail', { service: s })
    }
  }
}

// Het startpunt van een groot venster, zoals de vensters het al verwachten (initial of request).
function bigStart(o, prev) {
  if (o.id === 'logs') return { host: o.host ?? null, q: o.q ?? '', setup: !!o.setup, keep: !!o.keep }
  if (o.id === 'cron') return o.job ? { job: o.job } : o.filter ? { filter: o.filter } : null
  if (o.id === 'health') return o.tab ? { tab: o.tab } : null
  // Terminal: zonder host of venster blijft het vorige verzoek staan (de terminal deed dat al).
  if (o.id === 'terminal') return o.hostId || o.sub ? { hostId: o.hostId ?? null, modal: o.sub ?? null } : prev?.initial ?? null
  return null
}

export const dash = new Dash()
