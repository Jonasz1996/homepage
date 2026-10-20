<script>
  import { onMount, tick, untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import { bits, crumbs, emptyDirs, fileCaller, fromBits, isDir, join, octal, parent, parseOctal, resolve, sortEntries, speed, uploadFile, visible } from './bestanden.js'
  import { copyText } from './copy.js'
  import { ask, askText } from './dialog.svelte.js'
  import { bytes, date } from './format.js'
  import Modal from './Modal.svelte'

  // Bestanden op een host, zoals WinSCP: bladeren, slepen vanaf de pc om te uploaden, downloaden (een map als zip),
  // hernoemen, verwijderen, rechten en kleine tekstbestanden bewerken. Zelfde login en hostsleutel als de terminal.
  let { host, active = true, onstate } = $props()

  const pref = (k, d) => { try { return JSON.parse(localStorage.getItem('hp-files-' + k)) ?? d } catch { return d } }
  const savePref = (k, v) => { try { localStorage.setItem('hp-files-' + k, JSON.stringify(v)) } catch { /* */ } }

  let phase = $state('verbinden')
  let hostkey = $state(null)
  let info = $state(null) // {id, home, user, chunk, edit_max}
  let path = $state('')
  let typed = $state('')
  let editingPath = $state(false)
  let listing = $state(null)
  let loading = $state(false)
  let error = $state('')
  let toast = $state('')
  let back = $state([])
  let fwd = $state([])
  let selected = $state(new Set())
  let anchor = null
  let sortKey = $state(pref('sort', 'name'))
  let sortAsc = $state(pref('asc', true))
  let hidden = $state(pref('hidden', false))
  let filter = $state('')
  let menu = $state(null)
  let editor = $state(null)
  let props = $state(null)
  let conflict = $state(null)
  let dragOver = $state(false)
  let queue = $state([])
  let rate = $state(0)
  let root = $state()
  let pathInput = $state()
  let pickFiles = $state()
  let pickDir = $state()
  let toastTimer
  let seq = 0
  let destroyed = false // het tabblad is dicht: niets meer openen of vernieuwen
  let dropDir = $state(null) // slepen boven een map in de lijst: daarheen uploaden

  const ICON = { dir: '📁', file: '📄', link: '🔗', other: '⚙' }
  const icon = (e) => (e.type === 'link' && e.to === 'dir' ? '📂' : ICON[e.type] || '📄')

  function setPhase(p) {
    phase = p
    onstate?.(p === 'hostkey' ? 'verbinden' : p)
  }

  // Een fout in de balk onderaan. Is het venster dicht (de host veranderde, of verbinden lukte niet), dan blijft de
  // uitleg daarvan staan: "Niet verbonden" van een actie die nog wachtte, zegt niets.
  function fail(e) {
    if (info || !error) error = e?.message ?? String(e)
  }

  function say(text) {
    toast = text
    clearTimeout(toastTimer)
    toastTimer = setTimeout(() => (toast = ''), 2200)
  }

  // --- Verbinden ---------------------------------------------------------------------------------------------------

  async function open(navigate = true) {
    setPhase('verbinden')
    error = ''
    hostkey = null
    try {
      const r = await withReauth(() => api(`/ssh/hosts/${host.id}/files`, { method: 'POST' }))
      if (destroyed) {
        // Intussen gesloten (een trage host): dit venster niet laten openstaan op de server.
        if (r.id) api(`/ssh/files/${r.id}/close`, { method: 'POST' }).catch(() => {})
        return
      }
      if (r.hostkey) { hostkey = r.hostkey; info = null; setPhase('hostkey'); return }
      info = r
      setPhase('verbonden')
      if (navigate) {
        await go(path || r.home, false)
        // De thuismap (of de vorige map) is niet leesbaar: dan bij / beginnen.
        if (!listing) await go('/', false)
      }
    } catch (e) {
      info = null
      error = e.message
      setPhase('fout')
    }
  }

  async function answerKey(ok) {
    const k = hostkey
    hostkey = null
    if (!ok) { error = 'Hostsleutel niet aanvaard'; setPhase('fout'); return }
    try {
      await withReauth(() => api(`/ssh/hosts/${host.id}/files/hostkey`, { method: 'POST', body: { fp: k.fp } }))
      await open()
    } catch (e) { error = e.message; setPhase('fout') }
  }

  // api() voor dit venster (zie fileCaller): verlopen, dan opnieuw openen; de host veranderde, dan dicht.
  const call = fileCaller(api, {
    info: () => info,
    reopen: () => open(false),
    gone: () => destroyed,
    name: () => host.name,
    closed(msg, id) {
      if (id) api(`/ssh/files/${id}/close`, { method: 'POST' }).catch(() => {})
      info = listing = null
      error = msg
      setPhase('fout')
    },
  })

  // --- Bladeren ----------------------------------------------------------------------------------------------------

  // clear: de foutmelding weghalen (een andere map, of zelf vernieuwen). Na een actie niet: die fout hoort erbij.
  async function go(p, remember = true, clear = true) {
    if (!info) return
    loading = true
    if (clear) error = ''
    try {
      const l = await call('/list', { method: 'POST', body: { path: p } })
      if (remember && path && l.path !== path) { back = [...back, path].slice(-50); fwd = [] }
      const keep = l.path === path ? selected : new Set()
      listing = l
      path = typed = l.path
      selected = new Set(l.entries.filter((e) => keep.has(e.name)).map((e) => e.name))
      if (!selected.size) anchor = null
      editingPath = false
    } catch (e) {
      fail(e)
      typed = path
    } finally {
      loading = false
    }
  }

  const refresh = () => go(path, false)
  // Na een actie: de lijst opnieuw, de fout van die actie blijft staan.
  const relist = () => go(path, false, false)

  const up = () => path !== '/' && go(parent(path))

  function goBack() {
    if (!back.length) return
    fwd = [path, ...fwd]
    const p = back.at(-1)
    back = back.slice(0, -1)
    go(p, false)
  }

  function goForward() {
    if (!fwd.length) return
    back = [...back, path]
    const [p, ...rest] = fwd
    fwd = rest
    go(p, false)
  }

  async function editPath() {
    editingPath = true
    typed = path
    await tick()
    pathInput?.focus()
    pathInput?.select()
  }

  function goTyped(e) {
    e.preventDefault()
    if (typed.trim()) go(resolve(path, typed, info?.home))
  }

  let rows = $derived(listing ? sortEntries(visible(listing.entries, { hidden, filter }), sortKey, sortAsc) : [])
  let chosen = $derived(rows.filter((e) => selected.has(e.name) && !e.odd))
  let one = $derived(chosen.length === 1 ? chosen[0] : null)
  let chosenSize = $derived(chosen.reduce((n, e) => n + (isDir(e) ? 0 : e.size), 0))

  function sortBy(k) {
    if (sortKey === k) sortAsc = !sortAsc
    else { sortKey = k; sortAsc = k !== 'mtime' && k !== 'size' }
    savePref('sort', sortKey)
    savePref('asc', sortAsc)
  }

  function toggleHidden() {
    hidden = !hidden
    savePref('hidden', hidden)
  }

  function pick(e, ev) {
    if (ev.shiftKey && anchor != null) {
      const names = rows.map((r) => r.name)
      const [a, b] = [names.indexOf(anchor), names.indexOf(e.name)].sort((x, y) => x - y)
      if (a >= 0) { selected = new Set(names.slice(a, b + 1)); return }
    }
    if (ev.ctrlKey || ev.metaKey) {
      const s = new Set(selected)
      s.has(e.name) ? s.delete(e.name) : s.add(e.name)
      selected = s
    } else selected = new Set([e.name])
    anchor = e.name
  }

  function move(d) {
    if (!rows.length) return
    const i = rows.findIndex((r) => r.name === anchor)
    const j = Math.min(rows.length - 1, Math.max(0, i < 0 ? 0 : i + d))
    selected = new Set([rows[j].name])
    anchor = rows[j].name
    root?.querySelector(`tr[data-i="${j}"]`)?.scrollIntoView({ block: 'nearest' })
  }

  async function activate(e) {
    if (e.odd) { error = 'Deze naam is geen UTF-8: open hem in de terminal'; return }
    if (isDir(e)) return go(join(path, e.name))
    if (e.type === 'link' && e.broken) { error = `${e.name} wijst naar iets dat niet bestaat`; return }
    if (e.type === 'other') { error = `${e.name} is geen gewoon bestand`; return }
    if (e.type === 'file' && e.size > info.edit_max) return download([e.name])
    return edit(e)
  }

  // --- Downloaden en bewerken --------------------------------------------------------------------------------------

  async function download(names = chosen.map((e) => e.name)) {
    if (!names.length) return
    if (names.length > 1000) { error = `${names.length} items is te veel voor één zip (hoogstens 1000): download de map erboven`; return }
    try {
      const r = await call('/download', { method: 'POST', body: { dir: path, names } })
      // Een gewone link: de browser slaat het zelf op (ook een groot bestand), met voortgang in zijn downloads.
      const a = document.createElement('a')
      a.href = r.url
      a.download = r.name
      document.body.append(a)
      a.click()
      a.remove()
      say(r.zip ? `${r.name}: de zip wordt gemaakt terwijl hij downloadt` : `${r.name} wordt gedownload`)
    } catch (e) { fail(e) }
  }

  async function edit(e) {
    const p = join(path, e.name)
    try {
      const r = await call('/read', { method: 'POST', body: { path: p } })
      editor = { path: p, name: e.name, text: r.text, orig: r.text, eol: r.eol, mixed: r.mixed, mtime: r.mtime, size: r.size, error: '', saving: false, conflict: false }
    } catch (err) {
      if (err.status === 413 || err.status === 415) {
        if (await ask(`${e.name}: ${err.message.replace(/: download het$/, '')}. Downloaden?`, { ok: 'Downloaden', title: host.name })) download([e.name])
      } else fail(err)
    }
  }

  async function save(force = false) {
    const ed = editor
    if (!ed || ed.saving) return
    ed.saving = true
    ed.error = ''
    try {
      const r = await call('/write', { method: 'POST', body: { path: ed.path, text: ed.text, eol: ed.eol, mtime: ed.mtime, size: ed.size, force } })
      Object.assign(ed, { mtime: r.mtime, size: r.size, orig: ed.text, conflict: false })
      say(`${ed.name} bewaard`)
      refresh()
    } catch (e) {
      ed.conflict = e.status === 409 && !force
      ed.error = ed.conflict ? `${e.message}. Opnieuw laden (jouw wijzigingen gaan verloren) of toch bewaren?` : e.message
    } finally {
      ed.saving = false
    }
  }

  async function reload() {
    const ed = editor
    try {
      const r = await call('/read', { method: 'POST', body: { path: ed.path } })
      Object.assign(ed, { text: r.text, orig: r.text, eol: r.eol, mixed: r.mixed, mtime: r.mtime, size: r.size, error: '', conflict: false })
    } catch (e) { ed.error = e.message }
  }

  // Het venster ging dicht terwijl de editor openstond (de host veranderde): opnieuw verbinden, je tekst blijft.
  async function reconnectEditor() {
    await open()
    if (editor && info) editor.error = `Opnieuw verbonden als ${info.user}@${host.host}: bewaar opnieuw als dat goed is`
    else if (editor) editor.error = error || (hostkey ? 'Eerst de hostsleutel bevestigen: die vraag staat achter de editor (kopieer je tekst voor je sluit)' : 'Verbinden lukte niet')
  }

  async function closeEditor() {
    if (editor && editor.text !== editor.orig && !(await ask(`Je wijzigingen aan ${editor.name} zijn niet bewaard. Toch sluiten?`, { ok: 'Sluiten', danger: true }))) return
    editor = null
    focus()
  }

  function editorKey(e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); save() }
    else if (e.key === 'Tab' && !e.ctrlKey && !e.altKey && !e.metaKey) {
      // Een tab in het bestand, niet naar de volgende knop springen.
      e.preventDefault()
      e.target.setRangeText('\t', e.target.selectionStart, e.target.selectionEnd, 'end')
      editor.text = e.target.value
    }
  }

  // --- Mappen, hernoemen, verwijderen, rechten ---------------------------------------------------------------------

  const badName = (n) => !n || n === '.' || n === '..' || n.includes('/')

  async function newDir() {
    const name = (await askText('Naam van de nieuwe map', { ok: 'Maken', title: path }))?.trim()
    if (name == null || name === '') return
    if (badName(name)) { error = 'Een naam zonder /'; return }
    try {
      await call('/mkdir', { method: 'POST', body: { path: join(path, name) } })
      await refresh()
      selected = new Set([name])
      anchor = name
    } catch (e) { fail(e) }
  }

  async function newFile() {
    const name = (await askText('Naam van het nieuwe bestand', { ok: 'Maken', title: path }))?.trim()
    if (name == null || name === '') return
    if (badName(name)) { error = 'Een naam zonder /'; return }
    const p = join(path, name)
    try {
      const r = await call('/write', { method: 'POST', body: { path: p, text: '' } })
      await refresh()
      selected = new Set([name])
      anchor = name
      editor = { path: p, name, text: '', orig: '', eol: 'lf', mtime: r.mtime, size: r.size, error: '', saving: false, conflict: false }
    } catch (e) { fail(e) }
  }

  async function rename(e = one) {
    if (!e) return
    const to = (await askText(`Nieuwe naam voor ${e.name}. Een pad (bv. ../oud/${e.name}) verplaatst het.`, { value: e.name, ok: 'Hernoemen', title: host.name }))?.trim()
    if (!to || to === e.name) return
    const body = { path: join(path, e.name), to: resolve(path, to, info.home) }
    try {
      await call('/rename', { method: 'POST', body })
    } catch (err) {
      if (err.status !== 409) { fail(err); return }
      if (!(await ask(`${err.message}. Overschrijven?`, { ok: 'Overschrijven', danger: true, title: host.name }))) return
      try { await call('/rename', { method: 'POST', body: { ...body, overwrite: true } }) } catch (err2) { fail(err2); return }
    }
    await refresh()
  }

  async function remove(list = chosen) {
    if (!list.length) return
    const dirs = list.some((e) => e.type === 'dir')
    const what = list.length === 1 ? list[0].name : `${list.length} items`
    const msg = `${what} verwijderen op ${host.name}?${dirs ? ' Mappen gaan weg met al hun inhoud.' : ''} Dit kan je niet ongedaan maken.`
    if (!(await ask(msg, { ok: 'Verwijderen', danger: true, title: path }))) return
    const paths = list.map((e) => join(path, e.name))
    if (info) error = ''
    try {
      // Per 500 (de server neemt er hoogstens 1000 per keer): ook na Ctrl+A in een grote map.
      for (let i = 0; i < paths.length; i += 500) await call('/delete', { method: 'POST', body: { paths: paths.slice(i, i + 500), recursive: dirs } })
    } catch (e) { fail(e) }
    await relist()
  }

  function showProps(e = one) {
    if (e) props = { e, rows: bits(e.mode ?? 0), text: octal(e.mode ?? 0), saving: false, error: '' }
  }

  function bitsChanged() {
    props.text = octal(fromBits(props.rows, props.e.mode ?? 0))
  }

  function octalTyped() {
    const m = parseOctal(props.text)
    if (m != null) props.rows = bits(m)
  }

  async function saveMode() {
    const p = props
    if (parseOctal(p.text) == null) { p.error = 'Drie of vier cijfers van 0 tot 7, bv. 644'; return }
    p.saving = true
    try {
      await call('/chmod', { method: 'POST', body: { path: join(path, p.e.name), mode: p.text.trim() } })
      if (props === p) props = null
      await refresh()
      focus()
    } catch (e) {
      // Intussen gesloten: dan de fout in de balk onderaan.
      if (props === p) { p.error = e.message; p.saving = false } else fail(new Error(`${p.e.name}: ${e.message}`))
    }
  }

  async function copyPath(e = one) {
    if (await copyText(e ? join(path, e.name) : path)) say('pad gekopieerd')
  }

  // --- Uploaden ----------------------------------------------------------------------------------------------------

  // Twee bestanden tegelijk, elk in stukken van 3 MiB (drie tegelijk): zo vult het de lijn ook met kleine bestanden.
  const FILES_AT_ONCE = 2
  let running = 0
  let conflictChain = Promise.resolve()
  // Per keer kiezen of slepen: "alles overschrijven" of "alles overslaan". Geen $state: elk item in de wachtrij
  // kreeg anders zijn eigen kopie, en gold het antwoord alleen voor dat ene bestand.
  const policies = new Map()
  let batches = 0

  function enqueue(files, dirs = [], dir = path) {
    if (!info || (!files.length && !dirs.length)) return
    // "alles overschrijven" of "alles overslaan" geldt voor wat samen gekozen of gesleept werd, niet voor wat later komt.
    const batch = ++batches
    for (const d of emptyDirs(dirs, files)) queue.push({ uid: ++seq, rel: d, dir, size: 0, done: 0, state: 'wachten', mkdir: true, batch })
    for (const f of files) queue.push({ uid: ++seq, file: f.file, rel: f.rel, dir, size: f.file.size, done: 0, state: 'wachten', batch })
    pump()
  }

  function pump() {
    while (running < FILES_AT_ONCE) {
      const item = queue.find((q) => q.state === 'wachten')
      if (!item) break
      running++
      item.state = 'bezig'
      run(item).finally(() => {
        running--
        pump()
        if (!running && !destroyed) relist()
      })
    }
  }

  async function run(item, overwrite = false) {
    const ctrl = new AbortController()
    item.ctrl = ctrl
    try {
      if (item.mkdir) {
        await call('/mkdir', { method: 'POST', body: { path: join(item.dir, item.rel), parents: true } })
        item.state = 'klaar'
        return
      }
      const r = await uploadFile(call, { file: item.file, dir: item.dir, rel: item.rel, overwrite }, { signal: ctrl.signal, onbytes: (n) => (item.done += n) })
      if (r.exists) {
        item.state = 'bestaat al'
        const choice = await askConflict(item, r.exists)
        if (ctrl.signal.aborted) { item.state = 'geannuleerd'; return }
        if (choice === 'one' || choice === 'all') { item.state = 'bezig'; item.done = 0; return await run(item, true) }
        item.state = 'overgeslagen'
        return
      }
      item.state = 'klaar'
      item.done = item.size
    } catch (e) {
      if (e?.name === 'AbortError' || ctrl.signal.aborted) item.state = 'geannuleerd'
      else { item.state = 'fout'; item.error = e.message }
    }
  }

  // Eén vraag tegelijk, ook als twee uploads tegelijk op een bestaand bestand stoten.
  function askConflict(item, exists) {
    // Intussen geannuleerd ("alles annuleren"): niet meer vragen.
    const p = conflictChain.then(() => (item.ctrl?.signal.aborted ? 'none' : policies.get(item.batch))
      || new Promise((res) => (conflict = { item, exists, resolve: res })))
    conflictChain = p.catch(() => {})
    return p
  }

  function answerConflict(choice) {
    const c = conflict
    conflict = null
    if (choice === 'all' || choice === 'none') policies.set(c.item.batch, choice)
    c.resolve(choice)
  }

  function cancel(item) {
    if (item.state === 'wachten') item.state = 'geannuleerd'
    else item.ctrl?.abort()
  }

  function cancelAll() {
    queue.forEach(cancel)
    if (conflict) answerConflict('none')
  }
  const clearDone = () => (queue = queue.filter((q) => q.state === 'wachten' || q.state === 'bezig' || q.state === 'bestaat al'))

  let busy = $derived(queue.some((q) => q.state === 'wachten' || q.state === 'bezig' || q.state === 'bestaat al'))
  let totals = $derived.by(() => {
    const live = queue.filter((q) => q.state !== 'overgeslagen' && q.state !== 'geannuleerd')
    return { size: live.reduce((n, q) => n + q.size, 0), done: live.reduce((n, q) => n + q.done, 0),
             files: live.filter((q) => !q.mkdir).length, ready: live.filter((q) => !q.mkdir && q.state === 'klaar').length,
             failed: queue.filter((q) => q.state === 'fout').length }
  })

  // Snelheid: wat er de laatste seconden bijkwam.
  $effect(() => {
    if (!busy) { rate = 0; return }
    let last = untrack(() => totals.done)
    let at = performance.now()
    const t = setInterval(() => {
      const now = performance.now()
      const d = totals.done
      // Na "wis klaar", annuleren of opnieuw beginnen daalt het totaal: dat is geen negatieve snelheid.
      const r = Math.max(0, d - last) / ((now - at) / 1000)
      rate = rate ? rate * 0.6 + r * 0.4 : r
      last = d
      at = now
    }, 1000)
    return () => clearInterval(t)
  })

  // Een upload loopt: niet zomaar de pagina sluiten.
  $effect(() => {
    if (!busy) return
    const warn = (e) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  })

  function pickedFiles(e) {
    enqueue([...e.target.files].map((f) => ({ file: f, rel: f.webkitRelativePath || f.name })))
    e.target.value = ''
  }

  // Slepen vanaf de pc: bestanden en mappen (met hun inhoud).
  async function walkEntries(entries) {
    const files = [], dirs = []
    const readAll = (reader) => new Promise((res, rej) => {
      const out = []
      const more = () => reader.readEntries((b) => { if (!b.length) res(out); else { out.push(...b); more() } }, rej)
      more()
    })
    async function walk(entry, prefix) {
      if (entry.isFile) files.push({ file: await new Promise((res, rej) => entry.file(res, rej)), rel: prefix + entry.name })
      else if (entry.isDirectory) {
        dirs.push(prefix + entry.name)
        for (const c of await readAll(entry.createReader())) await walk(c, prefix + entry.name + '/')
      }
    }
    for (const e of entries) await walk(e, '')
    return { files, dirs }
  }

  const fromPc = (ev) => [...(ev.dataTransfer?.types || [])].includes('Files')

  // Overal in het venster (ook op de knoppen of de wachtrij): anders opent de browser het bestand zelf, en zijn de
  // pagina en elke terminal weg.
  function dragover(ev) {
    if (!fromPc(ev)) return
    ev.preventDefault()
    if (!info || !listing) { ev.dataTransfer.dropEffect = 'none'; return }
    ev.dataTransfer.dropEffect = 'copy'
    dragOver = true
    // Boven een map in de lijst: daarheen (de rij licht op, de melding zegt het).
    dropDir = ev.target.closest?.('tr[data-dir]')?.dataset.dir ?? null
  }

  // Daarbuiten (een open dialoog zoals de editor, of elders op het scherm), zolang je dit tabblad ziet: niets doen, maar
  // ook niet de browser het bestand laten openen.
  function guardDrop(ev) {
    if (!active || !fromPc(ev) || ev.defaultPrevented) return
    ev.preventDefault()
    ev.dataTransfer.dropEffect = 'none'
  }

  async function drop(ev) {
    if (!fromPc(ev)) return
    ev.preventDefault()
    const row = ev.target.closest?.('tr[data-dir]')?.dataset.dir
    dragOver = false
    dropDir = null
    if (!info || !listing) return
    const dir = row ? join(path, row) : path
    // Meteen lezen: na de eerste await zijn de items van het slepen niet meer geldig.
    const entries = [...ev.dataTransfer.items].filter((i) => i.kind === 'file').map((i) => i.webkitGetAsEntry?.()).filter(Boolean)
    const plain = [...ev.dataTransfer.files]
    try {
      const { files, dirs } = entries.length ? await walkEntries(entries) : { files: plain.map((f) => ({ file: f, rel: f.name })), dirs: [] }
      enqueue(files, dirs, dir)
    } catch (e) { fail(new Error(`Slepen lukte niet: ${e.message}`)) }
  }

  // --- Menu en toetsen ---------------------------------------------------------------------------------------------

  function openMenu(ev, e = null) {
    ev.preventDefault()
    if (e && !selected.has(e.name)) { selected = new Set([e.name]); anchor = e.name }
    if (!e) { selected = new Set(); anchor = null }
    const r = root.getBoundingClientRect()
    menu = { x: Math.min(ev.clientX - r.left, r.width - 210), y: Math.min(ev.clientY - r.top, r.height - 260), e }
  }

  // Het item van het menu eerst bewaren: na menu = null is menu.e weg.
  function menuDo(fn) {
    const e = menu?.e
    menu = null
    fn(e)
  }

  function key(ev) {
    if (!active || !info || editor || props || conflict) return
    if (ev.key === 'Escape') { menu = null; return }
    if (ev.target.closest?.('input, textarea, select')) return
    const k = ev.key
    // Op een knop doen Enter en spatie wat de knop doet.
    if ((k === 'Enter' || k === ' ') && ev.target.closest?.('button')) return
    if (k === 'Enter' && one) activate(one)
    else if (k === 'Backspace' || (k === 'ArrowUp' && ev.altKey)) up()
    else if (k === 'ArrowLeft' && ev.altKey) goBack()
    else if (k === 'ArrowRight' && ev.altKey) goForward()
    else if (k === 'Delete') remove()
    else if (k === 'F2') rename()
    else if (k === 'F5') refresh()
    else if (k === 'F7') newDir()
    else if (k === 'ArrowDown') move(1)
    else if (k === 'ArrowUp') move(-1)
    else if (k === 'a' && (ev.ctrlKey || ev.metaKey)) selected = new Set(rows.map((r) => r.name))
    else return
    ev.preventDefault()
  }

  // --- Voor het venster eromheen -----------------------------------------------------------------------------------

  export function focus() {
    if (active && !editingPath) root?.focus({ preventScroll: true })
  }

  export function reconnect() {
    open()
  }

  /** Lopen er nog uploads? (de terminal vraagt het voor het tabblad sluit). */
  export function uploading() {
    return busy
  }

  onMount(() => {
    if (pickDir) pickDir.webkitdirectory = true
    open()
    return () => {
      destroyed = true
      clearTimeout(toastTimer)
      cancelAll()
      if (info) api(`/ssh/files/${info.id}/close`, { method: 'POST' }).catch(() => {})
    }
  })

  $effect(() => {
    if (active && phase === 'verbonden') queueMicrotask(focus)
  })

  const stateClass = { klaar: 'ok', fout: 'err', bezig: 'mid', 'bestaat al': 'mid' }
  const safe = (node) => { queueMicrotask(() => node.focus({ preventScroll: true })) }
</script>

<svelte:window onclick={() => (menu = null)} ondragover={guardDrop} ondrop={guardDrop} />

<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_static_element_interactions -->
<div class="sess" class:hidden={!active} bind:this={root} tabindex="-1" onkeydown={key} ondragover={dragover}
     ondragleave={(e) => !e.currentTarget.contains(e.relatedTarget) && ((dragOver = false), (dropDir = null))} ondrop={drop}>
  {#if info && listing}
    <div class="bar">
      <span class="grp">
        <button class="mini" onclick={goBack} disabled={!back.length} title="Terug (Alt+←)">←</button>
        <button class="mini" onclick={goForward} disabled={!fwd.length} title="Vooruit (Alt+→)">→</button>
        <button class="mini" onclick={up} disabled={path === '/'} title="Map hoger (Backspace)">↑</button>
        <button class="mini" onclick={() => go(info.home)} title="Thuismap van {info.user} ({info.home})">⌂</button>
        <button class="mini" onclick={() => refresh()} title="Vernieuwen (F5)">⟳</button>
      </span>
      <span class="grp">
        <button class="mini" onclick={newDir} title="Nieuwe map (F7)">+ map</button>
        <button class="mini" onclick={newFile} title="Nieuw tekstbestand">+ bestand</button>
        <button class="mini" onclick={() => pickFiles.click()} title="Bestanden van je pc uploaden (of sleep ze hierheen)">⇪ uploaden</button>
        <button class="mini" onclick={() => pickDir.click()} title="Een map van je pc uploaden, met de inhoud">⇪ map</button>
      </span>
      <span class="grp">
        <button class="mini" onclick={() => download()} disabled={!chosen.length} title="Downloaden (meerdere of een map: als zip)">↓ downloaden</button>
        <button class="mini" onclick={() => one && activate(one)} disabled={!one || isDir(one)} title="Bewerken (Enter)">✎</button>
        <button class="mini" onclick={() => rename()} disabled={!one} title="Hernoemen of verplaatsen (F2)">⇄</button>
        <button class="mini" onclick={() => showProps()} disabled={!one} title="Eigenschappen en rechten">ⓘ</button>
        <button class="mini x" onclick={() => remove()} disabled={!chosen.length} title="Verwijderen (Delete)">🗑</button>
      </span>
      <span class="grp grow">
        <input class="flt" bind:value={filter} placeholder="filter…" aria-label="Bestanden filteren" />
        <button class="mini" class:on={hidden} onclick={toggleHidden} title="Verborgen bestanden (met een punt) tonen">.*</button>
      </span>
    </div>
    <div class="loc">
      {#if editingPath}
        <form onsubmit={goTyped}>
          <input bind:this={pathInput} bind:value={typed} spellcheck="false" aria-label="Pad"
                 onkeydown={(e) => e.key === 'Escape' && ((editingPath = false), focus())} onblur={() => (editingPath = false)} />
        </form>
      {:else}
        <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
        <div class="crumbs" onclick={(e) => e.target === e.currentTarget && editPath()} title="Klik naast het pad om het te typen">
          {#each crumbs(path) as c, i (c.path)}
            {#if i > 1}<span class="sl">/</span>{/if}
            <button class="cr" onclick={() => go(c.path)}>{c.name}</button>
          {/each}
          <button class="mini ed" onclick={editPath} title="Pad typen">✎</button>
          <button class="mini ed" onclick={() => copyPath(null)} title="Pad kopiëren">⧉</button>
        </div>
      {/if}
    </div>
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="list" class:over={dragOver} oncontextmenu={(e) => e.target.closest('tr') || openMenu(e)}>
      <table>
        <thead>
          <tr>
            {#each [['name', 'Naam'], ['size', 'Grootte'], ['mtime', 'Gewijzigd'], ['perms', 'Rechten'], ['owner', 'Eigenaar']] as [k, label] (k)}
              <th class={k}><button onclick={() => sortBy(k)}>{label}{sortKey === k ? (sortAsc ? ' ▲' : ' ▼') : ''}</button></th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#if path !== '/'}
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <tr class="up" ondblclick={up}><td class="name" colspan="5"><span class="ic">↰</span>..</td></tr>
          {/if}
          {#each rows as e, i (e.odd ? `${i}:${e.name}` : e.name)}
            <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
            <tr data-i={i} data-dir={isDir(e) && !e.odd ? e.name : undefined} class:sel={selected.has(e.name)} class:odd={e.odd}
                class:hid={e.name.startsWith('.')} class:target={dragOver && dropDir === e.name}
                onclick={(ev) => pick(e, ev)} ondblclick={() => activate(e)} oncontextmenu={(ev) => openMenu(ev, e)}>
              <td class="name" title={e.type === 'link' ? `${e.name} → ${e.target ?? '?'}` : e.name}>
                <span class="ic">{icon(e)}</span>{e.name}{#if e.type === 'link'}<small class:broken={e.broken}> → {e.target ?? '?'}</small>{/if}
              </td>
              <td class="size">{isDir(e) || e.type === 'link' ? '' : bytes(e.size)}</td>
              <td class="mtime">{e.mtime ? date(e.mtime) : ''}</td>
              <td class="perms">{e.perms}</td>
              <td class="owner">{e.owner}{e.group && e.group !== e.owner ? `:${e.group}` : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if !rows.length}
        <p class="empty">{listing.entries.length ? 'Niets dat past bij de filter (of alleen verborgen bestanden: .*).' : 'Lege map. Sleep bestanden of mappen van je pc hierheen om ze te uploaden.'}</p>
      {/if}
      {#if dragOver}<div class="drop">Loslaten om te uploaden naar <b>{dropDir ? join(path, dropDir) : path}</b></div>{/if}
    </div>
    {#if queue.length}
      <div class="queue">
        <div class="qh">
          <span>
            {#if busy}⇪ {totals.ready} van {totals.files} · {bytes(totals.done)} van {bytes(totals.size)}{rate ? ` · ${speed(rate)}` : ''}
            {:else}⇪ {totals.ready} van {totals.files} geüpload{totals.failed ? `, ${totals.failed} mislukt` : ''}{/if}
          </span>
          <span class="grp">
            {#if busy}<button class="mini x" onclick={cancelAll}>alles annuleren</button>{/if}
            <button class="mini" onclick={clearDone} disabled={busy && queue.every((q) => q.state === 'wachten' || q.state === 'bezig')}>wis klaar</button>
          </span>
        </div>
        {#if busy}<div class="bar-total"><i style:width="{totals.size ? (100 * totals.done) / totals.size : 0}%"></i></div>{/if}
        <div class="qi">
          {#each queue as q (q.uid)}
            <div class="q">
              <span class="qn" title="{q.dir === '/' ? '' : q.dir}/{q.rel}">{q.mkdir ? '📁 ' : ''}{q.rel}</span>
              <span class="qs {stateClass[q.state] || ''}" title={q.error || ''}>
                {q.state === 'bezig' && q.size ? `${Math.floor((100 * q.done) / q.size)}%` : q.state}{q.error ? `: ${q.error}` : ''}
              </span>
              {#if q.state === 'wachten' || q.state === 'bezig'}
                <button class="tx" onclick={() => cancel(q)} aria-label="Annuleren">✕</button>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}
    <div class="status">
      <span>{rows.length} items{listing.truncated ? ` (alleen de eerste ${listing.entries.length}: de rest zie je in de terminal)` : ''}{chosen.length ? ` · ${chosen.length} geselecteerd${chosenSize ? ` (${bytes(chosenSize)})` : ''}` : ''}</span>
      <span class="who">{info.user}@{host.host}{listing.free != null ? ` · ${bytes(listing.free)} vrij` : ''}</span>
    </div>
    {#if error}<div class="errbar"><span>{error}</span><button class="tx" onclick={() => (error = '')} aria-label="Sluiten">✕</button></div>{/if}
    {#if loading}<div class="loading">laden…</div>{/if}
  {:else}
    <div class="center">
      {#if hostkey}
        <div class="hk card">
          <p>Eerste verbinding met <b>{host.name}</b> ({host.host}). Klopt deze hostsleutel?</p>
          <code class="fp">{hostkey.alg} {hostkey.fp}</code>
          <p class="hint">Dit is de vingerafdruk van de server zelf, geen login-sleutel. Controleer op de server met
            <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>.</p>
          <div class="row">
            <button class="btn" onclick={() => answerKey(true)}>Aanvaarden</button>
            <button class="btn alt" onclick={() => answerKey(false)}>Weigeren</button>
          </div>
        </div>
      {:else if phase === 'fout' || (phase === 'verbonden' && !loading)}
        <p class="err">{error || 'Geen map leesbaar'}</p>
        <button class="btn alt" onclick={() => open()}>Opnieuw verbinden</button>
      {:else}
        <p class="hint">Verbinden met {host.name} ({host.host}) over SFTP…</p>
      {/if}
    </div>
  {/if}

  {#if menu}
    <div class="menu card" style:left="{menu.x}px" style:top="{menu.y}px" role="menu">
      {#if menu.e}
        {#if !menu.e.odd}
          <button onclick={() => menuDo((e) => activate(e))}>{isDir(menu.e) ? 'Openen' : 'Bewerken'}</button>
          <button onclick={() => menuDo(() => download())}>Downloaden{chosen.length > 1 || isDir(menu.e) ? ' (zip)' : ''}</button>
          {#if chosen.length === 1}
            <button onclick={() => menuDo((e) => rename(e))}>Hernoemen of verplaatsen</button>
            <button onclick={() => menuDo((e) => showProps(e))}>Eigenschappen en rechten</button>
            <button onclick={() => menuDo((e) => copyPath(e))}>Pad kopiëren</button>
          {/if}
          <button class="danger" onclick={() => menuDo(() => remove())}>Verwijderen{chosen.length > 1 ? ` (${chosen.length})` : ''}</button>
        {:else}
          <p class="hint">Deze naam is geen UTF-8: gebruik de terminal.</p>
        {/if}
      {:else}
        <button onclick={() => menuDo(() => newDir())}>Nieuwe map</button>
        <button onclick={() => menuDo(() => newFile())}>Nieuw bestand</button>
        <button onclick={() => menuDo(() => pickFiles.click())}>Bestanden uploaden</button>
        <button onclick={() => menuDo(() => pickDir.click())}>Map uploaden</button>
        <button onclick={() => menuDo(() => copyPath(null))}>Pad kopiëren</button>
        <button onclick={() => menuDo(() => refresh())}>Vernieuwen</button>
      {/if}
    </div>
  {/if}
  {#if toast}<div class="toast">{toast}</div>{/if}
  <input type="file" multiple hidden bind:this={pickFiles} onchange={pickedFiles} />
  <input type="file" multiple hidden bind:this={pickDir} onchange={pickedFiles} />
</div>

{#if editor}
  <Modal title="{host.name}: {editor.path}" wide onclose={closeEditor}>
    <textarea class="code" bind:value={editor.text} onkeydown={editorKey} spellcheck="false" wrap="off" aria-label="Inhoud van {editor.name}"></textarea>
    <p class="err">{editor.error}</p>
    <div class="row">
      {#if editor.conflict}
        <button class="btn danger" onclick={() => save(true)} disabled={editor.saving}>Toch bewaren</button>
        <button class="btn alt" onclick={reload}>Opnieuw laden</button>
      {:else}
        <button class="btn" onclick={() => save()} disabled={editor.saving || editor.text === editor.orig}>{editor.saving ? 'Bewaren…' : 'Bewaren (Ctrl+S)'}</button>
      {/if}
      {#if !info && phase === 'fout'}
        <button class="btn alt" onclick={reconnectEditor}>Opnieuw verbinden</button>
      {/if}
      <button class="btn alt" onclick={closeEditor}>Sluiten</button>
      <span class="hint end">{editor.mixed ? `gemengde regeleindes: bewaren maakt ze allemaal ${editor.eol === 'crlf' ? 'CRLF' : 'LF'} · ` : editor.eol === 'crlf' ? 'Windows-regeleindes (CRLF) · ' : ''}{bytes(editor.size)}{editor.text !== editor.orig ? ' · niet bewaard' : ''}</span>
    </div>
  </Modal>
{/if}

{#if props}
  <Modal title={props.e.name} small onclose={() => { props = null; focus() }}>
    <dl class="props">
      <dt>pad</dt><dd>{join(path, props.e.name)}</dd>
      <dt>soort</dt><dd>{props.e.type === 'dir' ? 'map' : props.e.type === 'link' ? `symlink naar ${props.e.target ?? '?'}${props.e.broken ? ' (bestaat niet)' : ''}` : props.e.type === 'file' ? 'bestand' : 'speciaal bestand'}</dd>
      {#if props.e.type === 'file'}<dt>grootte</dt><dd>{bytes(props.e.size)} ({props.e.size.toLocaleString('nl-BE')} bytes)</dd>{/if}
      <dt>gewijzigd</dt><dd>{props.e.mtime ? date(props.e.mtime) : '—'}</dd>
      <dt>eigenaar</dt><dd>{props.e.owner}:{props.e.group}</dd>
    </dl>
    {#if props.e.type !== 'link'}
      <table class="rwx">
        <thead><tr><th></th><th>lezen</th><th>schrijven</th><th>uitvoeren</th></tr></thead>
        <tbody>
          {#each ['eigenaar', 'groep', 'anderen'] as who, i (who)}
            <tr><th>{who}</th>{#each [0, 1, 2] as j (j)}<td><input type="checkbox" checked={props.rows[i][j]} aria-label="{who} {['lezen', 'schrijven', 'uitvoeren'][j]}"
                                                                     onchange={(ev) => { props.rows[i][j] = ev.currentTarget.checked; bitsChanged() }} /></td>{/each}</tr>
          {/each}
        </tbody>
      </table>
      <label class="lbl" for="fs-mode">octaal</label>
      <input id="fs-mode" class="oct" value={props.text} inputmode="numeric"
             oninput={(ev) => { props.text = ev.currentTarget.value; octalTyped() }} />
      <p class="err">{props.error}</p>
      <div class="row">
        <button class="btn" onclick={saveMode} disabled={props.saving || props.text.trim() === octal(props.e.mode ?? 0)}>Rechten zetten</button>
        <button class="btn alt" onclick={() => { props = null; focus() }}>Sluiten</button>
      </div>
    {:else}
      <p class="hint">De rechten van een symlink zelf tellen niet: open het doel om die te wijzigen.</p>
    {/if}
  </Modal>
{/if}

<!-- Alleen als je dit tabblad ziet: anders wacht de vraag (de lijst onderaan toont "bestaat al"). -->
{#if conflict && active}
  <Modal title="Bestaat al" small onclose={() => answerConflict('skip')}>
    <p><b>{conflict.item.rel}</b> bestaat al in {conflict.item.dir}.</p>
    <p class="hint">Op {host.name}: {bytes(conflict.exists.size)}{conflict.exists.mtime ? `, gewijzigd ${date(conflict.exists.mtime)}` : ''}.<br />
      Van je pc: {bytes(conflict.item.size)}{conflict.item.file?.lastModified ? `, gewijzigd ${date(conflict.item.file.lastModified / 1000)}` : ''}.</p>
    <div class="row">
      <button class="btn danger" onclick={() => answerConflict('one')}>Overschrijven</button>
      <!-- De vraag komt vanzelf, ook terwijl je typt: Enter mag dan niets overschrijven. -->
      <button class="btn alt" onclick={() => answerConflict('skip')} use:safe>Overslaan</button>
    </div>
    <div class="row">
      <button class="mini" onclick={() => answerConflict('all')}>alles overschrijven</button>
      <button class="mini" onclick={() => answerConflict('none')}>alles overslaan</button>
    </div>
  </Modal>
{/if}

<style>
  .sess { position: absolute; inset: 0; display: flex; flex-direction: column; background: #0c0c0c; outline: none; font-size: 12.5px }
  .sess.hidden { visibility: hidden; pointer-events: none }
  .bar { display: flex; flex-wrap: wrap; gap: 6px 12px; padding: 6px 8px; border-bottom: 1px solid rgba(255, 255, 255, .05) }
  .grp { display: flex; gap: 4px; align-items: center }
  .grow { flex: 1; justify-content: flex-end; min-width: 160px }
  .flt { max-width: 220px; padding: 4px 8px; font-size: 12px }
  .mini:disabled { opacity: .35; cursor: default }
  .loc { padding: 4px 8px; border-bottom: 1px solid rgba(255, 255, 255, .05); min-height: 32px }
  .loc input { padding: 4px 8px; font-family: var(--mono); font-size: 12.5px }
  .crumbs { display: flex; align-items: center; flex-wrap: wrap; gap: 0 2px; font-family: var(--mono); cursor: text; min-height: 24px }
  .cr { background: none; border: 0; color: var(--text); font: inherit; padding: 2px 4px; border-radius: 5px; cursor: pointer }
  .cr:hover { background: var(--fill-h); color: #fff }
  .sl { color: var(--dim) }
  .ed { margin-left: 6px; padding: 2px 7px; opacity: .6 }
  .ed + .ed { margin-left: 2px }
  .list { flex: 1; overflow: auto; position: relative; min-height: 0 }
  .list.over { box-shadow: inset 0 0 0 2px rgba(143, 214, 164, .5) }
  table { width: 100%; border-collapse: collapse; table-layout: fixed }
  th { position: sticky; top: 0; background: #141414; z-index: 1; text-align: left; font-weight: 500; border-bottom: 1px solid var(--line) }
  th button { background: none; border: 0; color: var(--muted); font: inherit; font-size: 11.5px; padding: 6px 8px; cursor: pointer; width: 100%; text-align: inherit }
  th button:hover { color: #fff }
  th.size, td.size { width: 90px; text-align: right }
  th.mtime, td.mtime { width: 130px }
  th.perms, td.perms { width: 100px }
  th.owner, td.owner { width: 130px }
  td { padding: 3px 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text); border-bottom: 1px solid rgba(255, 255, 255, .025) }
  td.perms, td.size { font-family: var(--mono); font-size: 11.5px; color: var(--muted) }
  td.mtime, td.owner { color: var(--muted) }
  tbody tr { cursor: default; user-select: none }
  tbody tr:hover { background: rgba(255, 255, 255, .04) }
  tr.sel, tr.sel:hover { background: rgba(90, 122, 154, .35) }
  tr.sel td { color: #fff }
  tr.hid td.name { opacity: .65 }
  tr.odd td.name { color: var(--mid) }
  .ic { display: inline-block; width: 1.6em }
  td.name small { color: var(--dim); margin-left: 4px }
  td.name small.broken { color: var(--err) }
  tr.up td { color: var(--muted) }
  .empty { color: var(--muted); text-align: center; margin: 40px 20px }
  /* Loslaten op de melding zelf: naar de map die ze noemt (de rijen eronder zijn dan geen doel). */
  .drop { position: absolute; inset: 40px 20px auto; padding: 18px; text-align: center; border: 2px dashed rgba(143, 214, 164, .6); border-radius: 12px;
          background: rgba(12, 12, 12, .9); color: var(--ok) }
  tr.target, tr.target:hover { background: rgba(143, 214, 164, .18) }
  .queue { border-top: 1px solid var(--line); background: #101010; max-height: 30%; display: flex; flex-direction: column; min-height: 0 }
  .qh { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 5px 8px; color: var(--text) }
  .bar-total { height: 3px; background: rgba(255, 255, 255, .06) }
  .bar-total i { display: block; height: 100%; background: var(--ok); transition: width .3s }
  .qi { overflow: auto; padding: 2px 8px 6px }
  .q { display: flex; gap: 8px; align-items: center; padding: 1px 0 }
  .qn { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted) }
  .qs { flex: none; max-width: 50%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dim) }
  .qs.ok { color: var(--ok) }
  .qs.err { color: var(--err) }
  .qs.mid { color: var(--mid) }
  .tx { background: none; border: 0; color: var(--dim); cursor: pointer; font: inherit; padding: 0 4px }
  .tx:hover { color: var(--text-h) }
  .status { display: flex; justify-content: space-between; gap: 10px; padding: 4px 8px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11.5px }
  .who { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .errbar { position: absolute; left: 12px; right: 12px; bottom: 34px; display: flex; gap: 8px; justify-content: space-between; align-items: flex-start;
            padding: 8px 12px; border-radius: 8px; background: rgba(60, 20, 20, .95); border: 1px solid rgba(229, 139, 139, .45); color: var(--err); z-index: 3 }
  .loading { position: absolute; right: 14px; top: 84px; color: var(--dim); font-size: 11.5px; pointer-events: none }
  .center { margin: 14vh auto 0; text-align: center; padding: 0 20px; max-width: 600px }
  .hk { padding: 16px 18px; text-align: left }
  .hk code.fp { display: block; word-break: break-all; color: var(--ok); margin: 8px 0 }
  .hk p { margin: 0 0 6px; font-size: 13px }
  .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 8px }
  .end { margin: 0 0 0 auto }
  .menu { position: absolute; z-index: 5; min-width: 200px; padding: 6px; display: flex; flex-direction: column; gap: 1px }
  .menu button { background: none; border: 0; text-align: left; padding: 6px 10px; border-radius: 6px; cursor: pointer; color: var(--text); font: inherit }
  .menu button:hover { background: var(--fill-h); color: #fff }
  .menu button.danger:hover { color: var(--err) }
  .menu .hint { margin: 4px 8px }
  .toast { position: absolute; right: 18px; bottom: 40px; padding: 5px 10px; border-radius: 7px; font-size: 12px; z-index: 4;
           background: rgba(143, 214, 164, .15); border: 1px solid rgba(143, 214, 164, .4); color: var(--ok); pointer-events: none }
  textarea.code { font-family: var(--mono); font-size: 12.5px; height: 62vh; white-space: pre; tab-size: 4; resize: vertical }
  .props { display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; margin: 0 0 10px; font-size: 13px }
  .props dt { color: var(--muted) }
  .props dd { margin: 0; word-break: break-all }
  .rwx { border-collapse: collapse; margin: 6px 0; table-layout: auto; width: auto }
  .rwx th, .rwx td { padding: 4px 10px; text-align: center; position: static; background: none; border: 0; font-size: 12.5px; color: var(--muted) }
  .rwx tbody th { text-align: left }
  .oct { max-width: 120px; font-family: var(--mono) }
  @media (max-width: 700px) {
    th.perms, td.perms, th.owner, td.owner { display: none }
    th.mtime, td.mtime { width: 110px }
    .grow { min-width: 100% }
    .flt { max-width: none }
  }
</style>
