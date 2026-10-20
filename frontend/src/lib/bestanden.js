// Hulp voor het bestandenvenster (FileSession.svelte): paden, sorteren, rechten, uploaden in stukken, en api() voor
// één venster. Zonder Svelte of DOM, zodat npm test (node --test) het kan nakijken.
import { ApiError } from './api.js'

export const join = (dir, name) => (dir === '/' ? '' : dir) + '/' + name
export const parent = (path) => (path === '/' ? null : path.slice(0, path.lastIndexOf('/')) || '/')

// Een map, of een symlink naar een map: dubbelklikken opent hem.
export const isDir = (e) => e.type === 'dir' || (e.type === 'link' && e.to === 'dir')

/** Broodkruimels: [{name: '/', path: '/'}, {name: 'etc', path: '/etc'}, ...]. */
export function crumbs(path) {
  const out = [{ name: '/', path: '/' }]
  let cur = ''
  for (const part of path.split('/').filter(Boolean)) {
    cur += '/' + part
    out.push({ name: part, path: cur })
  }
  return out
}

/** Een getypt pad naar een absoluut pad: "../x" of "x" tegenover dir, "~" is de thuismap. */
export function resolve(dir, typed, home = '/') {
  let p = typed.trim()
  if (p === '~' || p.startsWith('~/')) p = home + p.slice(1)
  if (!p.startsWith('/')) p = join(dir, p)
  const out = []
  for (const part of p.split('/')) {
    if (!part || part === '.') continue
    if (part === '..') out.pop()
    else out.push(part)
  }
  return '/' + out.join('/')
}

const collator = new Intl.Collator('nl', { numeric: true, sensitivity: 'base' })

/** Mappen eerst, dan op de gekozen kolom (naam, grootte, datum, rechten, eigenaar). */
export function sortEntries(entries, key = 'name', asc = true) {
  const dir = asc ? 1 : -1
  const val = (e) => (key === 'size' ? (isDir(e) ? -1 : e.size) : key === 'mtime' ? e.mtime ?? 0 : e[key] ?? '')
  return [...entries].sort((a, b) => {
    if (isDir(a) !== isDir(b)) return isDir(a) ? -1 : 1
    const x = val(a), y = val(b)
    const c = typeof x === 'number' && typeof y === 'number' ? x - y : collator.compare(String(x), String(y))
    return (c || collator.compare(a.name, b.name)) * dir
  })
}

/** Zichtbaar met de filter en de keuze voor verborgen bestanden (die met een punt). */
export function visible(entries, { hidden = false, filter = '' } = {}) {
  const words = filter.toLowerCase().split(/\s+/).filter(Boolean)
  return entries.filter((e) => (hidden || !e.name.startsWith('.')) && words.every((w) => e.name.toLowerCase().includes(w)))
}

// --- Rechten -------------------------------------------------------------------------------------------------------

export const octal = (mode) => (mode & 0o7777).toString(8).padStart(3, '0')

/** [[r, w, x] van eigenaar, groep, anderen] uit een mode. */
export const bits = (mode) => [6, 3, 0].map((s) => [4, 2, 1].map((b) => !!((mode >> s) & b)))

/** Terug naar een mode; de speciale bits (setuid, setgid, sticky) van old blijven. */
export function fromBits(rows, old = 0) {
  let mode = old & 0o7000
  rows.forEach((row, i) => row.forEach((on, j) => { if (on) mode |= [4, 2, 1][j] << [6, 3, 0][i] }))
  return mode
}

export function parseOctal(text) {
  return /^[0-7]{3,4}$/.test(text.trim()) ? parseInt(text.trim(), 8) : null
}

// --- Uploaden ------------------------------------------------------------------------------------------------------

/** Voor een map die je uploadt: de lege mappen (de rest maakt de server zelf bij het eerste bestand erin). */
export function emptyDirs(dirs, files) {
  return dirs.filter((d) => !files.some((f) => f.rel.startsWith(d + '/')) && !dirs.some((o) => o.startsWith(d + '/')))
}

export function speed(bytesPerSec) {
  if (!(bytesPerSec > 0)) return ''
  const u = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  let i = 0
  while (bytesPerSec >= 1000 && i < u.length - 1) { bytesPerSec /= 1000; i++ }
  return `${bytesPerSec >= 100 || i === 0 ? Math.round(bytesPerSec) : bytesPerSec.toFixed(1)} ${u[i]}`
}

// Een verbinding die even wegvalt (wifi, een herstart van NPM): zo vaak een stuk opnieuw proberen.
const RETRIES = 3
const retryable = (e) => e?.name !== 'AbortError' && (e?.status == null || e.status === 0 || e.status === 502 || e.status === 503 || e.status === 504)

// Weigert een proxy ertussen een stuk als te groot (413), dan opnieuw met kleinere stukken (de server: minstens 64 KiB).
const SMALLER = [1024 * 1024, 256 * 1024, 64 * 1024]

/**
 * Eén bestand uploaden in stukken. call(path, opts) is api() voor dit venster (met het pad na /ssh/files/<id>).
 * Geeft {exists} als het bestand er al is en overwrite uit staat, anders het nieuwe item uit de lijst.
 * onbytes(n): n bytes meer aangekomen (negatief bij opnieuw beginnen). Afbreken met signal; de server ruimt het
 * tijdelijke bestand dan op.
 */
export async function uploadFile(call, { file, dir, rel, overwrite = false }, { onbytes = () => {}, signal, parallel = 3, wait = (ms) => new Promise((r) => setTimeout(r, ms)), chunk: ask = null } = {}) {
  const start = await call('/upload', { method: 'POST', body: { dir, name: rel, size: file.size, mtime: file.lastModified ? file.lastModified / 1000 : null, overwrite, chunk: ask }, signal })
  if (start.exists) return { exists: start.exists }
  const { id, chunks, chunk } = start
  let next = 0
  let sent = 0
  const send = async (i) => {
    const part = file.slice(i * chunk, Math.min(file.size, (i + 1) * chunk))
    for (let attempt = 0; ; attempt++) {
      try {
        await call(`/upload/${id}/${i}`, { method: 'PUT', body: part, signal })
        sent += part.size
        onbytes(part.size)
        return
      } catch (e) {
        if (attempt >= RETRIES || !retryable(e) || signal?.aborted) throw e
        await wait(1000 * 2 ** attempt)
      }
    }
  }
  const worker = async () => { while (next < chunks) await send(next++) }
  try {
    await Promise.all(Array.from({ length: Math.min(parallel, chunks) }, worker))
    return await call(`/upload/${id}/finish`, { method: 'POST', signal })
  } catch (e) {
    // Afgebroken of mislukt: het tijdelijke bestand op de host weg (de server doet het anders na 10 minuten).
    call(`/upload/${id}`, { method: 'DELETE' }).catch(() => {})
    const smaller = SMALLER.find((n) => n < chunk)
    if (e?.status !== 413 || !smaller || signal?.aborted) throw e
    onbytes(-sent)
    return uploadFile(call, { file, dir, rel, overwrite }, { onbytes, signal, parallel, wait, chunk: smaller })
  }
}

/**
 * api() voor één bestandenvenster: call('/list', opts) gaat naar /ssh/files/<id>/list.
 * win.info(): {id, user} van het venster, of null (dicht). win.reopen(): opnieuw openen (zet het nieuwe venster).
 * win.closed(msg, id): het venster dicht met die uitleg (id: een nieuw venster dat de server ook moet sluiten).
 * win.gone(): het tabblad is dicht. win.name(): de naam van de host.
 * - 410 (verlopen: 30 minuten stil, of de API herstartte): één keer opnieuw openen en het verzoek nog eens. Twee
 *   verzoeken die tegelijk 410 krijgen (twee uploads), openen samen één nieuw venster. Niet voor de stukken van een
 *   upload: die horen bij het oude venster.
 * - 412 (de host of zijn login veranderde), of het venster opent opnieuw als een andere gebruiker: dicht, en niets
 *   herhalen, ook de wachtrij niet. Je verbindt zelf opnieuw, en ziet dan als wie.
 */
export function fileCaller(api, win) {
  let reopening = null
  return async function call(sub, opts = {}) {
    const info = win.info()
    if (!info) throw new ApiError('Niet verbonden', 0)
    const { id, user } = info
    try {
      return await api(`/ssh/files/${id}${sub}`, opts)
    } catch (e) {
      if (e instanceof ApiError && e.status === 412) {
        if (win.info()?.id === id) win.closed(e.message)
        throw e
      }
      if (!(e instanceof ApiError && e.status === 410) || sub.startsWith('/upload/') || win.gone()) throw e
      if (win.info()?.id === id) reopening ??= win.reopen().finally(() => (reopening = null))
      await reopening
      const now = win.info()
      if (!now || win.gone()) throw e
      if (now.user !== user) {
        const msg = `${win.name()} opende opnieuw als ${now.user} (was ${user}): er is niets gedaan. Verbind opnieuw als dat goed is`
        win.closed(msg, now.id)
        throw new ApiError(msg, 412)
      }
      return await api(`/ssh/files/${now.id}${sub}`, opts)
    }
  }
}
