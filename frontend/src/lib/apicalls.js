// Zelfde rekenwerk als backend/app/integrations/calls.py, voor een voorbeeld terwijl je velden instelt.
// Wat er echt op de tegel komt, rekent de server uit.

export const FORMATS = {
  auto: 'automatisch', number: 'getal', percent: 'procent', bytes: 'bytes (GB, TB)', duration: 'duur (seconden)',
  date: 'datum/tijd', count: 'aantal', sum: 'som (*)', avg: 'gemiddelde (*)', min: 'kleinste (*)', max: 'grootste (*)',
  bool: 'ja/nee', text: 'tekst',
}

export const SHOW = { tile: 'op de tegel', detail: 'alleen mini dashboard', action: 'knop (actie)' }

export function pick(data, path) {
  if (path == null || path === '' || path === '.') return data
  const parts = String(path).split('.')
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (part === '*') {
      const items = Array.isArray(data) ? data : data && typeof data === 'object' ? Object.values(data) : []
      const rest = parts.slice(i + 1).join('.')
      const out = []
      for (const it of items) {
        const v = rest ? pick(it, rest) : it
        if (Array.isArray(v) && rest.includes('*')) out.push(...v)
        else out.push(v)
      }
      return out
    }
    if (Array.isArray(data)) data = data[Number(part)]
    else if (data && typeof data === 'object') data = data[part]
    else return undefined
    if (data === undefined) return undefined
  }
  return data
}

const num = (v) => (typeof v === 'boolean' ? Number(v) : typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' && !isNaN(Number(v.trim().replace(/%$/, ''))) ? Number(v.trim().replace(/%$/, '')) : null)

// Geeft [waarde voor format.value(), getal voor de drempels].
export function fieldValue(data, f) {
  let raw = pick(data, f.path || '')
  const fmt = f.format || 'auto'
  if (Array.isArray(raw) && ['count', 'sum', 'avg', 'min', 'max'].includes(fmt)) {
    if (fmt === 'count') {
      const n = f.equals != null && f.equals !== ''
        ? raw.filter((x) => String(x).toLowerCase() === String(f.equals).toLowerCase()).length
        : raw.filter((x) => x != null && x !== false && x !== '' && !(Array.isArray(x) && !x.length)).length
      return [n, n]
    }
    const ns = raw.map(num).filter((x) => x != null)
    if (!ns.length) return ['—', null]
    raw = fmt === 'sum' ? ns.reduce((a, b) => a + b, 0) : fmt === 'avg' ? ns.reduce((a, b) => a + b, 0) / ns.length
      : fmt === 'min' ? Math.min(...ns) : Math.max(...ns)
  } else if (fmt === 'count') {
    const n = Array.isArray(raw) ? raw.length : raw && typeof raw === 'object' ? Object.keys(raw).length : num(raw) || 0
    return [n, n]
  } else if (Array.isArray(raw) && String(f.path || '').includes('*') && ['auto', 'number', 'bytes', 'duration', 'percent'].includes(fmt)) {
    // Over alle items (records.*.size) als getal: opgeteld.
    const ns = raw.map(num).filter((x) => x != null)
    raw = ns.length ? ns.reduce((a, b) => a + b, 0) : null
  }
  if (raw == null) return ['—', null]
  const n = num(raw)
  const suffix = f.suffix || ''
  if (fmt === 'bool') {
    const on = typeof raw === 'boolean' ? raw : ['1', 'true', 'on', 'yes', 'ja', 'ok', 'up', 'enabled'].includes(String(raw).toLowerCase())
    return [on, Number(on)]
  }
  if (fmt === 'bytes' && n != null) return [{ bytes: n }, n]
  if (fmt === 'duration' && n != null) return [{ uptime: n }, n]
  if (fmt === 'date') return [String(raw), null]
  if (fmt === 'percent' && n != null) return [`${Math.round(n)}%`, n]
  if (fmt === 'text' || typeof raw === 'string') return [String(raw).slice(0, 80) + suffix, n]
  if (typeof raw === 'object') return [Array.isArray(raw) ? `${raw.length} items` : '…', null]
  if (typeof raw === 'boolean') return [raw, Number(raw)]
  if (n != null) return [suffix ? `${Math.round(n * 100) / 100}${suffix}` : Math.round(n * 100) / 100, n]
  return [String(raw), null]
}

export function level(n, f) {
  const warn = num(f.warn), err = num(f.err)
  if (n == null || (warn == null && err == null)) return null
  const lowerWorse = warn != null && err != null && warn > err
  const past = (lim) => lim != null && (lowerWorse ? n <= lim : n >= lim)
  return past(err) ? 'err' : past(warn) ? 'warn' : 'ok'
}

// Een eerste gok voor het formaat, op basis van de naam en de waarde.
export function guess(path, v) {
  const key = String(path).split('.').pop()
  if (typeof v === 'boolean') return 'bool'
  if (typeof v === 'number') {
    if (/size|bytes|space|usage|free|used|total_?b|disk|mem(ory)?$/i.test(key)) return 'bytes'
    if (/percent|pct|ratio/i.test(key)) return 'percent'
    if (/uptime|duration|seconds/i.test(key)) return 'duration'
  }
  if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(v)) return 'date'
  return 'auto'
}

export const lastKey = (path) => {
  const parts = String(path).split('.').filter((p) => p !== '*' && !/^\d+$/.test(p))
  return (parts.pop() || 'aantal').slice(0, 30)
}

// records.0.title → records.*.title (over alle items)
export const starred = (path) => String(path).replace(/(^|\.)\d+(\.|$)/, '$1*$2')
