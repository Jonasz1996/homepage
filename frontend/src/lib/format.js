// Opmaak van waarden uit integraties. Een object zegt welk soort waarde het is.
export function bytes(n) {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  while (Math.abs(n) >= 1000 && i < u.length - 1) { n /= 1000; i++ }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${u[i]}`
}

export function duration(s) {
  if (s == null) return '—'
  s = Math.round(s)
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`
  if (s < 86400) return `${Math.floor(s / 3600)} u`
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} u`
}

export const date = (epoch) => new Date(epoch * 1000).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })

export function value(v) {
  if (v == null) return '—'
  if (typeof v === 'boolean') return v ? 'ja' : 'nee'
  if (typeof v === 'number') return v.toLocaleString('nl-BE')
  if (typeof v !== 'object') return String(v)
  if ('bytes' in v) return bytes(v.bytes)
  if ('uptime' in v) return duration(v.uptime)
  if ('age' in v) return `${duration(v.age)} geleden`
  if ('ts' in v) return v.ts ? date(v.ts) : '—'
  if ('full_at' in v) return `vol rond ${new Date(v.full_at * 1000).toLocaleDateString('nl-BE', { dateStyle: 'medium' })}`
  return JSON.stringify(v)
}
