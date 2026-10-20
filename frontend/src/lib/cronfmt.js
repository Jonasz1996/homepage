// Gedeelde opmaak voor de cronweergave.
export const KIND = {
  cron: 'cron', timer: 'timer', periodic: 'periodiek', 'pve-backup': 'back-up', 'pve-repl': 'replicatie',
  'pbs-sync': 'pbs sync', 'pbs-verify': 'verify', 'pbs-prune': 'prune', 'pbs-gc': 'gc',
}

export const STATUS = {
  ok: 'gelukt', fout: 'mislukt', gemist: 'niet gelopen', gestart: 'gelopen', bezig: 'bezig', gestopt: 'gestopt',
}

export const STATUS_HINT = {
  gestart: 'Cron startte de job; of hij lukte weet het dashboard pas als je hem bewaakt.',
  gemist: 'De laatste geplande keer staat niet in de cronlog.',
}

// "over 12 min", "3 u geleden", "gisteren 03:00", "za 01:00"
export function rel(ts, now = Date.now()) {
  if (!ts) return '—'
  const t = new Date(ts).getTime()
  const d = (t - now) / 1000
  const a = Math.abs(d)
  if (a < 60) return d > 0 ? 'zo meteen' : 'net'
  if (a < 3600) return d > 0 ? `over ${Math.round(a / 60)} min` : `${Math.round(a / 60)} min geleden`
  if (a < 6 * 3600) return d > 0 ? `over ${Math.round(a / 3600)} u` : `${Math.round(a / 3600)} u geleden`
  const day = new Date(t)
  const today = new Date(now)
  const diff = Math.round((new Date(day.toDateString()) - new Date(today.toDateString())) / 86400000)
  const hm = day.toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })
  if (diff === 0) return `vandaag ${hm}`
  if (diff === 1) return `morgen ${hm}`
  if (diff === -1) return `gisteren ${hm}`
  if (Math.abs(diff) < 7) return `${day.toLocaleDateString('nl-BE', { weekday: 'short' })} ${hm}`
  return `${day.toLocaleDateString('nl-BE', { day: '2-digit', month: '2-digit' })} ${hm}`
}

export function dur(s) {
  if (s == null) return ''
  if (s < 60) return `${Math.max(0, Math.round(s))} s`
  if (s < 3600) return `${Math.floor(s / 60)} min${s % 60 >= 1 && s < 600 ? ` ${Math.round(s % 60)} s` : ''}`
  return `${Math.floor(s / 3600)} u ${Math.round((s % 3600) / 60)} min`
}

export const hm = (ts) => new Date(ts).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })
export const full = (ts) => (ts ? new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '—')

export function wsUrl(path) {
  return `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api${path}`
}
