// Zet een icoon-naam om naar een URL, met dezelfde conventies als homepage.dev.
const DASH = 'https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons'

export function iconUrl(icon) {
  if (!icon) return null
  const v = icon.trim()
  if (/^https?:\/\//i.test(v) || v.startsWith('/')) return v
  if (v.startsWith('mdi-')) return `https://cdn.jsdelivr.net/npm/@mdi/svg/svg/${v.slice(4)}.svg`
  if (v.startsWith('si-')) return `https://cdn.jsdelivr.net/npm/simple-icons/icons/${v.slice(3)}.svg`
  if (v.startsWith('sh-')) {
    const name = v.slice(3)
    const ext = name.endsWith('.svg') ? 'svg' : 'png'
    return `https://cdn.jsdelivr.net/gh/selfhst/icons/${ext}/${name.replace(/\.(png|svg)$/, '')}.${ext}`
  }
  const m = v.match(/^(.*?)(?:\.(png|svg|webp))?$/)
  const ext = m[2] || 'png'
  return `${DASH}/${ext}/${m[1]}.${ext}`
}

// Monochrome sets (mdi, simple-icons) zijn zwart: die maken we licht.
export function iconIsMono(icon) {
  return !!icon && /^(mdi|si)-/.test(icon.trim())
}
