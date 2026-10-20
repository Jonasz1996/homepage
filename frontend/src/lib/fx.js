// Speciale effecten zoals in aiverslag: vuur, vonken, bliksem, flits, schudden en een ripple op knoppen.
// Alles tekent op één doorzichtig canvas boven de pagina en stopt zodra er niets meer beweegt.
// Uit bij "minder beweging" in het systeem, of met Ctrl+K → "effecten".

const KEY = 'hp-fx'
const RM = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
let on = true
try { on = localStorage.getItem(KEY) !== 'off' } catch { /* geen opslag: standaard aan */ }

export const fxEnabled = () => on && !RM
export function setFx(value) {
  on = value
  try { localStorage.setItem(KEY, value ? 'on' : 'off') } catch { /* niet bewaard */ }
}

// Laatste klik- of tikpositie: effecten zonder eigen plek ontstaan daar.
const last = { x: innerWidth / 2, y: innerHeight / 3 }
addEventListener('pointerdown', (e) => { last.x = e.clientX; last.y = e.clientY }, { capture: true, passive: true })

let canvas, f, flashEl, W, H
let fire = [], rings = [], bolts = [], running = false

function setup() {
  if (canvas) return
  canvas = document.createElement('canvas')
  canvas.id = 'fx'
  canvas.setAttribute('aria-hidden', 'true')
  flashEl = document.createElement('div')
  flashEl.id = 'flash'
  document.body.append(canvas, flashEl)
  f = canvas.getContext('2d')
  size()
  addEventListener('resize', size)
}

function size() {
  const dpr = Math.min(devicePixelRatio || 1, 2)
  W = innerWidth; H = innerHeight
  canvas.width = W * dpr; canvas.height = H * dpr
  f.setTransform(dpr, 0, 0, dpr, 0, 0)
}

function go() {
  if (!running) { running = true; requestAnimationFrame(frame) }
}

function at(p) {
  if (p && typeof p.getBoundingClientRect === 'function') {
    const r = p.getBoundingClientRect()
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 }
  }
  return p && typeof p.x === 'number' ? p : { ...last }
}

/** Vuurbal met schokgolf, bv. bij verwijderen. */
export function explode(where, k = 1) {
  if (!fxEnabled()) return
  setup()
  const { x, y } = at(where)
  for (let i = 0; i < 130 * k; i++) {
    const a = Math.random() * 6.283, s = Math.random() ** 0.5 * 9 * k
    fire.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s - 1.5, life: 1, dec: 0.014 + Math.random() * 0.02,
                sz: Math.random() * 7 * k + 2, h: Math.random() * 45 + 5, g: -0.05 })
  }
  for (let i = 0; i < 40 * k; i++) {
    const a = Math.random() * 6.283, s = Math.random() * 14 * k + 4
    fire.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s, life: 1, dec: 0.02 + Math.random() * 0.02,
                sz: 1.6, h: 45, g: 0.28, spark: true })
  }
  rings.push({ x, y, r: 6, life: 1, k }, { x, y, r: 2, life: 1, k: k * 0.6, slow: true })
  go()
}

/** Blauwe vonken, bv. bij goedkeuren of "gelezen". */
export function sparkle(where, color = 210) {
  if (!fxEnabled()) return
  setup()
  const { x, y } = at(where)
  for (let i = 0; i < 60; i++) {
    const a = Math.random() * 6.283, s = Math.random() * 11 + 3
    fire.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s, life: 1, dec: 0.03 + Math.random() * 0.03,
                sz: 1.8, h: color, l: 85, g: 0.2, spark: true })
  }
  rings.push({ x, y, r: 4, life: 1, k: 0.8, hue: color })
  go()
}

function jag(x1, y1, x2, y2, d, out) {
  if (d < 3) { out.push([x1, y1, x2, y2]); return }
  const mx = (x1 + x2) / 2 + (Math.random() - 0.5) * d, my = (y1 + y2) / 2 + (Math.random() - 0.5) * d
  jag(x1, y1, mx, my, d / 2, out); jag(mx, my, x2, y2, d / 2, out)
}

function shape(x0, y0, x, y) {
  const main = []
  jag(x0, y0, x, y, Math.hypot(x - x0, y - y0) * 0.35, main)
  const br = []
  for (let i = 0; i < 7; i++) {
    const s = main[Math.floor(Math.random() * main.length)], ang = Math.random() * 3.1 + 0.02
    const len = 60 + Math.random() * 140, seg = []
    jag(s[2], s[3], s[2] + Math.cos(ang) * len * (Math.random() < 0.5 ? -1 : 1), s[3] + Math.sin(ang) * len, len * 0.4, seg)
    br.push(seg)
  }
  return { main, br }
}

/** Bliksem van boven het scherm naar een punt. */
export function bolt(where) {
  if (!fxEnabled()) return
  setup()
  const { x, y } = at(where)
  const x0 = x + (Math.random() - 0.5) * 400
  bolts.push({ x0, x, y, shape: shape(x0, -10, x, y), life: 1, t: 0 })
  go()
}

/** Een paar bliksems rond een punt, met flits en vonken: voor een geslaagde actie. */
export function storm(where, n = 3) {
  if (!fxEnabled()) return
  const { x, y } = at(where)
  for (let i = 0; i < n; i++) setTimeout(() => bolt({ x: x + (Math.random() - 0.5) * 300, y: y - 40 + Math.random() * 80 }), i * 140)
  flash('rgba(190,220,255,.8)')
  setTimeout(() => { sparkle({ x, y }); shake() }, 200)
}

/** Kort het hele scherm laten oplichten. */
export function flash(color = 'rgba(190,220,255,.8)') {
  if (!fxEnabled()) return
  setup()
  flashEl.style.transition = 'none'
  flashEl.style.background = color
  flashEl.style.opacity = '1'
  requestAnimationFrame(() => requestAnimationFrame(() => {
    flashEl.style.transition = 'opacity .45s ease-out'
    flashEl.style.opacity = '0'
  }))
}

export const FIRE = 'radial-gradient(circle at 50% 40%, rgba(255,150,40,.55), transparent 70%)'
export const RED = 'rgba(229,139,139,.45)'

/** De pagina even laten schudden. */
export function shake() {
  if (!fxEnabled()) return
  const w = document.querySelector('main.wrap')
  if (!w) return
  w.classList.remove('shk'); void w.offsetWidth; w.classList.add('shk')
}

/** Ontploffing + flits + schudden: voor iets dat echt weg is. */
export function boom(where, k = 1.2) {
  if (!fxEnabled()) return
  explode(where, k)
  flash(FIRE)
  shake()
}

function segs(s, w) {
  f.lineWidth = w
  f.beginPath()
  for (const q of s) { f.moveTo(q[0], q[1]); f.lineTo(q[2], q[3]) }
  f.stroke()
}

function frame() {
  f.clearRect(0, 0, W, H)
  f.globalCompositeOperation = 'lighter'
  rings = rings.filter((r) => r.life > 0)
  for (const r of rings) {
    r.r += (r.slow ? 7 : 16) * r.k; r.life -= 0.035
    f.lineWidth = (r.slow ? 10 : 5) * r.life * r.k
    f.strokeStyle = r.hue !== undefined ? `hsla(${r.hue},100%,80%,${r.life})` : `rgba(255,${(140 + r.life * 80) | 0},40,${r.life * 0.8})`
    f.beginPath(); f.arc(r.x, r.y, r.r, 0, 6.283); f.stroke()
  }
  fire = fire.filter((p) => p.life > 0)
  for (const p of fire) {
    p.x += p.vx; p.y += p.vy; p.vy += p.g; p.vx *= 0.97; p.life -= p.dec
    if (p.spark) {
      f.fillStyle = `hsla(${p.h},100%,${p.l || 70}%,${p.life})`
      f.fillRect(p.x, p.y, p.sz * 1.6, p.sz * 1.6)
    } else {
      const s = p.sz * (0.4 + p.life), h = p.h * p.life + (1 - p.life) * 5
      const g = f.createRadialGradient(p.x, p.y, 0, p.x, p.y, s * 2)
      g.addColorStop(0, `hsla(${h + 15},100%,${55 + p.life * 35}%,${p.life * 0.85})`)
      g.addColorStop(1, `hsla(${h},100%,45%,0)`)
      f.fillStyle = g; f.beginPath(); f.arc(p.x, p.y, s * 2, 0, 6.283); f.fill()
    }
  }
  bolts = bolts.filter((b) => b.life > 0)
  for (const b of bolts) {
    b.t++; b.life -= 0.045
    if (b.t % 4 === 0) b.shape = shape(b.x0, -10, b.x, b.y)
    const a = Math.random() < 0.25 ? b.life * 0.3 : Math.min(1, b.life * 1.6)
    f.shadowColor = '#7db7ff'; f.shadowBlur = 28
    f.strokeStyle = `rgba(120,175,255,${a * 0.7})`; segs(b.shape.main, 7)
    for (const s of b.shape.br) { f.strokeStyle = `rgba(120,175,255,${a * 0.5})`; segs(s, 3) }
    f.shadowBlur = 10
    f.strokeStyle = `rgba(255,255,255,${a})`; segs(b.shape.main, 2.2)
    for (const s of b.shape.br) { f.strokeStyle = `rgba(230,240,255,${a * 0.8})`; segs(s, 1) }
    f.shadowBlur = 0
  }
  f.globalCompositeOperation = 'source-over'
  if (fire.length || rings.length || bolts.length) requestAnimationFrame(frame)
  else { running = false; f.clearRect(0, 0, W, H) }
}

/** Ripple op elke knop (.btn en .mini), via één luisteraar op het document. */
export function startRipples() {
  document.addEventListener('click', (e) => {
    if (!fxEnabled()) return
    const b = e.target.closest?.('.btn, .mini')
    if (!b || b.disabled) return
    const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height) / 2
    const p = document.createElement('span')
    p.className = 'rip'
    p.style.cssText = `width:${s}px;height:${s}px;left:${e.clientX - r.left - s / 2}px;top:${e.clientY - r.top - s / 2}px`
    b.append(p)
    setTimeout(() => p.remove(), 600)
  })
}

/** Vensters kantelen een heel klein beetje mee met de muis (3D). */
export function startTilt() {
  if (RM) return
  addEventListener('mousemove', (e) => {
    const all = document.querySelectorAll('.ov .box')
    const card = all[all.length - 1]
    if (!card) return
    if (!fxEnabled()) { card.style.transform = ''; return }
    const x = e.clientX / innerWidth - 0.5, y = e.clientY / innerHeight - 0.5
    card.style.transform = `perspective(1400px) rotateY(${x * 3}deg) rotateX(${-y * 3}deg)`
  }, { passive: true })
}
