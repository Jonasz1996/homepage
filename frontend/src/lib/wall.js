// Eigen achtergrond van het dashboard (Instellingen → Weergave). De server bewaart afbeelding en instellingen voor
// alle toestellen; hier alleen tonen: CSS-variabelen en twee classes op <html> (zie app.css onderaan).
//   wall: er is een eigen afbeelding
//   wall-plain: zonder de effecten van aiverslag erboven (geen gloed, scanlijnen of zwevende punten)
import { api } from './api.js'

const KEY = 'hp-wall'

export function applyWall(cfg) {
  const root = document.documentElement
  const img = cfg?.beeld?.url
  root.classList.toggle('wall', !!img)
  root.classList.toggle('wall-plain', !!img && cfg.effecten === false)
  if (img) {
    root.style.setProperty('--wall-img', `url("${img}")`)
    root.style.setProperty('--wall-dim', String((cfg.dimmen ?? 35) / 100))
    root.style.setProperty('--wall-blur', `${cfg.vervagen ?? 0}px`)
  } else {
    for (const p of ['--wall-img', '--wall-dim', '--wall-blur']) root.style.removeProperty(p)
  }
  // Onthouden op dit toestel: bij de volgende start staat de achtergrond er meteen (de afbeelding zit in de cache).
  try {
    if (img) localStorage.setItem(KEY, JSON.stringify(cfg))
    else localStorage.removeItem(KEY)
  } catch { /* geen opslag */ }
  // De punten (background.js) stoppen of starten opnieuw.
  window.dispatchEvent(new Event('hp:fx'))
}

/** Niet ingelogd (het beeld vraagt een sessie): de gewone achtergrond, zonder te vergeten wat er was. */
export function hideWall() {
  document.documentElement.classList.remove('wall', 'wall-plain')
  window.dispatchEvent(new Event('hp:fx'))
}

/** Na een fabrieksreset: ook op dit toestel niets meer onthouden. */
export function forgetWall() {
  try { localStorage.removeItem(KEY) } catch { /* geen opslag */ }
  hideWall()
}

/** Bij het opstarten: eerst wat dit toestel nog weet, dan wat de server zegt. */
export async function loadWall() {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || 'null')
    if (saved) applyWall(saved)
  } catch { /* geen opslag */ }
  try {
    applyWall(await api('/achtergrond'))
  } catch { /* niet ingelogd of de server even weg: laten zoals het is */ }
}

/** Een foto verkleinen voor de upload (nginx neemt hoogstens 4 MB): langste zijde 2560 px, als JPEG of WebP. */
export async function shrink(file, max = 2560, limit = 3_800_000) {
  // Klein genoeg: zoals het is (een GIF blijft zo ook bewegen). Anders verkleinen.
  if (file.size <= 1_500_000 && /^image\/(png|jpeg|webp|gif|avif)$/.test(file.type)) return file
  const bmp = await createImageBitmap(file)
  const scale = Math.min(1, max / Math.max(bmp.width, bmp.height))
  const w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale)
  const canvas = document.createElement('canvas')
  canvas.width = w; canvas.height = h
  canvas.getContext('2d').drawImage(bmp, 0, 0, w, h)
  bmp.close?.()
  for (const q of [0.85, 0.72, 0.6]) {
    const blob = await new Promise((r) => canvas.toBlob(r, 'image/jpeg', q))
    if (blob && blob.size <= limit) return blob
  }
  throw new Error('De afbeelding blijft te groot, kies een kleinere')
}
