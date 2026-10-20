// Rustige achtergrond: zwevende punten die dichtbij elkaar met een lijntje verbonden worden.
export function startBackground(canvas) {
  if (!canvas || matchMedia('(prefers-reduced-motion: reduce)').matches) return
  const ctx = canvas.getContext('2d')
  let w, h, dots
  const resize = () => {
    w = canvas.width = innerWidth * devicePixelRatio
    h = canvas.height = innerHeight * devicePixelRatio
    const n = Math.min(70, Math.round((innerWidth * innerHeight) / 22000))
    dots = Array.from({ length: n }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.25 * devicePixelRatio, vy: (Math.random() - 0.5) * 0.25 * devicePixelRatio,
    }))
  }
  resize()
  addEventListener('resize', resize)
  const reach = 140 * devicePixelRatio
  const frame = () => {
    if (!document.hidden) {
      ctx.clearRect(0, 0, w, h)
      for (const d of dots) {
        d.x = (d.x + d.vx + w) % w
        d.y = (d.y + d.vy + h) % h
      }
      for (let i = 0; i < dots.length; i++) {
        const a = dots[i]
        ctx.fillStyle = 'rgba(255,255,255,.35)'
        ctx.fillRect(a.x, a.y, 1.5 * devicePixelRatio, 1.5 * devicePixelRatio)
        for (let j = i + 1; j < dots.length; j++) {
          const b = dots[j]
          const dist = Math.hypot(a.x - b.x, a.y - b.y)
          if (dist < reach) {
            ctx.strokeStyle = `rgba(255,255,255,${0.08 * (1 - dist / reach)})`
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
          }
        }
      }
    }
    requestAnimationFrame(frame)
  }
  requestAnimationFrame(frame)
}
