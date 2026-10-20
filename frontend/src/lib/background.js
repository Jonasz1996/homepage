// Achtergrond zoals in aiverslag: een netwerk van zwevende punten en enkele knipperende 0/1-tekens.
// Punten wijken voor de muis uit en de muis trekt lijntjes naar de punten in de buurt.
export function startBackground(canvas) {
  if (!canvas || matchMedia('(prefers-reduced-motion: reduce)').matches) return
  const c = canvas.getContext('2d')
  let W, H, P = []
  const mouse = { x: -999, y: -999 }
  const size = () => {
    const dpr = Math.min(devicePixelRatio || 1, 2)
    W = innerWidth; H = innerHeight
    canvas.width = W * dpr; canvas.height = H * dpr
    c.setTransform(dpr, 0, 0, dpr, 0, 0)
    const n = Math.min(110, Math.floor((W * H) / 14000))
    P = Array.from({ length: n }, (_, i) => ({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.35, vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 1.4 + 0.6,
      ch: i % 4 === 0 ? (Math.random() < 0.5 ? '0' : '1') : null, t: Math.random() * 200,
    }))
  }
  size()
  addEventListener('resize', size)
  addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY }, { passive: true })
  document.addEventListener('mouseleave', () => { mouse.x = mouse.y = -999 })

  const frame = () => {
    if (!document.hidden) {
      c.clearRect(0, 0, W, H)
      c.font = '11px monospace'
      for (const p of P) {
        p.x += p.vx; p.y += p.vy
        if (p.x < 0 || p.x > W) p.vx *= -1
        if (p.y < 0 || p.y > H) p.vy *= -1
        const dx = p.x - mouse.x, dy = p.y - mouse.y, d = Math.hypot(dx, dy)
        if (d < 130 && d > 0) { p.x += (dx / d) * 1.2; p.y += (dy / d) * 1.2 }
        if (p.ch) {
          if (++p.t > 120) { p.t = 0; p.ch = Math.random() < 0.5 ? '0' : '1' }
          c.fillStyle = 'rgba(200,200,200,.35)'; c.fillText(p.ch, p.x, p.y)
        } else {
          c.beginPath(); c.arc(p.x, p.y, p.r, 0, 6.283); c.fillStyle = 'rgba(220,220,220,.55)'; c.fill()
        }
      }
      c.lineWidth = 1
      for (let i = 0; i < P.length; i++) {
        for (let j = i + 1; j < P.length; j++) {
          const d = Math.hypot(P[i].x - P[j].x, P[i].y - P[j].y)
          if (d < 120) {
            c.strokeStyle = `rgba(200,200,200,${(1 - d / 120) * 0.22})`
            c.beginPath(); c.moveTo(P[i].x, P[i].y); c.lineTo(P[j].x, P[j].y); c.stroke()
          }
        }
        const d = Math.hypot(P[i].x - mouse.x, P[i].y - mouse.y)
        if (d < 170) {
          c.strokeStyle = `rgba(255,255,255,${(1 - d / 170) * 0.5})`
          c.beginPath(); c.moveTo(P[i].x, P[i].y); c.lineTo(mouse.x, mouse.y); c.stroke()
        }
      }
    }
    requestAnimationFrame(frame)
  }
  requestAnimationFrame(frame)
}
