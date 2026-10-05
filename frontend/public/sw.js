// Service worker: de app opent ook bij een trage of wegvallende verbinding meteen, en is installeerbaar.
// De API wordt nooit gecachet (altijd verse status, en niets gevoeligs op het toestel).
const CACHE = 'homepage-__BUILD__'
const SHELL = ['/', '/manifest.webmanifest', '/favicon.svg', '/icon-192.png']

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()))
})

self.addEventListener('fetch', (e) => {
  const req = e.request
  const url = new URL(req.url)
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return
  if (req.mode === 'navigate') {
    // Eerst het netwerk (nieuwe versie meteen zichtbaar), anders de laatst bekende pagina.
    e.respondWith(fetch(req).then((res) => {
      if (res.ok) caches.open(CACHE).then((c) => c.put('/', res.clone()))
      return res
    }).catch(() => caches.match('/')))
    return
  }
  if (url.pathname.startsWith('/assets/')) {
    // Bestandsnamen bevatten een hash: wat er staat, verandert nooit.
    e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)) }
      return res
    })))
    return
  }
  e.respondWith(caches.match(req).then((hit) => {
    const net = fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)) }
      return res
    }).catch(() => hit)
    return hit || net
  }))
})

// --- Web push: meldingen van het dashboard, ook als het tabblad dicht is ------------------------------------

self.addEventListener('push', (e) => {
  let d = {}
  try { d = e.data ? e.data.json() : {} } catch { d = { title: e.data?.text() } }
  const tag = d.tag || undefined
  e.waitUntil(self.registration.showNotification(d.title || 'homepage', {
    body: d.body || '',
    tag,
    // Een storing die een oudere melding van dezelfde service vervangt, moet opnieuw trillen.
    renotify: d.level === 'err' && !!tag,
    icon: '/icon-192.png',
    badge: '/badge-96.png',
    data: { url: d.url || '/' },
  }))
})

self.addEventListener('notificationclick', (e) => {
  e.notification.close()
  const url = new URL(e.notification.data?.url || '/', self.location.origin)
  // Alleen eigen pagina's openen.
  const target = url.origin === self.location.origin ? url.href : self.location.origin + '/'
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const own = wins.find((c) => new URL(c.url).origin === self.location.origin)
    if (own) {
      try {
        await own.focus()
        if (await own.navigate(target)) return
      } catch { /* niet door deze service worker geladen: dan een nieuw venster */ }
    }
    await self.clients.openWindow(target)
  })())
})

// De browser vernieuwt soms zelf het pushadres (maanden na het aanmelden): dan meldt de service worker het
// nieuwe adres aan met het geheim dat de pagina bij het aanzetten in IndexedDB zette. Geen sessie nodig.
function pushStore(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('homepage', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('kv')
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const tx = open.result.transaction('kv', mode)
      const req = fn(tx.objectStore('kv'))
      tx.oncomplete = () => { open.result.close(); resolve(req.result) }
      tx.onerror = () => { open.result.close(); reject(tx.error) }
    }
  })
}

function keyBytes(b64) {
  const s = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64.length % 4)) % 4))
  return Uint8Array.from(s, (c) => c.charCodeAt(0))
}

self.addEventListener('pushsubscriptionchange', (e) => {
  e.waitUntil((async () => {
    const saved = await pushStore('readonly', (s) => s.get('webpush')).catch(() => null)
    if (!saved?.id || !saved?.renew || !saved?.applicationServerKey) return
    const sub = e.newSubscription || await self.registration.pushManager.subscribe({
      userVisibleOnly: true, applicationServerKey: keyBytes(saved.applicationServerKey),
    })
    const j = sub.toJSON()
    const r = await fetch('/api/webpush/subscriptions/renew', {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'homepage' },
      body: JSON.stringify({ id: saved.id, renew: saved.renew, subscription: { endpoint: j.endpoint, keys: j.keys } }),
    })
    // Elk vernieuwgeheim werkt één keer: het nieuwe bewaren voor de volgende keer.
    const out = r.ok ? await r.json().catch(() => null) : null
    if (out?.renew) await pushStore('readwrite', (s) => s.put({ ...saved, renew: out.renew }, 'webpush')).catch(() => {})
  })())
})
