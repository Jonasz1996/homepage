import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
import { startBackground } from './lib/background.js'
import { startRipples, startTilt } from './lib/fx.js'

startBackground(document.getElementById('bg'))

// Na een update bestaan de oude stukjes code niet meer: dan de pagina één keer herladen in plaats van niets te doen.
window.addEventListener('vite:preloadError', (e) => {
  e.preventDefault()
  if (sessionStorage.getItem('hp-reloaded')) return
  try { sessionStorage.setItem('hp-reloaded', '1') } catch { /* privévenster */ }
  location.reload()
})
setTimeout(() => { try { sessionStorage.removeItem('hp-reloaded') } catch { /* */ } }, 10000)
startRipples()
startTilt()

// Service worker (installeerbaar als app, opent ook bij een slechte verbinding). Alleen in de build.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}))
}

export default mount(App, { target: document.getElementById('app') })
