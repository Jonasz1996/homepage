import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
import { startBackground } from './lib/background.js'
import { startRipples, startTilt } from './lib/fx.js'

startBackground(document.getElementById('bg'))
startRipples()
startTilt()

// Service worker (installeerbaar als app, opent ook bij een slechte verbinding). Alleen in de build.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}))
}

export default mount(App, { target: document.getElementById('app') })
