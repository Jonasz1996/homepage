import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
import { startBackground } from './lib/background.js'

startBackground(document.getElementById('bg'))

// Service worker (installeerbaar als app, opent ook bij een slechte verbinding). Alleen in de build.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}))
}

export default mount(App, { target: document.getElementById('app') })
