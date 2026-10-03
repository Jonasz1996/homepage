import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
import { startBackground } from './lib/background.js'

startBackground(document.getElementById('bg'))

export default mount(App, { target: document.getElementById('app') })
