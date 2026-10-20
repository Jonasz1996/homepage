import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// Elke build krijgt een eigen cachenaam in de service worker: zo ruimt hij bij een update de oude bestanden op.
function swVersion() {
  let outDir
  return {
    name: 'sw-version',
    apply: 'build',
    configResolved(c) { outDir = c.build.outDir },
    closeBundle() {
      const f = resolve(outDir, 'sw.js')
      writeFileSync(f, readFileSync(f, 'utf8').replace('__BUILD__', Date.now().toString(36)))
    },
  }
}

export default defineConfig({
  plugins: [svelte(), swVersion()],
  server: {
    // Tijdens ontwikkelen: API draait lokaal op poort 8000.
    proxy: { '/api': { target: 'http://127.0.0.1:8000', ws: true } },
  },
})
