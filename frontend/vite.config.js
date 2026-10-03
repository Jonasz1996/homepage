import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  server: {
    // Tijdens ontwikkelen: API draait lokaal op poort 8000.
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
