import { defineConfig } from '@playwright/test'

// Browsertests: de backend moet al draaien op 127.0.0.1:8000 (vite preview stuurt /api daarheen).
// HOMEPAGE_URL zetten om tegen een andere, al draaiende frontend te testen.
export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  expect: { timeout: 10_000 },
  workers: 1,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.HOMEPAGE_URL || 'http://127.0.0.1:4173',
    viewport: { width: 1400, height: 900 },
    // Zonder effecten (vuurbal bij uitloggen, ...): sneller en voorspelbaar.
    reducedMotion: 'reduce',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
  },
  webServer: process.env.HOMEPAGE_URL ? undefined : {
    command: 'npm run build && npx vite preview --host 127.0.0.1 --port 4173 --strictPort',
    cwd: '../frontend',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: true,
    timeout: 180_000,
  },
})
