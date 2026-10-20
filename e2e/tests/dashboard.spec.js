import { test, expect } from '@playwright/test'
import { freshCode } from './totp.js'

// Eén doorlopend verhaal op een lege database: account aanmaken met 2FA, uitloggen en weer inloggen,
// een pagina, groep en tegel maken en aanpassen, en elk venster in de titelbalk openen en sluiten.
test.describe.configure({ mode: 'serial' })

const TOKEN = process.env.HOMEPAGE_SETUP_TOKEN || 'e2e-setup-token'
const USER = 'jonas'
const PASS = 'een-lang-wachtwoord-voor-e2e'
let page, secret, usedStep
const errors = []

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage()
  page.on('pageerror', (e) => errors.push(String(e)))
  // Mislukte verzoeken (401 voor het inloggen, iconen van buiten) zijn geen fout in de interface.
  page.on('console', (m) => m.type() === 'error' && !/Failed to load resource/.test(m.text()) && errors.push(m.text()))
  page.on('dialog', (d) => d.accept())
})

test.afterAll(async () => { await page?.close() })

test.afterEach(() => {
  expect(errors.splice(0), 'fouten in de browserconsole').toEqual([])
})

test('eerste account met 2FA', async () => {
  await page.goto('/')
  await page.fill('#t', TOKEN)
  await page.fill('#u', USER)
  await page.fill('#p', PASS)
  await page.fill('#p2', PASS)
  await page.getByRole('button', { name: 'Account aanmaken' }).click()
  secret = (await page.locator('#s').textContent()).trim()
  const { code, at } = await freshCode(secret)
  usedStep = at
  await page.fill('#c', code)
  await page.getByRole('button', { name: 'Activeren' }).click()
  await expect(page.getByRole('heading', { name: 'Nog leeg' })).toBeVisible()
})

test('uitloggen en inloggen met wachtwoord en 2FA-code', async () => {
  await page.locator('button[title="Uitloggen"]').click()
  await expect(page.locator('#u')).toBeVisible()
  await page.fill('#u', USER)
  await page.fill('#p', 'fout-wachtwoord-123')
  await page.getByRole('button', { name: 'Inloggen' }).click()
  await expect(page.locator('#c')).toHaveCount(0)
  await page.fill('#p', PASS)
  await page.getByRole('button', { name: 'Inloggen' }).click()
  await expect(page.locator('#c')).toBeVisible()
  const { code, at } = await freshCode(secret, usedStep)
  usedStep = at
  await page.fill('#c', code)
  await page.getByRole('button', { name: 'Bevestigen' }).click()
  await expect(page.getByRole('heading', { name: 'Nog leeg' })).toBeVisible()
})

test('bewerkmodus: pagina, groep en tegel', async () => {
  await page.getByRole('button', { name: 'Lege pagina' }).click()
  await page.fill('#nf-name', 'Thuis')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await expect(page.getByRole('button', { name: 'Thuis' })).toBeVisible()

  const edit = page.getByRole('button', { name: '✎ bewerken' })
  if (await edit.isVisible()) await edit.click()
  await page.getByRole('button', { name: '+ groep' }).click()
  await page.fill('#nf-name', 'Infra')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await expect(page.getByText('ls infra/')).toBeVisible()

  await page.getByRole('button', { name: 'Service toevoegen aan Infra' }).click()
  await page.fill('#sf-name', 'Router')
  await page.fill('#sf-url', 'http://127.0.0.1:9/')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  const tile = page.locator('.tile', { hasText: 'Router' })
  await expect(tile).toBeVisible()

  await tile.click()
  await page.fill('#sf-name', 'OPNsense')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await expect(page.locator('.tile', { hasText: 'OPNsense' })).toBeVisible()

  await page.getByRole('button', { name: '✓ klaar' }).click()
  await expect(page.getByRole('button', { name: '+ groep' })).toHaveCount(0)
  await page.reload()
  await expect(page.locator('.tile', { hasText: 'OPNsense' })).toBeVisible()

  await page.getByRole('button', { name: '✎ bewerken' }).click()
  await page.locator('.tile', { hasText: 'OPNsense' }).click()
  await page.getByRole('button', { name: 'Verwijderen' }).click()
  await expect(page.locator('.tile', { hasText: 'OPNsense' })).toHaveCount(0)
  await page.getByRole('button', { name: '✓ klaar' }).click()
})

// Elke knop in de titelbalk opent een venster dat weer dicht kan.
const WINDOWS = ['Aandacht', 'Logs', 'SSH-terminal', 'Capaciteit', 'Internet', 'Tijdlijn', 'Configuratiewijzigingen', 'API-beheer',
  'Cronjobs', 'Gezondheid', 'Openstaande updates', 'Beveiliging']

for (const name of WINDOWS) {
  test(`titelbalk: ${name}`, async () => {
    await page.locator(`header button[title^="${name}"], .bar button[title^="${name}"], button.mini[title^="${name}"]`).first().click()
    const close = page.locator('button[aria-label="Sluiten"], button[aria-label$=" sluiten"]:not([aria-label="Sessie sluiten"])')
      .filter({ visible: true })
    await expect(close.first()).toBeVisible()
    await close.last().click()
    await expect(close).toHaveCount(0)
  })
}

test('aandacht: wat nu mis is en de instellingen-checklist', async () => {
  await page.locator('button.mini[title^="Aandacht"]').click()
  const win = page.getByRole('dialog')
  await expect(win.getByRole('button', { name: /^nu/ })).toBeVisible()
  await win.getByRole('button', { name: /^instellingen/ }).click()
  await expect(win.locator('.row', { hasText: 'SSH-standaardlogin' })).toBeVisible({ timeout: 20000 })
  await win.getByRole('button', { name: 'Sluiten' }).click()
  await expect(win).toHaveCount(0)
})

test('hw: back-ups en cluster zonder Proxmox-tegel', async () => {
  await page.locator('button.mini[title^="Gezondheid"]').click()
  await page.locator('.tabs button', { hasText: 'back-ups' }).click()
  await expect(page.getByText('Nog geen gegevens.')).toBeVisible()
  await page.locator('.tabs button', { hasText: 'cluster' }).click()
  await expect(page.getByText('Nog geen gegevens.')).toBeVisible()
  await page.getByRole('button', { name: 'Gezondheid sluiten' }).click()
})

test('gsm: knoppen achter het menu', async () => {
  await page.setViewportSize({ width: 390, height: 844 })
  const menu = page.getByRole('button', { name: 'Menu' })
  await expect(menu).toBeVisible()
  await menu.click()
  await expect(page.locator('button.mini[title^="Logs"]')).toBeVisible()
  await page.setViewportSize({ width: 1400, height: 900 })
})
