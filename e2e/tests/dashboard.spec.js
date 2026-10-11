import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
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
  // Het noodplan staat in een iframe zonder scripts: de tracer van Playwright (trace: retain-on-failure) probeert daar
  // toch een script in te zetten en Chrome meldt dat het geblokkeerd is. Dat komt van het testgereedschap, niet van het
  // dashboard; de noodplantest kijkt zelf na dat het iframe geen scripts bevat.
  const tool = /Blocked script execution in 'about:srcdoc'/
  page.on('console', (m) => m.type() === 'error' && !/Failed to load resource/.test(m.text()) && !tool.test(m.text()) &&
    errors.push(m.text()))
  // confirm() en prompt() werken niet in een WebView (de Android-app): het dashboard gebruikt eigen vensters. Een
  // ingebouwde dialoog van de browser is dus een fout.
  page.on('dialog', (d) => { errors.push(`ingebouwde dialoog: ${d.message()}`); d.dismiss() })
})

// Een venster uit een menu in de titelbalk openen (Infrastructuur, Beheer, Instellingen).
async function menu(name, item) {
  await page.getByRole('button', { name: new RegExp(`^${name}`) }).click()
  await page.getByRole('menuitem', { name: new RegExp(`^${item}`) }).click()
}
// Een vraag van het dashboard zelf (in plaats van confirm()) beantwoorden.
async function bevestig(knop) {
  await page.getByRole('dialog', { name: 'bevestigen' }).getByRole('button', { name: knop }).click()
}

// De vraag om de 2FA-code (ReauthDialog) beantwoorden als ze komt: de vorige bevestiging kan al ouder zijn dan het
// kwartier van een recente 2FA. Wacht tot de vraag of `until` zichtbaar is, zodat ze een late vraag niet mist.
async function confirm2fa(until) {
  const box = page.locator('#ra-code')
  await expect(box.or(until)).toBeVisible({ timeout: 60000 })
  if (!(await box.isVisible())) return
  const { code, at } = await freshCode(secret, usedStep)
  usedStep = at
  await box.fill(code)
  await page.getByRole('button', { name: 'Bevestigen' }).click()
}

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
  await menu('Instellingen', 'Uitloggen')
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

  await menu('Beheer', 'Dashboard bewerken')
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

  await menu('Beheer', 'Dashboard bewerken')
  await page.locator('.tile', { hasText: 'OPNsense' }).click()
  await page.getByRole('button', { name: 'Verwijderen' }).click()
  await bevestig('Verwijderen')
  await expect(page.locator('.tile', { hasText: 'OPNsense' })).toHaveCount(0)
  await page.getByRole('button', { name: '✓ klaar' }).click()
})

// Elk venster uit de menu's in de titelbalk opent en kan weer dicht.
const MENUS = {
  Infrastructuur: ['Gezondheid', 'Capaciteit', 'Netwerk', 'Cronjobs', 'Logs', 'Tijdlijn', 'Noodplan'],
  Beheer: ['Terminal', 'Updates', 'Gepland onderhoud', 'Configuratiewijzigingen', 'Hersteltest'],
  Instellingen: ['Beveiliging', 'API-beheer', 'Webhooks', 'Meldingen op je gsm', 'Instellingen-checklist', 'Wat is er nieuw'],
}
const closeButtons = () => page.locator('button[aria-label="Sluiten"], button[aria-label$=" sluiten"]:not([aria-label="Sessie sluiten"])')
  .filter({ visible: true })

for (const [name, items] of Object.entries(MENUS)) {
  for (const item of items) {
    test(`${name}: ${item}`, async () => {
      await menu(name, item)
      const close = closeButtons()
      await expect(close.first()).toBeVisible()
      await close.last().click()
      await expect(close).toHaveCount(0)
    })
  }
}

test('titelbalk: Aandacht', async () => {
  await page.locator('button.mini[title^="Aandacht"]').click()
  await expect(closeButtons().first()).toBeVisible()
  await closeButtons().last().click()
  await expect(closeButtons()).toHaveCount(0)
})

test('terugknop sluit het bovenste venster, niet de pagina', async () => {
  const url = page.url()
  await menu('Infrastructuur', 'Gezondheid')
  await expect(page.getByRole('button', { name: 'Gezondheid sluiten' })).toBeVisible()
  await page.locator('.tabs button', { hasText: 'back-ups' }).click()
  await page.goBack()
  await expect(page.getByRole('button', { name: 'Gezondheid sluiten' })).toBeHidden()
  expect(page.url()).toBe(url)
  // Venster boven venster: terug sluit eerst het bovenste (de standaardlogin boven de terminal).
  await menu('Beheer', 'Terminal')
  await page.getByRole('button', { name: '⚙ standaard' }).click()
  const n = await page.locator('[role=dialog]:visible').count()
  expect(n).toBeGreaterThan(1)
  await page.goBack()
  await expect(page.locator('[role=dialog]:visible')).toHaveCount(n - 1)
  await expect(page.getByRole('button', { name: 'Terminal sluiten' })).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('button', { name: 'Terminal sluiten' })).toBeHidden()
  // Zelf sluiten met ✕ laat geen extra stap achter: terug gaat daarna echt terug.
  await menu('Instellingen', 'Webhooks')
  await closeButtons().last().click()
  await expect(closeButtons()).toHaveCount(0)
  expect(await page.evaluate(() => history.state?.hpLaag || false)).toBe(false)
  // Een menu sluit ook met terug.
  await page.getByRole('button', { name: /^Beheer/ }).click()
  await expect(page.getByRole('menu')).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('menu')).toHaveCount(0)
  expect(page.url()).toBe(url)
})

test('een groot venster houdt zijn tab als een ander groot venster opent en sluit', async () => {
  await page.getByRole('searchbox', { name: 'Zoeken' }).fill('cluster: quorum')
  await page.getByRole('searchbox', { name: 'Zoeken' }).press('Enter')
  const health = page.getByRole('dialog', { name: 'Gezondheid' })
  await expect(health.getByRole('tab', { name: /^cluster/ })).toHaveAttribute('aria-selected', 'true')
  await health.getByRole('tab', { name: /^temperatuur/ }).click()
  // Gezondheid bedekt de titelbalk: Logs via Ctrl+K.
  await page.keyboard.press('Control+k')
  await page.keyboard.type('syslog van je machines')
  await page.keyboard.press('Enter')
  await page.getByRole('button', { name: 'Logs sluiten' }).click()
  await expect(health.getByRole('tab', { name: /^temperatuur/ })).toHaveAttribute('aria-selected', 'true')
  await page.getByRole('button', { name: 'Gezondheid sluiten' }).click()
  await expect(closeButtons()).toHaveCount(0)
})

test('Escape sluit alleen het venster dat bovenaan ligt', async () => {
  const zoek = async (q) => {
    await page.keyboard.press('Control+k')
    await page.keyboard.type(q)
    await page.keyboard.press('Enter')
  }
  await menu('Beheer', 'Terminal')
  await page.getByRole('button', { name: '⚙ standaard' }).click()
  const standaard = page.getByRole('dialog', { name: 'ssh --defaults' })
  await expect(standaard).toBeVisible()
  // Gezondheid erboven: Escape laat de standaardlogin eronder staan.
  await zoek('cluster: quorum')
  await expect(page.getByRole('button', { name: 'Gezondheid sluiten' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(standaard).toHaveCount(1)
  // De terminal weer naar voren: nu sluit Escape de standaardlogin wel.
  await zoek('ssh naar je machines')
  await page.keyboard.press('Escape')
  await expect(standaard).toHaveCount(0)
  await page.getByRole('button', { name: 'Terminal sluiten' }).click()
  await page.getByRole('button', { name: 'Gezondheid sluiten' }).click()
  await expect(closeButtons()).toHaveCount(0)
})

test('verbinding weg: balk met opnieuw proberen, daarna weer bijgewerkt', async () => {
  // Het dashboard ververst elke 30 seconden: binnen die tijd komt de balk.
  await page.route('**/api/overzicht**', (r) => r.abort())
  await expect(page.getByRole('alert').filter({ hasText: 'Geen verbinding met de homepage' })).toBeVisible({ timeout: 45000 })
  await page.unroute('**/api/overzicht**')
  await page.getByRole('button', { name: 'opnieuw proberen' }).click()
  await expect(page.getByText('Geen verbinding met de homepage')).toHaveCount(0)
  await expect(page.getByText(/bijgewerkt \d\d:\d\d/)).toBeVisible()
})

test('aandacht: wat nu mis is en de instellingen-checklist', async () => {
  await page.locator('button.mini[title^="Aandacht"]').click()
  const win = page.getByRole('dialog')
  await expect(win.getByRole('tab', { name: /^nu/ })).toBeVisible()
  await win.getByRole('tab', { name: /^instellingen/ }).click()
  await expect(win.locator('.row', { hasText: 'SSH-standaardlogin' })).toBeVisible({ timeout: 20000 })
  await win.getByRole('button', { name: 'Sluiten' }).click()
  await expect(win).toHaveCount(0)
})

test('diagnose: één bestand onder !, zonder wachtwoord', async () => {
  await page.locator('button.mini[title^="Aandacht"]').click()
  const win = page.getByRole('dialog')
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 40000 }),
    win.getByRole('button', { name: 'diagnose ↓' }).click()])
  expect(dl.suggestedFilename()).toMatch(/^homepage-diagnose-\d{8}-\d{4}\.json$/)
  const text = readFileSync(await dl.path(), 'utf8')
  const d = JSON.parse(text)
  expect(d.formaat).toBe(1)
  expect(d.versie).toBeTruthy()
  expect(text).not.toContain(PASS)
  expect(text).not.toContain(secret)
  await win.getByRole('button', { name: 'Sluiten' }).click()
  await expect(win).toHaveCount(0)
})

test('proef: wat de nachtelijke updates zouden doen', async () => {
  await menu('Beheer', 'Updates')
  const win = page.getByRole('dialog')
  await win.getByRole('tab', { name: /^'s nachts/ }).click()
  await win.getByRole('button', { name: 'proef van vannacht' }).click()
  await expect(win.getByText('er is niets uitgevoerd')).toBeVisible()
  await expect(win.getByText('Er zou niets gebeuren.')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(win).toHaveCount(0)
})

test('hw: back-ups en cluster zonder Proxmox-tegel', async () => {
  await menu('Infrastructuur', 'Gezondheid')
  await page.locator('.tabs button', { hasText: 'back-ups' }).click()
  await expect(page.getByText('Nog geen gegevens.')).toBeVisible()
  await page.locator('.tabs button', { hasText: 'cluster' }).click()
  await expect(page.getByText('Nog geen gegevens.')).toBeVisible()
  await page.getByRole('button', { name: 'Gezondheid sluiten' }).click()
})

test('één node \'s nachts uit', async () => {
  await menu('Infrastructuur', 'Capaciteit')
  await page.getByRole('button', { name: 'voorstel berekenen' }).click()
  await expect(page.getByText('Nog geen Proxmox-tegel')).toBeVisible()
  await page.keyboard.press('Escape')
})

test('kuma vervangen: push-check, foute header en pauzeren', async () => {
  await menu('Beheer', 'Dashboard bewerken')
  await page.getByRole('button', { name: 'Service toevoegen aan Infra' }).click()
  await page.fill('#sf-name', 'Back-up')
  await page.locator('summary', { hasText: 'Monitoring' }).click()
  await page.selectOption('#sf-ct', 'http')
  await page.locator('summary', { hasText: 'verzoek' }).click()
  await page.fill('#sf-h', 'Authorization: Bearer geheim')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await expect(page.getByText(/lijkt geheim/)).toBeVisible()
  await page.fill('#sf-h', '')
  await page.selectOption('#sf-ct', 'push')
  await expect(page.locator('#sf-da')).toHaveValue('1')
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await page.getByRole('button', { name: '✓ klaar' }).click()

  await page.locator('.tile', { hasText: 'Back-up' }).hover()
  await page.getByRole('button', { name: 'Details van Back-up' }).click()
  await page.getByRole('button', { name: 'push-adres maken' }).click()
  await expect(page.locator('.pm code').first()).toContainText('/api/push/')
  await page.getByRole('button', { name: '⏸ pauzeren' }).click()
  await page.getByRole('dialog', { name: 'bevestigen' }).getByRole('button', { name: 'Pauzeren' }).click()
  await expect(page.getByRole('button', { name: '▶ hervatten' }).first()).toBeVisible()
  await expect(page.getByText('De check staat gepauzeerd')).toBeVisible()
  // Bewerken vanuit het detailvenster laat de pauze staan.
  await page.getByRole('dialog').getByRole('button', { name: '✎ bewerken' }).click()
  await page.getByRole('button', { name: 'Opslaan' }).click()
  await expect(page.locator('#sf-name')).toHaveCount(0)
  await page.locator('.tile', { hasText: 'Back-up' }).hover()
  await page.getByRole('button', { name: 'Details van Back-up' }).click()
  await expect(page.getByText('De check staat gepauzeerd')).toBeVisible()
  await page.getByRole('button', { name: '▶ hervatten' }).first().click()
  await expect(page.getByRole('button', { name: '⏸ pauzeren' })).toBeVisible()
  await page.keyboard.press('Escape')
})

test('gsm: knoppen achter het menu', async () => {
  await page.setViewportSize({ width: 390, height: 844 })
  const knop = page.getByRole('button', { name: 'Menu' })
  await expect(knop).toBeVisible()
  await expect(page.getByRole('button', { name: /^Infrastructuur/ })).toBeHidden()
  await knop.click()
  await expect(page.getByRole('menuitem', { name: /^Logs/ })).toBeVisible()
  await expect(page.getByRole('menuitem', { name: /^Uitloggen/ })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menu')).toHaveCount(0)
  await page.setViewportSize({ width: 1400, height: 900 })
})

test('noodplan: bijwerken, tonen, afdrukken en downloaden', async () => {
  await menu('Infrastructuur', 'Noodplan')
  const win = page.getByRole('dialog', { name: 'less noodplan.html' })
  await expect(win.getByText('Nog geen noodplan.')).toBeVisible()
  await win.getByRole('button', { name: 'nu bijwerken' }).click()
  await confirm2fa(win.locator('iframe[title="Noodplan"]'))
  const paper = page.frameLocator('iframe[title="Noodplan"]')
  await expect(paper.getByRole('heading', { level: 1 })).toHaveText(/Noodplan/, { timeout: 60000 })
  await expect(paper.getByText('homepage-terugzetten').first()).toBeVisible()
  await expect(win.getByText('✓ bijgewerkt')).toBeVisible()
  // Zo hoog als het document (het venster scrolt), en geen scripts of on…-attributen in het iframe.
  const frame = win.locator('iframe[title="Noodplan"]')
  await expect.poll(async () => (await frame.boundingBox()).height).toBeGreaterThan(300)
  expect(await frame.evaluate((f) => [...f.contentDocument.querySelectorAll('*')].filter((el) => el.localName === 'script' ||
    [...el.attributes].some((a) => a.name.startsWith('on'))).length)).toBe(0)
  // Afdrukken: print() van het iframe vervangen vanuit de pagina (het iframe zelf voert geen scripts uit).
  await page.evaluate(() => {
    document.querySelector('iframe[title="Noodplan"]').contentWindow.print = () => { window.__geprint = true }
  })
  await win.getByRole('button', { name: 'afdrukken' }).click()
  expect(await page.evaluate(() => window.__geprint)).toBe(true)
  // De 2FA hierboven is seconden oud: de tekstversie vraagt niets meer.
  const [dl] = await Promise.all([page.waitForEvent('download'), win.getByRole('button', { name: '↓ tekst' }).click()])
  expect(dl.suggestedFilename()).toMatch(/^noodplan-\d{4}-\d{2}-\d{2}\.md$/)
  const text = readFileSync(await dl.path(), 'utf8')
  expect(text).toContain('# Noodplan')
  expect(text).not.toContain(PASS)
  expect(text).not.toContain(secret)
  await win.getByRole('button', { name: 'proef' }).click()
  await expect(win.getByText('er is niets uitgevoerd')).toBeVisible()
  // gsm: hetzelfde venster op 393 px, met het document erin en zonder horizontaal scrollen.
  await page.setViewportSize({ width: 393, height: 852 })
  await expect(win.getByRole('button', { name: 'afdrukken' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(393)
  expect((await page.locator('iframe[title="Noodplan"]').boundingBox()).width).toBeLessThanOrEqual(393)
  await page.setViewportSize({ width: 1400, height: 900 })
  await win.getByRole('button', { name: 'Sluiten' }).click()
  await expect(win).toHaveCount(0)
})
