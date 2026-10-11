// Terugknop (gsm, Android-app, browser): sluit het bovenste venster of menu in plaats van de app of de pagina.
// Elk open venster is een laag. Zolang er een laag open is, staat er één extra stap in de geschiedenis van de
// browser; terug haalt die weg en sluit de bovenste laag. Sluit je het laatste venster zelf (✕, Escape), dan haalt
// het dashboard die stap weer weg, zodat terug daarna de app sluit zoals je verwacht.
const layers = []
let ignore = 0
let queued = false

// Staan we op de extra stap? Uit de geschiedenis zelf gelezen, niet onthouden: een stap terug die nog onderweg is
// terwijl er al een nieuw venster opengaat, kan zo nooit een verkeerde toestand achterlaten.
const onStep = () => history.state?.hpLaag === true

// Pas na de huidige wijzigingen kijken: een venster sluiten en meteen een ander openen (bv. vanuit Aandacht) geeft
// zo geen heen en weer in de geschiedenis.
function sync() {
  if (queued) return
  queued = true
  queueMicrotask(() => {
    queued = false
    if (layers.length && !onStep()) {
      history.pushState({ hpLaag: true }, '')
    } else if (!layers.length && onStep()) {
      ignore++
      history.back()
    }
  })
}

if (typeof window !== 'undefined') {
  addEventListener('popstate', () => {
    if (ignore) {
      // Onze eigen stap terug: alleen opnieuw kijken of er intussen een venster openging.
      ignore--
      sync()
      return
    }
    // Terug gedrukt: de extra stap is weg. De bovenste laag sluit; blijft er nog iets open, dan komt de stap terug.
    if (!onStep()) layers.at(-1)?.close()
    sync()
  })
}

/** Registreert een open venster of menu. close() wordt opgeroepen bij terug; geeft een functie die de laag weghaalt. */
export function layer(close) {
  const me = { close }
  layers.push(me)
  sync()
  let done = false
  return () => {
    if (done) return
    done = true
    const i = layers.indexOf(me)
    if (i >= 0) layers.splice(i, 1)
    sync()
  }
}
