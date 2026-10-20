// Eigen bevestigings- en invoervensters in plaats van confirm() en prompt(): die doen in een WebView (de Android-app)
// vaak niets, zodat verwijderen, herstarten of Wake-on-LAN stilletjes niet gebeurt. Dialogs.svelte toont ze.
class Queue {
  list = $state.raw([])
}
export const dialogs = new Queue()
let next = 0

function open(d) {
  return new Promise((resolve) => {
    dialogs.list = [...dialogs.list, { ...d, id: ++next, resolve }]
  })
}

/**
 * Vraagt een bevestiging; geeft true (OK) of false (Annuleren, Escape, terug).
 * opts: title, ok (tekst van de knop), danger (rode knop).
 */
export const ask = (text, opts = {}) => open({ kind: 'ask', text, ...opts })

/**
 * Vraagt een tekst; geeft de ingevulde tekst, of null bij Annuleren.
 * opts: title, value (beginwaarde), ok, placeholder, inputmode ('numeric', ...), type ('text', 'password', 'url').
 */
export const askText = (text, opts = {}) => open({ kind: 'text', text, value: '', ...opts })

/** Sluit een venster met dit antwoord. */
export function answer(d, value) {
  dialogs.list = dialogs.list.filter((x) => x.id !== d.id)
  d.resolve(value)
}
