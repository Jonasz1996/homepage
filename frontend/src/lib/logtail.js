// Live meekijken in de logviewer (Logs.svelte). De lijst staat op tijd, nieuwste eerst; de id's volgen de volgorde van
// binnenkomen. Die twee lopen niet gelijk: een regel die rsyslog vasthield, komt later binnen met zijn eigen, oudere
// tijd. Dezelfde id twee keer in de lijst laat {#each} met sleutel vastlopen, tot de filter verandert.

// Waar live meekijken verder gaat na het zoeken: de grootste id van toen (last_id). Zonder last_id de grootste id in
// de hele lijst, niet alleen bovenaan.
export const cursorOf = (r) => r.last_id ?? Math.max(0, ...r.items.map((i) => i.id))

// Na live meekijken: verder vanaf de grootste id die binnenkwam.
export const advance = (cursor, fresh) => Math.max(cursor, ...fresh.map((i) => i.id))

const without = (rows, items) => {
  const have = new Set(items.map((i) => i.id))
  return rows.filter((i) => !have.has(i.id))
}

// Live binnengekomen regels bovenaan, hoogstens max in de lijst; wat er al staat niet nog eens.
export function prepend(items, fresh, max = 3000) {
  const add = without(fresh, items)
  return add.length ? [...add, ...items].slice(0, max) : items
}

// Meer laden: onderaan, zonder wat er al staat (een vastgehouden regel die live bovenaan kwam).
export const append = (items, older) => [...items, ...without(older, items)]
