// Tekst naar het klembord, ook over gewoon http (IP-adres) waar navigator.clipboard niet bestaat.
export async function copyText(text) {
  try {
    if (window.isSecureContext && navigator.clipboard) { await navigator.clipboard.writeText(text); return true }
  } catch { /* val terug op de oude manier */ }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.cssText = 'position:fixed;left:-9999px;top:0'
  document.body.append(ta)
  ta.select()
  let ok = false
  try { ok = document.execCommand('copy') } catch { /* niet gelukt */ }
  ta.remove()
  return ok
}
