import { createHmac } from 'node:crypto'

// TOTP (RFC 6238, SHA-1, 6 cijfers, 30 s) zonder extra pakket.
function base32(s) {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of s.replace(/=+$/, '').toUpperCase()) bits += abc.indexOf(ch).toString(2).padStart(5, '0')
  const out = []
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(out)
}

export const step = () => Math.floor(Date.now() / 1000 / 30)

export function totp(secret, at = step()) {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(at))
  const h = createHmac('sha1', base32(secret)).update(msg).digest()
  const o = h[h.length - 1] & 0xf
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

// De server weigert een code die al gebruikt is: wacht tot er een nieuwe is.
export async function freshCode(secret, used) {
  while (used !== undefined && step() <= used) await new Promise((r) => setTimeout(r, 500))
  const at = step()
  return { code: totp(secret, at), at }
}
