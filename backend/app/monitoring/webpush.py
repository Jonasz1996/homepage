"""Web push: meldingen naar de eigen gsm of browser, zonder Telegram, ntfy of mail ertussen.

Versleuteling volgens RFC 8291 (aes128gcm) en aanmelding bij de pushdienst met VAPID (RFC 8292), allebei met
alleen het pakket cryptography. De worker roept run_webpush elke paar seconden op; draait de worker niet, dan
doet de API het (daarom mogen twee processen dit tegelijk doen: elke melding en elke wachtrijrij wordt eerst
met een voorwaardelijke UPDATE geclaimd).
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..deps import notify
from ..models import AppState, Notification, PushQueue, PushSubscription
from ..security import decrypt, decrypt_json, encrypt

log = logging.getLogger("homepage.webpush")

STATE_KEY = "webpush"
DEFAULT_SUB = "mailto:homepage@localhost"
LEVELS = {"info": 0, "warn": 1, "err": 2}
TTL = 86400
KEEP = timedelta(hours=24)
BACKOFF = (30, 120, 600, 1800, 3600)
PER_MINUTE = 10
# Zolang een rij "in behandeling" is; loopt een proces vast, dan neemt een ander ze daarna over.
LEASE = timedelta(minutes=5)
CLAIM_LIMIT = 50
DUE_LIMIT = 500
TIMEOUT = 10.0
# Een pushbericht mag 4096 bytes zijn: 86 bytes kop, 1 byte afsluiter en 16 bytes tag gaan eraf.
MAX_PLAIN = 3900
RS = 4096

PUSH_HOSTS = ("fcm.googleapis.com",)
PUSH_SUFFIXES = (".push.apple.com", ".push.services.mozilla.com", ".notify.windows.com")
# Een toestel dat de pushdienst niet meer kent, blijft zo lang staan (zie PushSubscription.gone_at).
GONE_KEEP = timedelta(days=30)

# Verstuurd per toestel (tijdstippen), voor het maximum per minuut. Per proces: genoeg, want de API doet dit
# alleen als de worker niet draait.
_sent: dict[int, deque[float]] = defaultdict(deque)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _aware(dt: datetime | None) -> datetime | None:
    # SQLite geeft tijdstippen zonder tijdzone terug; alles staat in UTC.
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def endpoint_hash(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode()).hexdigest()


def endpoint_ok(endpoint) -> bool:
    """Alleen echte pushdiensten: anders kan een pushadres de server naar het eigen netwerk laten verbinden."""
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 1000:
        return False
    # Alleen zichtbare ASCII: een stuurteken laat httpx later weigeren, en dat legde het versturen naar alle
    # toestellen stil.
    if any(not 0x21 <= ord(c) <= 0x7E for c in endpoint) or any(c in endpoint for c in "\\@"):
        return False
    try:
        p = urlsplit(endpoint)
        port = p.port
        if httpx.URL(endpoint).host != (p.hostname or ""):
            return False
    except (ValueError, httpx.InvalidURL):
        return False
    host = (p.hostname or "").lower()
    if p.scheme != "https" or port not in (None, 443) or not host:
        return False
    return host in PUSH_HOSTS or host.endswith(PUSH_SUFFIXES)


def service_of(endpoint: str) -> str | None:
    """Welke pushdienst (fcm.googleapis.com, .push.apple.com, ...): een browser blijft bij dezelfde."""
    host = (urlsplit(endpoint).hostname or "").lower()
    return next((x for x in PUSH_HOSTS + PUSH_SUFFIXES if host == x or host.endswith(x)), None)


def check_keys(p256dh: str, auth: str) -> tuple[bytes, bytes] | None:
    """De sleutels van de browser: een ongecomprimeerd P-256-punt (65 bytes) en een geheim van 16 bytes."""
    try:
        pub, secret = unb64u(p256dh), unb64u(auth)
        if len(pub) != 65 or pub[0] != 4 or len(secret) != 16:
            return None
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    except (ValueError, TypeError):
        return None
    return pub, secret


# --- RFC 8291: versleuteling --------------------------------------------------------------------------------

def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _public_bytes(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def encrypt_payload(plaintext: bytes, p256dh: bytes, auth: bytes, *, salt: bytes | None = None,
                    private_key: ec.EllipticCurvePrivateKey | None = None, rs: int = RS) -> bytes:
    """aes128gcm-bericht voor één toestel. salt en private_key zijn alleen voor de testvector; anders telkens nieuw."""
    salt = salt or os.urandom(16)
    as_key = private_key or ec.generate_private_key(ec.SECP256R1())
    as_public = _public_bytes(as_key)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    ecdh_secret = as_key.exchange(ec.ECDH(), ua_key)
    # HKDF met de auth-sleutel van de browser, daarna met de salt (RFC 8291 §3.3-3.4).
    prk_key = _hmac(auth, ecdh_secret)
    ikm = _hmac(prk_key, b"WebPush: info\x00" + p256dh + as_public + b"\x01")
    prk = _hmac(salt, ikm)
    cek = _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    # Eén record: de inhoud, dan 0x02 (laatste record), geen opvulling.
    cipher = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + rs.to_bytes(4, "big") + bytes([len(as_public)]) + as_public
    return header + cipher


# --- RFC 8292: VAPID ----------------------------------------------------------------------------------------

def vapid_jwt(endpoint: str, private_key: ec.EllipticCurvePrivateKey, sub: str, now: float | None = None) -> str:
    p = urlsplit(endpoint)
    claims = {"aud": f"{p.scheme}://{p.hostname}", "exp": int(now or time.time()) + 12 * 3600, "sub": sub}
    head = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":")).encode())
    der = private_key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{head}.{body}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _new_keys() -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.private_numbers().private_value.to_bytes(32, "big")
    return {"private": encrypt(b64u(raw)), "public": b64u(_public_bytes(key)), "sub": DEFAULT_SUB}


async def keys(db: AsyncSession) -> dict:
    """De VAPID-sleutels ({private (versleuteld), public, sub}), bij het eerste gebruik aangemaakt.
    De oproeper commit. INSERT ... ON CONFLICT: twee processen tegelijk krijgen hetzelfde sleutelpaar."""
    st = await db.get(AppState, STATE_KEY)
    if st is None or not (st.value or {}).get("private"):
        fresh = _new_keys()
        st = await ensure_state(db, STATE_KEY, fresh)
        if not (st.value or {}).get("private"):
            st.value = {**fresh, "sub": (st.value or {}).get("sub") or DEFAULT_SUB}
    return st.value


def private_key(state: dict) -> ec.EllipticCurvePrivateKey:
    raw = unb64u(decrypt(state["private"]))
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def origin_sub(origin: str | None) -> str | None:
    """https://host van het dashboard als VAPID-afzender (Apple weigert pushes zonder geldige sub)."""
    if not origin or len(origin) > 200:
        return None
    try:
        p = urlsplit(origin.strip())
        port = p.port
    except ValueError:
        return None
    if p.scheme != "https" or not p.hostname or p.path not in ("", "/") or p.query or p.username:
        return None
    return f"https://{p.hostname}" + (f":{port}" if port and port != 443 else "")


async def set_sub(db: AsyncSession, origin: str | None) -> None:
    sub = origin_sub(origin)
    if not sub:
        return
    st = await db.get(AppState, STATE_KEY)
    if st is not None and st.value.get("sub") != sub:
        st.value = {**st.value, "sub": sub}


# --- versturen ----------------------------------------------------------------------------------------------

def accepts(min_level: str, level: str, source: str, recovers: str | None = None) -> bool:
    """Laat dit toestel deze melding krijgen? Het weekrapport altijd, aanmeldingen vanaf warn. Herstel (ok) telt
    zoals de melding die hij herstelt (recovers: het niveau daarvan): "NAS weer bereikbaar" komt zo op een toestel
    dat ook "NAS down" kreeg, maar een geslaagde back-up of "2FA ingeschakeld" niet op een toestel voor storingen."""
    if source == "rapport":
        return True
    if level == "ok":
        level = recovers or "info"
    rank = LEVELS.get(level, 0)
    if source == "auth" and rank >= LEVELS["warn"]:
        return True
    return rank >= LEVELS.get(min_level, LEVELS["err"])


def payload_for(n) -> dict:
    # Zelfde storing, zelfde tag: op de gsm vervangt "weer bereikbaar" dan "down". Losse meldingen elk apart.
    tag = f"k{topic_for(n.push_key)}" if n.push_key else f"n{n.id}"
    return {"title": (n.title or "")[:200], "body": (n.body or "")[:1000], "level": n.level, "tag": tag,
            "url": f"/?open=melding&n={n.id}"}


def topic_for(key: str | None) -> str | None:
    """Topic-header (RFC 8030: hoogstens 32 tekens uit het base64url-alfabet): de pushdienst houdt van berichten met
    hetzelfde topic die nog niet afgeleverd zijn, alleen het nieuwste over."""
    return hashlib.sha256(key.encode()).hexdigest()[:32] if key else None


def _encode(payload: dict) -> bytes:
    p = dict(payload)
    data = json.dumps(p, ensure_ascii=False, separators=(",", ":")).encode()
    while len(data) > MAX_PLAIN and p.get("body"):
        # Zoveel bytes van de tekst weg als er te veel zijn (in JSON is een byte nooit korter), op een tekengrens.
        raw = p["body"].encode()
        p["body"] = raw[: max(0, len(raw) - (len(data) - MAX_PLAIN))].decode(errors="ignore")
        data = json.dumps(p, ensure_ascii=False, separators=(",", ":")).encode()
    return data


async def deliver(client: httpx.AsyncClient, info: dict, payload: dict, state: dict, key: ec.EllipticCurvePrivateKey,
                  topic: str | None = None) -> tuple[int | None, str | None]:
    """(HTTP-status, fout). None: netwerkfout (opnieuw proberen); 0: dit adres of deze sleutels gaan nooit lukken."""
    endpoint = info.get("endpoint")
    if not endpoint_ok(endpoint):
        return 0, "pushadres niet toegelaten"
    keys_ = check_keys(info.get("p256dh") or "", info.get("auth") or "")
    if keys_ is None:
        return 0, "ongeldige sleutels van het toestel"
    body = encrypt_payload(_encode(payload), *keys_)
    headers = {
        "TTL": str(TTL), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
        "Authorization": f"vapid t={vapid_jwt(endpoint, key, state.get('sub') or DEFAULT_SUB)}, k={state['public']}",
        "Urgency": "high" if payload.get("level") == "err" else "normal",
    }
    if topic:
        headers["Topic"] = topic
    try:
        r = await client.post(endpoint, content=body, headers=headers, follow_redirects=False, timeout=TIMEOUT)
    except httpx.InvalidURL:
        return 0, "ongeldig pushadres"
    except httpx.HTTPError as e:
        return None, f"netwerkfout: {type(e).__name__}"
    if r.status_code in (200, 201, 202):
        return r.status_code, None
    detail = " ".join((r.text or "").split())[:200]
    return r.status_code, f"HTTP {r.status_code}" + (f": {detail}" if detail else "")


def _kind(code: int | None) -> str:
    if code in (200, 201, 202):
        return "ok"
    if code in (404, 410):
        return "gone"
    if code is None or code == 429 or code >= 500:
        return "retry"
    return "fail"


def _mark_ok(sub: PushSubscription, now: datetime) -> None:
    sub.last_ok_at, sub.fail_count, sub.last_error, sub.warned, sub.gone_at = now, 0, None, False, None


def _mark_failed(db: AsyncSession, sub: PushSubscription, error: str) -> None:
    sub.last_error = error[:300]
    sub.fail_count = (sub.fail_count or 0) + 1
    if sub.fail_count >= 3 and not sub.warned:
        sub.warned = True
        notify(db, f"Meldingen naar {sub.label} mislukken: {sub.last_error}"[:200],
               "Ze komen niet aan. Test het toestel in 'Meldingen op je gsm', of zet het daar opnieuw aan.",
               level="err", source="homepage")


async def _gone(db: AsyncSession, sub: PushSubscription, now: datetime | None = None) -> None:
    """De pushdienst kent het toestel niet meer (afgemeld, app verwijderd): niets meer naartoe sturen, en zeggen op de
    andere. De rij blijft nog even: meldt de browser zich zelf opnieuw aan, dan werkt hij weer.

    Alleen als het adres dat faalde nog het huidige is: vernieuwde de browser het intussen (de service worker, terwijl
    dit bericht onderweg was), dan is het toestel niet weg."""
    res = await db.execute(update(PushSubscription).where(
        PushSubscription.id == sub.id, PushSubscription.endpoint_hash == sub.endpoint_hash,
        PushSubscription.gone_at.is_(None)).values(gone_at=now or datetime.now(timezone.utc),
                                                    last_error="de pushdienst kent dit toestel niet meer")
        .execution_options(synchronize_session=False))
    if res.rowcount == 1:
        await db.execute(delete(PushQueue).where(PushQueue.subscription_id == sub.id))
        notify(db, f"Je toestel {sub.label} krijgt geen meldingen meer",
               "De pushdienst kent het niet meer (afgemeld of app verwijderd). Zet het opnieuw aan in 'Meldingen op je "
               "gsm'.", level="err", source="homepage")


def _recent(sid: int) -> int:
    q = _sent[sid]
    now = time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    return len(q)


async def _claim(db: AsyncSession, now: datetime) -> None:
    # Te oud om nog naar de gsm te sturen (bv. de worker lag een dag stil): alleen in het meldingencentrum.
    await db.execute(update(Notification).where(Notification.pushed_at.is_(None), Notification.ts <= now - KEEP)
                     .values(pushed_at=now).execution_options(synchronize_session=False))
    subs = list((await db.execute(select(PushSubscription.id, PushSubscription.min_level)
                                  .where(PushSubscription.gone_at.is_(None)))).all())
    if not subs:
        await db.execute(update(Notification).where(Notification.pushed_at.is_(None))
                         .values(pushed_at=now).execution_options(synchronize_session=False))
        return
    rows = (await db.execute(
        select(Notification.id, Notification.level, Notification.source, Notification.push_key, Notification.recovers)
        .where(Notification.pushed_at.is_(None), Notification.ts > now - KEEP)
        .order_by(Notification.id).limit(CLAIM_LIMIT))).all()
    for n in rows:
        res = await db.execute(update(Notification).where(Notification.id == n.id, Notification.pushed_at.is_(None))
                               .values(pushed_at=now).execution_options(synchronize_session=False))
        if res.rowcount != 1:
            continue  # een ander proces was sneller
        for sid, min_level in subs:
            if not accepts(min_level, n.level, n.source, n.recovers):
                continue
            if n.push_key:
                # Nieuwer nieuws over dezelfde storing: een oudere melding die nog wacht (opnieuw proberen) zou
                # anders na deze aankomen ("down" na "weer bereikbaar"). Alleen dezelfde storing: een andere melding
                # over dezelfde tegel (een andere node in de cluster) blijft gewoon staan.
                await _supersede(db, sid, n.id, n.push_key)
            db.add(PushQueue(subscription_id=sid, notification_id=n.id, attempts=0, next_at=now, created_at=now))


async def _supersede(db: AsyncSession, sub_id: int, notification_id: int, key: str) -> None:
    """Oudere meldingen over dezelfde storing uit de wachtrij van dit toestel."""
    older = select(Notification.id).where(Notification.push_key == key, Notification.id < notification_id)
    await db.execute(delete(PushQueue).where(PushQueue.subscription_id == sub_id, PushQueue.notification_id.in_(older))
                     .execution_options(synchronize_session=False))


async def _send_due(db: AsyncSession, client: httpx.AsyncClient, now: datetime) -> None:
    due = (await db.execute(
        select(PushQueue.id, PushQueue.subscription_id, PushQueue.notification_id, PushQueue.attempts,
               PushQueue.created_at, Notification.ts)
        .outerjoin(Notification, Notification.id == PushQueue.notification_id)
        .where(PushQueue.next_at <= now).order_by(PushQueue.id).limit(DUE_LIMIT))).all()
    if not due:
        return
    mine = []
    for r in due:
        res = await db.execute(update(PushQueue).where(PushQueue.id == r.id, PushQueue.next_at <= now)
                               .values(next_at=now + LEASE).execution_options(synchronize_session=False))
        if res.rowcount == 1:
            mine.append(r)
    await db.commit()
    if not mine:
        return
    state = await keys(db)
    key = private_key(state)
    by_sub: dict[int, list] = defaultdict(list)
    for r in mine:
        by_sub[r.subscription_id].append(r)
    for sid, items in by_sub.items():
        # Elk toestel apart: een fout bij het ene (kapotte rij, intussen verwijderd) houdt de andere niet tegen.
        try:
            sub = await db.get(PushSubscription, sid)
            if sub is None or sub.gone_at is not None:
                await db.execute(delete(PushQueue).where(PushQueue.id.in_([r.id for r in items])))
            else:
                await _send_device(db, client, sub, items, state, key, now)
            await db.commit()
        except Exception:
            log.exception("web push naar toestel %s mislukt", sid)
            await db.rollback()
            await db.execute(update(PushQueue).where(PushQueue.id.in_([r.id for r in items]))
                             .values(next_at=now + timedelta(seconds=BACKOFF[0]))
                             .execution_options(synchronize_session=False))
            await db.commit()


async def _send_device(db: AsyncSession, client: httpx.AsyncClient, sub: PushSubscription, items: list,
                       state: dict, key: ec.EllipticCurvePrivateKey, now: datetime) -> None:
    fresh = []
    for r in items:
        if now - _aware(r.ts or r.created_at) >= KEEP:
            # Een dag lang niet gelukt: opgeven (hij staat in het meldingencentrum).
            await db.execute(delete(PushQueue).where(PushQueue.id == r.id))
            if r.attempts:
                _mark_failed(db, sub, sub.last_error or "een dag lang niet afgeleverd")
        else:
            fresh.append(r)
    if not fresh:
        return
    ids = [r.notification_id for r in fresh if r.notification_id]
    notes = {n.id: n for n in (await db.execute(select(Notification).where(Notification.id.in_(ids)))).scalars()}
    # Per storing alleen het nieuwste: "down" en "weer bereikbaar" in dezelfde ronde (of een "down" die opnieuw
    # geprobeerd werd) mogen niet in de verkeerde volgorde aankomen.
    newest: dict[str, int] = {}
    for r in fresh:
        n = notes.get(r.notification_id)
        if n is not None and n.push_key:
            newest[n.push_key] = max(newest.get(n.push_key, 0), n.id)
    stale = [r.id for r in fresh if (n := notes.get(r.notification_id)) is not None and n.push_key
             and n.id < newest[n.push_key]]
    if stale:
        await db.execute(delete(PushQueue).where(PushQueue.id.in_(stale)))
        fresh = [r for r in fresh if r.id not in stale]
    budget = PER_MINUTE - _recent(sub.id)
    dropped: list[str] = []
    if len(fresh) > budget:
        if budget < 2:
            # Over een minuut is er weer ruimte.
            await db.execute(update(PushQueue).where(PushQueue.id.in_([r.id for r in fresh]))
                             .values(next_at=now + timedelta(seconds=60)).execution_options(synchronize_session=False))
            return
        # Te veel tegelijk: de nieuwste, en één bericht voor de rest (die staan in het meldingencentrum). De rest
        # blijft in de wachtrij tot dat bericht aankwam.
        drop, fresh = fresh[:len(fresh) - (budget - 1)], fresh[len(fresh) - (budget - 1):]
        dropped = [notes[r.notification_id].level if r.notification_id in notes else "info" for r in drop]
    info = decrypt_json(sub.data)
    for r in fresh:
        n = notes.get(r.notification_id)
        if n is None:
            await db.execute(delete(PushQueue).where(PushQueue.id == r.id))
            continue
        _sent[sub.id].append(time.monotonic())
        code, error = await deliver(client, info, payload_for(n), state, key, topic=topic_for(n.push_key))
        kind = _kind(code)
        if kind == "gone":
            await _gone(db, sub, now)
            return
        if kind == "ok":
            _mark_ok(sub, now)
            await db.execute(delete(PushQueue).where(PushQueue.id == r.id))
            if n.push_key:
                # Wat nog over dezelfde storing wacht (ook een samengevatte rest), is nu achterhaald.
                await _supersede(db, sub.id, n.id, n.push_key)
        elif kind == "retry":
            sub.last_error = f"{error} (wordt opnieuw geprobeerd)"[:300]
            attempts = r.attempts + 1
            wait = timedelta(seconds=BACKOFF[min(attempts, len(BACKOFF)) - 1])
            if now + wait - _aware(n.ts) >= KEEP:
                await db.execute(delete(PushQueue).where(PushQueue.id == r.id))
                _mark_failed(db, sub, error or "een dag lang niet afgeleverd")
            else:
                await db.execute(update(PushQueue).where(PushQueue.id == r.id)
                                 .values(attempts=attempts, next_at=now + wait)
                                 .execution_options(synchronize_session=False))
        else:
            await db.execute(delete(PushQueue).where(PushQueue.id == r.id))
            _mark_failed(db, sub, error or f"HTTP {code}")
    if dropped:
        worst = max(dropped, key=lambda lv: LEVELS.get(lv, 0))
        _sent[sub.id].append(time.monotonic())
        summary = {"title": f"{len(dropped)} meldingen meer in het dashboard",
                   "body": "Te veel tegelijk voor je gsm: de rest staat in het meldingencentrum.",
                   "level": worst if worst in LEVELS else "info", "tag": "meer", "url": "/"}
        code, error = await deliver(client, info, summary, state, key)
        kind = _kind(code)
        if kind == "gone":
            await _gone(db, sub, now)
        elif kind == "ok":
            _mark_ok(sub, now)
            await db.execute(delete(PushQueue).where(PushQueue.id.in_([r.id for r in drop])))
        else:
            # Niet aangekomen: de weggelaten meldingen later opnieuw (samengevat of apart, naargelang de ruimte), tot
            # een dag oud. Wat intussen over dezelfde storing aankwam, haalt ze weg (_supersede).
            sub.last_error = (error or f"HTTP {code}")[:300]
            attempts = max((r.attempts for r in drop), default=0) + 1
            await db.execute(update(PushQueue).where(PushQueue.id.in_([r.id for r in drop]))
                             .values(attempts=attempts,
                                     next_at=now + timedelta(seconds=BACKOFF[min(attempts, len(BACKOFF)) - 1]))
                             .execution_options(synchronize_session=False))


async def run_webpush(db: AsyncSession, client: httpx.AsyncClient) -> None:
    """Nieuwe meldingen in de wachtrij zetten en wat klaarstaat versturen. Commit zelf."""
    now = datetime.now(timezone.utc)
    await _claim(db, now)
    await db.commit()
    await _send_due(db, client, now)
    await db.commit()


async def send_test(db: AsyncSession, client: httpx.AsyncClient, sub: PushSubscription) -> str | None:
    """Meteen een testbericht naar dit toestel. Geeft de fout terug, of None. De oproeper commit."""
    state = await keys(db)
    payload = {"title": "Testmelding van de homepage", "body": "Als je dit ziet, werken de meldingen op dit toestel.",
               "level": "info", "tag": "test", "url": "/"}
    code, error = await deliver(client, decrypt_json(sub.data), payload, state, private_key(state))
    kind = _kind(code)
    if kind == "ok":
        _mark_ok(sub, datetime.now(timezone.utc))
        return None
    if kind == "gone":
        await _gone(db, sub)
        return "De pushdienst kent dit toestel niet meer: zet het opnieuw aan."
    sub.last_error = (error or f"HTTP {code}")[:300]
    return sub.last_error


async def status(db: AsyncSession) -> dict:
    """Voor de instellingen-checklist: hoeveel toestellen, welke falen, wanneer het laatst iets aankwam."""
    subs = list((await db.execute(select(PushSubscription).order_by(PushSubscription.id))).scalars())
    live = [s for s in subs if s.gone_at is None]
    oks = [_aware(s.last_ok_at) for s in live if s.last_ok_at]
    return {"devices": len(live),
            "failing": [s.label for s in live if (s.fail_count or 0) >= 3] + [f"{s.label} (afgemeld)" for s in subs
                                                                              if s.gone_at is not None],
            "last_ok": max(oks) if oks else None}


async def forget_renew(db: AsyncSession, user_id: int) -> None:
    """Na een nieuw wachtwoord of "andere sessies afmelden": de vernieuwgeheimen van de toestellen gelden niet meer
    (wie er een kopieerde, kan zo de meldingen niet naar zich toe halen). De toestellen blijven meldingen krijgen;
    vernieuwt de browser later zelf zijn pushadres, dan zet je dat toestel opnieuw aan."""
    await db.execute(update(PushSubscription).where(PushSubscription.user_id == user_id)
                     .values(renew_hash=hashlib.sha256(os.urandom(32)).hexdigest(), prev_renew_hash=None)
                     .execution_options(synchronize_session=False))


async def forget_gone(db: AsyncSession, now: datetime) -> None:
    """Toestellen die de pushdienst al een maand niet meer kent: weg (de worker, bij het opruimen)."""
    await db.execute(delete(PushSubscription).where(PushSubscription.gone_at < now - GONE_KEEP))


async def endpoint_hosts(db: AsyncSession) -> list[tuple[str, str]]:
    """(host van de pushdienst, toestel): voor de firewall-weergave (uitgaand 443)."""
    out = []
    for s in (await db.execute(select(PushSubscription))).scalars():
        try:
            host = urlsplit(decrypt_json(s.data).get("endpoint") or "").hostname
        except Exception:  # sleutel gewisseld of kapotte rij: dan niet in de lijst
            continue
        if host:
            out.append((host, s.label))
    return out
