"""Web push: versleuteling (RFC 8291), VAPID (RFC 8292), aanmelden, en de wachtrij naar een nep-pushdienst."""

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update

from app.db import get_db
from app.deps import notify
from app.main import app
from app.models import AppState, AuditLog, Group, Notification, Page, PushQueue, PushSubscription, Service, Session
from app.monitoring import ports, webpush
from app.monitoring.webpush import b64u, unb64u
from app.routers import webpush as webpush_router
from app.security import decrypt_json


@pytest.fixture(autouse=True)
def _fresh():
    webpush._sent.clear()
    webpush_router.renew_limiter._fails.clear()
    yield
    webpush._sent.clear()


@pytest.fixture
async def authed(authed):
    """Ingelogd, en wat er al was (bv. "2FA ingeschakeld" bij het instellen) is al afgehandeld, zoals door de worker."""
    await _run(PushService([]))
    return authed


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _stale(authed) -> None:
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _pub(key) -> bytes:
    return webpush._public_bytes(key)


def decrypt(body: bytes, ua_key: ec.EllipticCurvePrivateKey, auth: bytes) -> bytes:
    """Wat de browser doet (RFC 8291 aan de ontvangstkant): om te controleren wat er echt verstuurd is."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public, cipher = body[21:21 + idlen], body[21 + idlen:]
    assert rs == 4096 and len(cipher) <= rs
    secret = ua_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ikm = _hmac(_hmac(auth, secret), b"WebPush: info\x00" + _pub(ua_key) + as_public + b"\x01")
    prk = _hmac(salt, ikm)
    plain = AESGCM(_hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]).decrypt(
        _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12], cipher, None)
    assert plain.endswith(b"\x02")
    return plain[:-1]


# --- RFC 8291 en RFC 8292 ------------------------------------------------------------------------------------

# RFC 8291, Appendix A.
VECTOR = {
    "plaintext": "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24",
    "as_public": "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "ua_private": "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "auth": "BTBZMqHH6r4Tts7J_aSIgg",
    "body": "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_"
            "yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
}


def _key(raw: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(unb64u(raw), "big"), ec.SECP256R1())


def test_rfc8291_testvector():
    as_key, ua_key = _key(VECTOR["as_private"]), _key(VECTOR["ua_private"])
    assert b64u(_pub(as_key)) == VECTOR["as_public"] and b64u(_pub(ua_key)) == VECTOR["ua_public"]
    body = webpush.encrypt_payload(unb64u(VECTOR["plaintext"]), unb64u(VECTOR["ua_public"]), unb64u(VECTOR["auth"]),
                                   salt=unb64u(VECTOR["salt"]), private_key=as_key)
    assert b64u(body) == VECTOR["body"]
    assert decrypt(body, ua_key, unb64u(VECTOR["auth"])) == b"When I grow up, I want to be a watermelon"
    # Zonder vaste salt en sleutel: elke keer anders, en toch leesbaar.
    other = webpush.encrypt_payload(b"hallo", unb64u(VECTOR["ua_public"]), unb64u(VECTOR["auth"]))
    assert other != webpush.encrypt_payload(b"hallo", unb64u(VECTOR["ua_public"]), unb64u(VECTOR["auth"]))
    assert decrypt(other, ua_key, unb64u(VECTOR["auth"])) == b"hallo"


def _verify_vapid(header: str, endpoint: str) -> dict:
    assert header.startswith("vapid t=")
    token, _, k = header[len("vapid t="):].partition(", k=")
    head, body, sig = token.split(".")
    assert json.loads(unb64u(head)) == {"typ": "JWT", "alg": "ES256"}
    raw = unb64u(sig)
    assert len(raw) == 64
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(k))
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
               f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
    claims = json.loads(unb64u(body))
    assert claims["aud"] == "https://" + httpx.URL(endpoint).host
    return {**claims, "k": k}


def test_vapid_jwt():
    key = ec.generate_private_key(ec.SECP256R1())
    jwt = webpush.vapid_jwt("https://web.push.apple.com/QGuQyavXutnMH", key, "https://homepage.jbogaert.be")
    header = f"vapid t={jwt}, k={b64u(_pub(key))}"
    claims = _verify_vapid(header, "https://web.push.apple.com/QGuQyavXutnMH")
    assert claims["aud"] == "https://web.push.apple.com" and claims["sub"] == "https://homepage.jbogaert.be"
    assert abs(claims["exp"] - (time.time() + 12 * 3600)) < 60


def test_endpoint_allowlist():
    ok = ["https://fcm.googleapis.com/fcm/send/abc:def", "https://web.push.apple.com/QGuQ",
          "https://updates.push.services.mozilla.com/wpush/v2/gAAA", "https://wns2-par02p.notify.windows.com/w/?token=AB%2b"]
    bad = ["http://fcm.googleapis.com/fcm/send/abc", "https://192.168.0.10/push", "https://nas.lan/push",
           "https://fcm.googleapis.com.evil.com/x", "https://evilpush.apple.com/x", "https://push.apple.com.evil/x",
           "https://fcm.googleapis.com:8443/x", "https://user@fcm.googleapis.com/x", "ftp://fcm.googleapis.com/x",
           "https://fcm.googleapis.com/" + "a" * 1000, "", None, "https://localhost/x"]
    assert all(webpush.endpoint_ok(e) for e in ok)
    assert not any(webpush.endpoint_ok(e) for e in bad)


# --- toestellen en een nep-pushdienst --------------------------------------------------------------------------

class Phone:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = os.urandom(16)

    def sub(self, **extra) -> dict:
        return {"endpoint": self.endpoint, "keys": {"p256dh": b64u(_pub(self.key)), "auth": b64u(self.auth)}, **extra}


class PushService:
    """Neemt pushberichten aan zoals FCM of Apple; per adres een vast antwoord (standaard 201)."""

    def __init__(self, phones: list[Phone]) -> None:
        self.phones = {p.endpoint: p for p in phones}
        self.status: dict[str, int] = {}
        self.got: list[dict] = []
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if self.down:
            raise httpx.ConnectError("geen verbinding", request=request)
        phone = self.phones[url]
        msg = json.loads(decrypt(request.content, phone.key, phone.auth))
        self.got.append({"to": url, "msg": msg, "headers": dict(request.headers)})
        return httpx.Response(self.status.get(url, 201), text="" if self.status.get(url, 201) < 300 else "nee")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def to(self, phone: Phone) -> list[dict]:
        return [g["msg"] for g in self.got if g["to"] == phone.endpoint]


A = "https://fcm.googleapis.com/fcm/send/toestel-a"
B = "https://web.push.apple.com/toestel-b"
C = "https://updates.push.services.mozilla.com/wpush/v2/toestel-c"


async def _subscribe(authed, phone: Phone, label: str, level: str = "err") -> dict:
    r = await authed.post("/api/webpush/subscriptions", json=phone.sub(label=label, min_level=level),
                          headers={"Origin": "https://homepage.jbogaert.be"})
    assert r.status_code == 201, r.text
    return r.json()


async def _run(svc: PushService) -> None:
    agen, db = await _db()
    async with svc.client() as client:
        await webpush.run_webpush(db, client)
    await agen.aclose()


async def _notify(*items: dict) -> list[int]:
    agen, db = await _db()
    for it in items:
        notify(db, **it)
    await db.commit()
    ids = list((await db.execute(select(Notification.id).order_by(Notification.id.desc()).limit(len(items)))).scalars())
    await agen.aclose()
    return sorted(ids)


async def _rows(model, *where):
    agen, db = await _db()
    rows = list((await db.execute(select(model).where(*where).order_by(model.id))).scalars())
    await agen.aclose()
    return rows


async def test_subscribe_needs_recent_auth_and_hides_secrets(authed):
    phone = Phone(A)
    key = (await authed.get("/api/webpush/key")).json()["public_key"]
    assert len(unb64u(key)) == 65 and (await authed.get("/api/webpush/key")).json()["public_key"] == key

    await _stale(authed)
    r = await authed.post("/api/webpush/subscriptions", json=phone.sub(label="Pixel"))
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})).status_code == 200
    first = await _subscribe(authed, phone, "Pixel")
    assert first["renew"] and first["id"]

    # Zelfde toestel opnieuw: dezelfde rij, nieuw vernieuwgeheim.
    again = await _subscribe(authed, phone, "Pixel 8", "warn")
    assert again["id"] == first["id"] and again["renew"] != first["renew"]
    items = (await authed.get("/api/webpush/subscriptions")).json()
    assert len(items) == 1 and items[0]["label"] == "Pixel 8" and items[0]["min_level"] == "warn"
    assert set(items[0]) == {"id", "label", "min_level", "created_at", "last_ok_at", "last_error", "fail_count", "gone"}
    text = json.dumps(items)
    assert "toestel-a" not in text and "p256dh" not in text

    (sub,) = await _rows(PushSubscription)
    assert decrypt_json(sub.data)["endpoint"] == A and sub.renew_hash == hashlib.sha256(again["renew"].encode()).hexdigest()
    agen, db = await _db()
    st = await db.get(AppState, "webpush")
    assert st.value["sub"] == "https://homepage.jbogaert.be" and st.value["public"] == key
    assert "private" in st.value and len(st.value["private"]) > 60  # versleuteld
    await agen.aclose()
    assert [a.action for a in await _rows(AuditLog, AuditLog.action.like("webpush%"))] == ["webpush_added", "webpush_added"]

    # Wijzigen en verwijderen vragen ook een recente bevestiging.
    await _stale(authed)
    r = await authed.patch(f"/api/webpush/subscriptions/{first['id']}", json={"min_level": "info"})
    assert r.status_code == 403
    assert (await authed.delete(f"/api/webpush/subscriptions/{first['id']}")).status_code == 403
    assert (await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})).status_code == 200
    r = await authed.patch(f"/api/webpush/subscriptions/{first['id']}", json={"min_level": "info", "label": "gsm"})
    assert r.status_code == 200 and r.json()["min_level"] == "info" and r.json()["label"] == "gsm"
    assert (await authed.patch(f"/api/webpush/subscriptions/{first['id']}", json={"min_level": "alles"})).status_code == 422


async def test_subscribe_rejects_bad_endpoints_and_keys(authed):
    for endpoint in ("http://fcm.googleapis.com/fcm/send/x", "https://192.168.0.10/push", "https://nas.lan/wpush"):
        r = await authed.post("/api/webpush/subscriptions", json=Phone(endpoint).sub(label="x"))
        assert r.status_code == 422, endpoint
    good = Phone(A).sub(label="x")
    for keys in ({"p256dh": b64u(b"\x04" + b"1" * 63), "auth": good["keys"]["auth"]},
                 {"p256dh": good["keys"]["p256dh"], "auth": b64u(b"kort")},
                 {"p256dh": b64u(b"\x04" + b"\x01" * 64), "auth": good["keys"]["auth"]}):
        assert (await authed.post("/api/webpush/subscriptions", json={**good, "keys": keys})).status_code == 422
    assert (await authed.get("/api/webpush/subscriptions")).json() == []
    # Zonder login niets.
    authed.cookies.clear()
    assert (await authed.get("/api/webpush/key")).status_code == 401
    assert (await authed.get("/api/webpush/subscriptions")).status_code == 401


async def test_level_filter_and_payload(authed):
    a, b, c = Phone(A), Phone(B), Phone(C)
    await _subscribe(authed, a, "alleen storingen", "err")
    await _subscribe(authed, b, "waarschuwingen", "warn")
    await _subscribe(authed, c, "alles", "info")
    agen, db = await _db()
    db.add(Page(name="p", groups=[Group(name="g", services=[Service(name="NAS")])]))
    await db.commit()
    sid = (await db.execute(select(Service.id))).scalar_one()
    await agen.aclose()
    key = f"svc{sid}"
    ids = await _notify(
        {"title": "NAS down", "body": "Time-out", "level": "err", "source": "monitor", "service_id": sid, "key": key},
        {"title": "Schijf 85% vol", "level": "warn", "source": "capaciteit"},
        {"title": "Back-up gelukt", "level": "info", "source": "backup"},
        {"title": "Login vanaf nieuw IP", "level": "warn", "source": "auth"},
        {"title": "2FA ingeschakeld", "level": "info", "source": "auth"},
        {"title": "Weekrapport", "level": "info", "source": "rapport"},
    )
    svc = PushService([a, b, c])
    await _run(svc)
    # Herstel komt op elk toestel dat de storing kreeg; "Back-up gelukt" (ok zonder storing) alleen bij "alles".
    await _notify({"title": "NAS weer up", "level": "ok", "source": "monitor", "service_id": sid, "key": key,
                   "recovers": "err"},
                  {"title": "Hersteltest geslaagd", "level": "ok", "source": "backup"})
    await _run(svc)
    titles = lambda p: [m["title"] for m in svc.to(p)]  # noqa: E731
    assert titles(a) == ["NAS down", "Login vanaf nieuw IP", "Weekrapport", "NAS weer up"]
    assert titles(b) == ["NAS down", "Schijf 85% vol", "Login vanaf nieuw IP", "Weekrapport", "NAS weer up"]
    assert titles(c) == ["NAS down", "Schijf 85% vol", "Back-up gelukt", "Login vanaf nieuw IP", "2FA ingeschakeld",
                         "Weekrapport", "NAS weer up", "Hersteltest geslaagd"]

    down = next(g for g in svc.got if g["to"] == A and g["msg"]["title"] == "NAS down")
    assert down["msg"] == {"title": "NAS down", "body": "Time-out", "level": "err", "tag": f"k{webpush.topic_for(key)}",
                           "url": f"/?open=melding&n={ids[0]}"}
    h = down["headers"]
    assert h["ttl"] == "86400" and h["content-encoding"] == "aes128gcm" and h["urgency"] == "high"
    assert h["topic"] == webpush.topic_for(key) and len(h["topic"]) <= 32
    claims = _verify_vapid(h["authorization"], A)
    assert claims["sub"] == "https://homepage.jbogaert.be"
    assert claims["k"] == (await authed.get("/api/webpush/key")).json()["public_key"]
    report = next(g for g in svc.got if g["to"] == A and g["msg"]["title"] == "Weekrapport")
    assert report["headers"]["urgency"] == "normal" and "topic" not in report["headers"]
    assert report["msg"]["tag"] == f"n{ids[-1]}"
    assert apple_aud(svc) == "https://web.push.apple.com"

    # Alles is geclaimd, de wachtrij is leeg, en de toestellen staan op "gelukt".
    assert not await _rows(Notification, Notification.pushed_at.is_(None))
    assert not await _rows(PushQueue)
    assert all(s.last_ok_at and s.fail_count == 0 for s in await _rows(PushSubscription))
    items = (await authed.get("/api/webpush/subscriptions")).json()
    assert all(i["last_ok_at"] for i in items)


def apple_aud(svc: PushService) -> str:
    return _verify_vapid(next(g for g in svc.got if g["to"] == B)["headers"]["authorization"], B)["aud"]


async def test_each_notification_is_pushed_once_and_push_false_never(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    await _notify({"title": "eerste", "level": "err"}, {"title": "stil", "level": "err", "push": False})
    svc = PushService([a])
    await _run(svc)
    await _run(svc)
    await _notify({"title": "tweede", "level": "err"})
    await _run(svc)
    await _run(svc)
    assert [m["title"] for m in svc.to(a)] == ["eerste", "tweede"]
    # Een ander proces dat dezelfde melding nog wil claimen, krijgt niets (rowcount 0).
    agen, db = await _db()
    res = await db.execute(update(Notification).where(Notification.pushed_at.is_(None)).values(pushed_at=datetime.now(timezone.utc)))
    assert res.rowcount == 0
    await agen.aclose()


async def test_without_devices_and_old_notifications_are_just_marked(authed):
    await _notify({"title": "niemand", "level": "err"})
    svc = PushService([])
    await _run(svc)
    assert not await _rows(Notification, Notification.pushed_at.is_(None)) and not svc.got

    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    (old,) = await _notify({"title": "van eergisteren", "level": "err"})
    agen, db = await _db()
    await db.execute(update(Notification).where(Notification.id == old)
                     .values(ts=datetime.now(timezone.utc) - timedelta(hours=30)))
    await db.commit()
    await agen.aclose()
    svc = PushService([a])
    await _run(svc)
    assert not svc.got and not await _rows(Notification, Notification.pushed_at.is_(None))


async def test_410_removes_device_and_tells_the_others(authed):
    a, b = Phone(A), Phone(B)
    await _subscribe(authed, a, "oude gsm")
    await _subscribe(authed, b, "iPhone")
    await _notify({"title": "NAS down", "level": "err"})
    svc = PushService([a, b])
    svc.status[A] = 410
    await _run(svc)
    # Blijft nog even staan (de browser kan zich zelf opnieuw aanmelden), maar krijgt niets meer.
    assert [(s.label, s.gone_at is not None) for s in await _rows(PushSubscription)] == [("oude gsm", True),
                                                                                         ("iPhone", False)]
    gone = await _rows(Notification, Notification.title == "Je toestel oude gsm krijgt geen meldingen meer")
    assert len(gone) == 1 and gone[0].level == "err" and gone[0].pushed_at is None
    await _run(svc)
    assert [m["title"] for m in svc.to(b)] == ["NAS down", "Je toestel oude gsm krijgt geen meldingen meer"]
    assert not await _rows(PushQueue)


async def test_503_is_retried_with_backoff_then_dropped_after_a_day(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    (nid,) = await _notify({"title": "NAS down", "level": "err"})
    svc = PushService([a])
    svc.status[A] = 503
    await _run(svc)
    (row,) = await _rows(PushQueue)
    wait = (webpush._aware(row.next_at) - datetime.now(timezone.utc)).total_seconds()
    assert row.attempts == 1 and 20 < wait <= 30
    await _run(svc)  # nog niet aan de beurt
    assert len(svc.got) == 1

    async def due(**values):
        agen, db = await _db()
        await db.execute(update(PushQueue).values(next_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        if values:
            await db.execute(update(Notification).where(Notification.id == nid).values(**values))
        await db.commit()
        await agen.aclose()

    await due()
    svc.down = True  # netwerkfout telt ook als "later opnieuw"
    await _run(svc)
    (row,) = await _rows(PushQueue)
    wait = (webpush._aware(row.next_at) - datetime.now(timezone.utc)).total_seconds()
    assert row.attempts == 2 and 100 < wait <= 120
    (sub,) = await _rows(PushSubscription)
    assert "netwerkfout" in sub.last_error and sub.fail_count == 0

    await due()
    svc.down = False
    await _run(svc)
    (row,) = await _rows(PushQueue)
    assert row.attempts == 3

    # Een dag later: opgeven.
    await due(ts=datetime.now(timezone.utc) - timedelta(hours=25))
    await _run(svc)
    assert not await _rows(PushQueue)
    (sub,) = await _rows(PushSubscription)
    assert sub.fail_count == 1
    assert len(svc.got) == 2  # de laatste keer niet meer verstuurd


async def test_three_failures_warn_once(authed):
    a, b = Phone(A), Phone(B)
    await _subscribe(authed, a, "Pixel")
    await _subscribe(authed, b, "iPhone")
    svc = PushService([a, b])
    svc.status[A] = 403
    await _notify(*({"title": f"storing {i}", "level": "err"} for i in range(3)))
    await _run(svc)
    pixel = (await _rows(PushSubscription, PushSubscription.label == "Pixel"))[0]
    assert pixel.fail_count == 3 and pixel.warned and pixel.last_error == "HTTP 403: nee"
    warns = await _rows(Notification, Notification.title.like("Meldingen naar Pixel mislukken%"))
    assert len(warns) == 1 and warns[0].title == "Meldingen naar Pixel mislukken: HTTP 403: nee"
    assert not await _rows(PushQueue)  # andere 4xx: niet opnieuw proberen

    await _notify({"title": "storing 4", "level": "err"})
    await _run(svc)
    await _run(svc)
    assert len(await _rows(Notification, Notification.title.like("Meldingen naar Pixel mislukken%"))) == 1
    assert "Meldingen naar Pixel mislukken: HTTP 403: nee" in [m["title"] for m in svc.to(b)]
    status = await _status()
    assert status["devices"] == 2 and status["failing"] == ["Pixel"] and status["last_ok"] is not None

    # Lukt het weer, dan is alles vergeten.
    svc.status[A] = 201
    await _notify({"title": "storing 5", "level": "err"})
    await _run(svc)
    pixel = (await _rows(PushSubscription, PushSubscription.label == "Pixel"))[0]
    assert pixel.fail_count == 0 and not pixel.warned and pixel.last_error is None
    assert (await _status())["failing"] == []


async def _status() -> dict:
    agen, db = await _db()
    out = await webpush.status(db)
    await agen.aclose()
    return out


async def test_at_most_ten_per_minute_with_summary(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel", "warn")
    await _notify(*({"title": f"melding {i}", "level": "warn" if i == 0 else "err"} for i in range(15)))
    await _notify(*({"title": f"info {i}", "level": "info"} for i in range(3)))  # niet voor dit toestel
    svc = PushService([a])
    await _run(svc)
    titles = [m["title"] for m in svc.to(a)]
    assert titles == [f"melding {i}" for i in range(6, 15)] + ["6 meldingen meer in het dashboard"]
    summary = svc.to(a)[-1]
    assert summary["level"] == "err" and summary["tag"] == "meer"
    assert not await _rows(PushQueue)

    # Die minuut zit vol: wat er nu bijkomt, wacht.
    await _notify({"title": "nog één", "level": "err"})
    await _run(svc)
    assert len(svc.got) == 10 and len(await _rows(PushQueue)) == 1
    webpush._sent.clear()  # een minuut later
    agen, db = await _db()
    await db.execute(update(PushQueue).values(next_at=datetime.now(timezone.utc)))
    await db.commit()
    await agen.aclose()
    await _run(svc)
    assert svc.to(a)[-1]["title"] == "nog één" and not await _rows(PushQueue)


async def test_test_button_and_delete(authed, monkeypatch):
    a, b = Phone(A), Phone(B)
    first = await _subscribe(authed, a, "Pixel")
    await _subscribe(authed, b, "iPhone")
    svc = PushService([a, b])
    monkeypatch.setattr(webpush_router, "make_client", svc.client)
    r = await authed.post(f"/api/webpush/subscriptions/{first['id']}/test")
    assert r.json() == {"ok": True, "error": None}
    assert svc.to(a)[0]["title"] == "Testmelding van de homepage"
    svc.status[A] = 400
    r = await authed.post(f"/api/webpush/subscriptions/{first['id']}/test")
    assert r.json() == {"ok": False, "error": "HTTP 400: nee"}
    assert (await authed.get("/api/webpush/subscriptions")).json()[0]["last_error"] == "HTTP 400: nee"

    assert (await authed.delete(f"/api/webpush/subscriptions/{first['id']}")).status_code == 204
    assert [i["label"] for i in (await authed.get("/api/webpush/subscriptions")).json()] == ["iPhone"]
    (off,) = await _rows(Notification, Notification.title == "Meldingen op Pixel uitgezet")
    assert off.level == "warn" and off.source == "auth"
    assert [a.action for a in await _rows(AuditLog, AuditLog.action == "webpush_removed")] == ["webpush_removed"]
    await _run(svc)
    assert [m["title"] for m in svc.to(b)] == ["Meldingen op Pixel uitgezet"]  # iPhone staat op "err", toch gekregen
    assert (await authed.post("/api/webpush/subscriptions/999/test")).status_code == 404


async def test_renew_with_secret(authed):
    a = Phone(A)
    first = await _subscribe(authed, a, "Pixel")
    new = Phone("https://fcm.googleapis.com/fcm/send/nieuw-adres")
    authed.cookies.clear()  # de service worker heeft geen sessie nodig

    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": "fout", "subscription": new.sub()})
    assert r.status_code == 403
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": 999, "renew": first["renew"], "subscription": new.sub()})
    assert r.status_code == 403
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"],
                                                                     "subscription": Phone("https://10.0.0.5/x").sub()})
    assert r.status_code == 422
    # Zonder CSRF-header niet (ook de service worker zet die).
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"], "subscription": new.sub()},
                         headers={"X-Requested-With": ""})
    assert r.status_code == 403
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"], "subscription": new.sub()})
    assert r.status_code == 200 and r.json()["id"] == first["id"] and r.json()["renew"] != first["renew"]
    # Het geheim werkt één keer: een ander adres ermee aanmelden kan niet meer (exact hetzelfde verzoek herhalen wel,
    # zie test_vernieuwen_twee_keer_hetzelfde_verzoek).
    r2 = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"],
                                                                      "subscription": Phone(A + "-ander").sub()})
    assert r2.status_code == 403
    (sub,) = await _rows(PushSubscription)
    data = decrypt_json(sub.data)
    assert data["endpoint"] == new.endpoint and data["p256dh"] == new.sub()["keys"]["p256dh"]
    assert sub.endpoint_hash == webpush.endpoint_hash(new.endpoint)
    (log,) = await _rows(AuditLog, AuditLog.action == "webpush_renewed")
    assert log.user_id is None and log.detail["label"] == "Pixel"

    # Het nieuwe adres krijgt de meldingen.
    await _notify({"title": "na vernieuwen", "level": "err"})
    svc = PushService([a, new])
    await _run(svc)
    assert [m["title"] for m in svc.to(new)] == ["Pushadres van Pixel vernieuwd", "na vernieuwen"] and not svc.to(a)

    # Te veel foute pogingen vanaf één IP: even niets meer, ook niet met het juiste geheim.
    for _ in range(8):
        await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": "fout", "subscription": new.sub()})
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"], "subscription": new.sub()})
    assert r.status_code == 429


async def test_notification_by_id_for_the_deep_link(authed):
    (nid,) = await _notify({"title": "NAS down", "body": "Time-out", "level": "err", "source": "monitor"})
    r = await authed.get(f"/api/notifications/{nid}")
    assert r.status_code == 200 and r.json()["title"] == "NAS down" and r.json()["read"] is False
    assert (await authed.get("/api/notifications/9999")).status_code == 404


async def test_firewall_view_lists_push_hosts(authed, monkeypatch):
    await _subscribe(authed, Phone(A), "Pixel")
    await _subscribe(authed, Phone(B), "iPhone")

    async def fake_resolve(names):
        return {n: {"fcm.googleapis.com": ["142.250.1.10"], "web.push.apple.com": ["17.188.1.1"]}.get(n, []) for n in names}

    monkeypatch.setattr(ports, "nameservers", lambda: [])
    monkeypatch.setattr(ports, "resolve", fake_resolve)
    data = (await authed.get("/api/network/ports")).json()
    rows = {r["ip"]: r for r in data["rows"]}
    assert rows["142.250.1.10"]["ports"] == ["443/tcp"] and rows["142.250.1.10"]["used_by"] == ["web push (Pixel)"]
    assert rows["17.188.1.1"]["names"] == ["web.push.apple.com"] and data["internet"] is True


async def test_long_payload_is_trimmed_to_fit(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    # 1000 tekens van 4 bytes passen niet in één pushbericht van 4096 bytes: de tekst wordt korter.
    await _notify({"title": "é" * 200, "body": "\U0001F600" * 5000, "level": "err"})
    svc = PushService([a])
    await _run(svc)
    (msg,) = svc.to(a)
    assert len(msg["title"]) == 200 and 800 < len(msg["body"]) < 1000
    assert len(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode()) <= webpush.MAX_PLAIN


# --- na het nalezen ----------------------------------------------------------------------------------------------

def test_stuurteken_in_pushadres_geweigerd():
    for bad in ("https://x\x0b.push.apple.com/zz", "https://web.push.apple.com/a\x7fb", "https://web.push.apple.com/a\x01b"):
        assert not webpush.endpoint_ok(bad)


async def test_een_kapot_toestel_houdt_de_andere_niet_tegen(authed):
    a, b = Phone(A), Phone(B)
    await _subscribe(authed, a, "kapot")
    await _subscribe(authed, b, "iPhone")
    agen, db = await _db()
    await db.execute(update(PushSubscription).where(PushSubscription.label == "kapot").values(data="geen-fernet"))
    await db.commit()
    await agen.aclose()
    await _notify({"title": "NAS down", "level": "err"})
    svc = PushService([a, b])
    await _run(svc)
    assert [m["title"] for m in svc.to(b)] == ["NAS down"]
    # De rij van het kapotte toestel wacht even en wordt dan opnieuw geprobeerd, niet vijf minuten vastgehouden.
    (row,) = await _rows(PushQueue)
    assert webpush._aware(row.next_at) - datetime.now(timezone.utc) <= timedelta(seconds=webpush.BACKOFF[0])


async def test_herstel_alleen_als_het_iets_herstelt(authed):
    a = Phone(A)
    await _subscribe(authed, a, "storingen", "err")
    await _notify({"title": "Back-up gelukt", "level": "ok", "source": "webhook"},
                  {"title": "2FA ingeschakeld", "level": "ok", "source": "auth"})
    svc = PushService([a])
    await _run(svc)
    assert svc.to(a) == []


async def test_nieuwer_nieuws_vervangt_een_wachtende_melding(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    agen, db = await _db()
    db.add(Page(name="p", groups=[Group(name="g", services=[Service(name="NAS")])]))
    await db.commit()
    sid = (await db.execute(select(Service.id))).scalar_one()
    await agen.aclose()
    await _notify({"title": "NAS down", "level": "err", "source": "monitor", "service_id": sid, "key": f"svc{sid}"})
    svc = PushService([a])
    svc.down = True
    await _run(svc)  # mislukt: wacht 30 s
    await _notify({"title": "NAS weer bereikbaar", "level": "ok", "source": "monitor", "service_id": sid,
                   "key": f"svc{sid}", "recovers": "err"})
    svc.down = False
    await _run(svc)
    assert [m["title"] for m in svc.to(a)] == ["NAS weer bereikbaar"] and not await _rows(PushQueue)


async def test_samenvatting_mislukt_dan_blijven_ze_wachten(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    await _notify(*({"title": f"m{i}", "level": "err"} for i in range(15)))
    svc = PushService([a])
    svc.down = True
    await _run(svc)
    # Niets aangekomen: alle 15 wachten nog (ook de 6 die in de samenvatting zaten).
    assert len(await _rows(PushQueue)) == 15


async def test_nieuw_wachtwoord_maakt_vernieuwgeheim_ongeldig_en_afgemeld_toestel_kan_terug(authed):
    a, other = Phone(A), Phone("https://fcm.googleapis.com/fcm/send/nieuw")
    first = await _subscribe(authed, a, "Pixel")
    svc = PushService([a])
    svc.status[A] = 410
    await _notify({"title": "NAS down", "level": "err"})
    await _run(svc)
    (sub,) = await _rows(PushSubscription)
    assert sub.gone_at is not None
    # Naar een andere pushdienst mag niet.
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"],
                                                                     "subscription": Phone(B).sub()})
    assert r.status_code == 422
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": first["renew"],
                                                                     "subscription": other.sub()})
    assert r.status_code == 200
    (sub,) = await _rows(PushSubscription)
    assert sub.gone_at is None
    renew = r.json()["renew"]
    from .conftest import PASSWORD
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "een-ander-lang-wachtwoord"})
    assert r.status_code == 200, r.text
    r = await authed.put("/api/webpush/subscriptions/renew", json={"id": first["id"], "renew": renew,
                                                                     "subscription": other.sub()})
    assert r.status_code == 403


async def _due_now():
    """Wat wacht (opnieuw proberen), nu laten gaan, zoals na de wachttijd."""
    agen, db = await _db()
    await db.execute(update(PushQueue).values(next_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    await db.commit()
    await agen.aclose()


async def test_andere_storing_over_dezelfde_tegel_blijft_staan(authed):
    """De cluster meldt alles onder de Proxmox-tegel: een replicatie-waarschuwing mag de wachtende "node weg" niet
    vervangen, en "node terug" komt op een toestel voor storingen ook als er intussen een waarschuwing was."""
    a, b = Phone(A), Phone(B)
    await _subscribe(authed, a, "storingen", "err")
    await _subscribe(authed, b, "waarschuwingen", "warn")
    node, repl = "cluster|c|node:pve2", "cluster|c|repl:100-0"
    await _notify({"title": "Node pve2 is weg", "level": "err", "source": "cluster", "key": node})
    svc = PushService([a, b])
    svc.down = True
    await _run(svc)
    svc.down = False
    await _notify({"title": "Replicatie 100-0 mislukt", "level": "warn", "source": "cluster", "key": repl})
    await _run(svc)
    await _due_now()
    await _run(svc)
    assert [m["title"] for m in svc.to(b)] == ["Replicatie 100-0 mislukt", "Node pve2 is weg"]
    assert [m["title"] for m in svc.to(a)] == ["Node pve2 is weg"]
    await _notify({"title": "Node pve2 is terug", "level": "ok", "source": "cluster", "key": node, "recovers": "err"},
                  {"title": "Replicatie 100-0 lukt weer", "level": "ok", "source": "cluster", "key": repl,
                   "recovers": "warn"})
    await _run(svc)
    assert [m["title"] for m in svc.to(a)] == ["Node pve2 is weg", "Node pve2 is terug"]
    assert [m["title"] for m in svc.to(b)][-2:] == ["Node pve2 is terug", "Replicatie 100-0 lukt weer"]
    tags = {m["title"]: m["tag"] for m in svc.to(b)}
    assert tags["Node pve2 is weg"] == tags["Node pve2 is terug"] != tags["Replicatie 100-0 mislukt"]


async def test_down_en_herstel_in_dezelfde_ronde(authed):
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    await _notify({"title": "NAS down", "level": "err", "source": "monitor", "key": "svc1"},
                  {"title": "Router down", "level": "err", "source": "monitor", "key": "svc2"},
                  {"title": "NAS weer bereikbaar", "level": "ok", "source": "monitor", "key": "svc1", "recovers": "err"})
    svc = PushService([a])
    await _run(svc)
    # Alleen het nieuwste over de NAS: anders kan "down" na "weer bereikbaar" aankomen.
    assert [m["title"] for m in svc.to(a)] == ["Router down", "NAS weer bereikbaar"]
    assert not await _rows(PushQueue)


async def test_samenvatting_mislukt_en_het_herstel_kwam_al(authed):
    """Een vloed met eerst "down" en op het eind "weer bereikbaar": wat na een mislukte samenvatting blijft wachten,
    komt later niet alsnog als "down" na het herstel."""
    a = Phone(A)
    await _subscribe(authed, a, "Pixel")
    await _notify({"title": "NAS is nog altijd down", "level": "err", "source": "monitor", "key": "svc1"},
                  *({"title": f"m{i}", "level": "err"} for i in range(12)))

    class Fails(PushService):
        def handler(self, request):
            r = super().handler(request)
            return httpx.Response(503) if self.got[-1]["msg"]["tag"] == "meer" else r
    svc = Fails([a])
    await _run(svc)
    assert len(svc.to(a)) == 10  # 9 apart en de samenvatting (mislukt)
    await _notify({"title": "NAS weer bereikbaar", "level": "ok", "source": "monitor", "key": "svc1",
                   "recovers": "err"})
    webpush._sent.clear()
    await _due_now()
    await _run(svc)
    titles = [m["title"] for m in svc.to(a)][10:]
    assert "NAS is nog altijd down" not in titles and titles[-1] == "NAS weer bereikbaar"


async def test_afgemeld_alleen_als_het_adres_nog_hetzelfde_is(authed):
    """De browser vernieuwde zijn adres terwijl er nog een bericht naar het oude onderweg was: de 410 daarvan maakt
    het vernieuwde toestel niet "afgemeld"."""
    a = Phone(A)
    first = await _subscribe(authed, a, "Firefox")
    agen, db = await _db()
    (sub,) = (await db.execute(select(PushSubscription))).scalars().all()
    r = await authed.put("/api/webpush/subscriptions/renew", json={
        "id": first["id"], "renew": first["renew"], "subscription": Phone(A + "-nieuw").sub()})
    assert r.status_code == 200
    await webpush._gone(db, sub)
    await db.commit()
    await agen.aclose()
    (sub,) = await _rows(PushSubscription)
    assert sub.gone_at is None
    assert not [n for n in await _rows(Notification) if "krijgt geen meldingen meer" in n.title]


async def test_vernieuwen_twee_keer_hetzelfde_verzoek(authed):
    """Het antwoord ging verloren: de service worker stuurt exact hetzelfde nog eens, en krijgt een geheim dat werkt.
    Een ander adres met dat oude geheim kan niet."""
    a = Phone(A)
    first = await _subscribe(authed, a, "Firefox")
    new = Phone(A + "-nieuw").sub()
    body = {"id": first["id"], "renew": first["renew"], "subscription": new}
    lost = await authed.put("/api/webpush/subscriptions/renew", json=body)
    assert lost.status_code == 200
    again = await authed.put("/api/webpush/subscriptions/renew", json=body)
    assert again.status_code == 200 and again.json()["renew"] != lost.json()["renew"]
    r = await authed.put("/api/webpush/subscriptions/renew", json={**body, "subscription": Phone(A + "-ander").sub()})
    assert r.status_code == 403
    r = await authed.put("/api/webpush/subscriptions/renew", json={**body, "renew": again.json()["renew"],
                                                                    "subscription": Phone(A + "-later").sub()})
    assert r.status_code == 200
    assert (await authed.put("/api/webpush/subscriptions/renew", json=body)).status_code == 403


async def test_vernieuwen_tegelijk_een_wint(authed):
    from fastapi import HTTPException

    from app.routers import webpush as route
    first = await _subscribe(authed, Phone(A), "Firefox")
    agen, db = await _db()
    s = await db.get(PushSubscription, first["id"])
    other, db2 = await _db()
    await db2.execute(update(PushSubscription).values(renew_hash="0" * 64))
    await db2.commit()
    await other.aclose()
    with pytest.raises(HTTPException) as e:
        await route._rotate(db, s, s.renew_hash)
    assert e.value.status_code == 409
    await agen.aclose()


async def test_herstel_na_down_en_dan_problemen(authed):
    """"WAN down", dan "WAN problemen" (alleen voor waarschuwingen), dan "weer online": het herstel komt ook op het
    toestel dat alleen storingen krijgt, anders blijft daar "down" staan."""
    a, b = Phone(A), Phone(B)
    await _subscribe(authed, a, "storingen", "err")
    await _subscribe(authed, b, "waarschuwingen", "warn")
    gw = "gw1:WAN"
    svc = PushService([a, b])
    await _notify({"title": "WAN: down", "level": "err", "source": "netwerk", "key": gw})
    await _run(svc)
    await _notify({"title": "WAN: problemen", "level": "warn", "source": "netwerk", "key": gw})
    await _run(svc)
    await _notify({"title": "WAN is weer online", "level": "ok", "source": "netwerk", "key": gw, "recovers": "warn"})
    await _run(svc)
    assert [m["title"] for m in svc.to(a)] == ["WAN: down", "WAN is weer online"]
    assert [m["title"] for m in svc.to(b)] == ["WAN: down", "WAN: problemen", "WAN is weer online"]
    # Een volgende storing van alleen "problemen" herstelt daarna weer alleen voor waarschuwingen.
    await _notify({"title": "WAN: problemen", "level": "warn", "source": "netwerk", "key": gw})
    await _notify({"title": "WAN is weer online", "level": "ok", "source": "netwerk", "key": gw, "recovers": "warn"})
    await _run(svc)
    assert len(svc.to(a)) == 2
