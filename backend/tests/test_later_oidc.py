import base64
import hashlib
import html
import hmac
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pyotp
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select, update

from app import oidc
from app.models import AuditLog, Notification, User
from app.routers import oidc as oidc_router

from .conftest import PASSWORD
from .test_capacity import _db

ISSUER = "https://auth.jbogaert.be/application/o/homepage/"
# Subject mode "Based on the User's hashed ID" in Authentik: een vaste hash, los van naam en e-mail.
SUB = hashlib.sha256(b"authentik-gebruiker-jonas").hexdigest()


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(claims: dict, key=None, alg="RS256", kid="k1", secret=None) -> str:
    h = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    p = b64(json.dumps(claims).encode())
    msg = f"{h}.{p}".encode()
    if alg == "HS256":
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    elif alg == "ES256":
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64(sig)}"


def rsa_jwk(key, kid="k1") -> dict:
    n = key.public_key().public_numbers()
    to = lambda i: b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))  # noqa: E731
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": to(n.n), "e": to(n.e)}


class Provider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = None
        self.claims = {}
        self.token_alg = "RS256"
        self.token_key = self.key
        self.form = None
        # Een ander antwoord van het token-endpoint (bv. de HTML-pagina van een proxy).
        self.token_response = None
        # Wat Authentik als issuer meldt (in de discovery en in elk ID-token).
        self.issuer = ISSUER

    def id_token(self) -> str:
        c = {"iss": self.issuer, "sub": SUB, "aud": "homepage", "exp": time.time() + 300, "iat": time.time(),
             "nonce": self.nonce, "preferred_username": "Jonas", "email": "jonas@jbogaert.be", "amr": ["pwd", "mfa"],
             **self.claims}
        return jwt({k: v for k, v in c.items() if v is not None}, self.token_key, self.token_alg, secret="geheim")

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": self.issuer, "authorization_endpoint": "https://auth.jbogaert.be/application/o/authorize/",
                                             "token_endpoint": "https://auth.jbogaert.be/application/o/token/",
                                             "jwks_uri": "https://auth.jbogaert.be/application/o/homepage/jwks/"})
        if p.endswith("/jwks/"):
            return httpx.Response(200, json={"keys": [rsa_jwk(self.key)]})
        if p.endswith("/token/"):
            assert req.headers["authorization"] == "Basic " + base64.b64encode(b"homepage:geheim").decode()
            self.form = parse_qs(req.content.decode())
            if self.token_response is not None:
                return self.token_response
            return httpx.Response(200, json={"access_token": "x", "id_token": self.id_token()})
        return httpx.Response(404)


@pytest.fixture
def provider(monkeypatch):
    prov = Provider()
    c = httpx.AsyncClient(transport=httpx.MockTransport(prov))
    monkeypatch.setattr(oidc_router, "_clients", {False: c, True: c})
    oidc._cache.clear()
    return prov


SETTINGS = {"enabled": True, "issuer": ISSUER, "client_id": "homepage", "client_secret": "geheim", "label": "Authentik"}


async def _login(c, prov, **cb):
    r = await c.get("/api/auth/oidc/start")
    assert r.status_code == 303, r.text
    loc = urlsplit(r.headers["location"])
    q = parse_qs(loc.query)
    assert loc.path == "/application/o/authorize/" and q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == ["http://test/api/auth/oidc/callback"] and "prompt" not in q
    prov.nonce = q["nonce"][0]
    return await c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0], **cb})


async def _link(c, prov, **cb):
    """Koppelen zoals de knop in ⚿ → authentik: POST /link geeft het adres bij Authentik, dan de terugkeer."""
    r = await c.post("/api/auth/oidc/link")
    assert r.status_code == 200, r.text
    q = parse_qs(urlsplit(r.json()["url"]).query)
    assert q["redirect_uri"] == ["http://test/api/auth/oidc/callback"] and q["code_challenge_method"] == ["S256"]
    # Koppelen laat Authentik opnieuw vragen wie je bent: niet stil het account dat toevallig ingelogd is.
    assert q["prompt"] == ["login"]
    prov.nonce = q["nonce"][0]
    return await c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0], **cb})


def _target(r) -> tuple[str, dict]:
    """Waar de pagina na de terugkeer naartoe stuurt: (pad, query)."""
    t = urlsplit(html.unescape(r.text.split('content="0;url=')[1].split('"')[0]))
    return t.path, {k: v[0] for k, v in parse_qs(t.query).items()}


async def _password_login(c):
    r = await c.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                               "code": pyotp.TOTP(c.totp_secret).now()})
    assert r.status_code == 200 and r.json()["mfa_ok"], r.text


async def _stale(c):
    """De laatste 2FA-bevestiging is te oud (zoals een uur later)."""
    from datetime import datetime, timedelta, timezone

    from app.models import Session
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()


async def _audit(action: str) -> list[AuditLog]:
    agen, db = await _db()
    rows = list((await db.execute(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id))).scalars())
    await agen.aclose()
    return rows


async def _jonas() -> User:
    agen, db = await _db()
    user = (await db.execute(select(User).where(User.username == "jonas"))).scalar_one()
    await agen.aclose()
    return user


async def test_oidc_login(authed, provider):
    assert (await authed.get("/api/auth/oidc")).json() == {"enabled": False, "label": "Authentik"}
    r = await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    assert r.status_code == 200, r.text
    assert r.json()["has_secret"] and "client_secret" not in r.json()
    assert r.json()["linked"] is False
    assert (await authed.get("/api/auth/oidc")).json()["enabled"]

    # Eén keer koppelen, ingelogd met wachtwoord en 2FA: de terugkeer bewaart de sub en logt niet opnieuw in.
    sessions = len((await authed.get("/api/auth/sessions")).json())
    r = await _link(authed, provider)
    assert _target(r) == ("/", {"open": "security", "tab": "sso"}), r.text
    st = (await authed.get("/api/auth/oidc/settings")).json()
    assert st["linked"] and st["linked_name"] == "Jonas" and st["linked_issuer"] == ISSUER
    assert SUB not in json.dumps(st)  # de sub zelf gaat niet naar de browser
    assert len((await authed.get("/api/auth/sessions")).json()) == sessions
    user = await _jonas()
    assert (user.oidc_sub, user.oidc_issuer, user.oidc_name) == (SUB, ISSUER, "Jonas")
    linked = await _audit("oidc_linked")
    assert len(linked) == 1 and linked[0].user_id == user.id and linked[0].detail["name"] == "Jonas"
    agen, db = await _db()
    note = (await db.execute(select(Notification).where(Notification.title == "Authentik-account gekoppeld"))) \
        .scalar_one()
    assert note.level == "warn" and note.source == "auth" and "Jonas" in note.body
    await agen.aclose()

    await authed.post("/api/auth/logout")
    assert (await authed.get("/api/auth/state")).json()["user"] is None
    r = await _login(authed, provider)
    assert r.status_code == 200 and 'content="0;url=/"' in r.text
    # Een login via Authentik maakt dit een bekend toestel (zie test_beveiliging.py §4b).
    assert "hp_device=" in r.headers.get("set-cookie", "")
    # PKCE: de verifier hoort bij de challenge.
    assert provider.form["code_verifier"] and provider.form["grant_type"] == ["authorization_code"]
    st = (await authed.get("/api/auth/state")).json()
    assert st["user"]["username"] == "jonas" and st["mfa_ok"]
    audit = (await authed.get("/api/auth/audit", params={"action": "login"})).json()["items"]
    assert audit[0]["detail"]["method"] == "oidc"


async def test_oidc_niet_gekoppeld(authed, provider):
    """Na de update: nog niets gekoppeld, dus inloggen via Authentik gaat niet, met uitleg. De checklist zegt het."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    assert rows["authentik"]["state"] == "half" and "nog geen Authentik-account gekoppeld" in rows["authentik"]["text"]
    assert rows["authentik"]["fix"] == {"window": "security", "tab": "sso"}

    await authed.post("/api/auth/logout")
    r = await _login(authed, provider)
    assert _target(r) == ("/", {"login_error": oidc_router.NOT_LINKED})
    assert oidc_router.NOT_LINKED == ("Dit Authentik-account is nog niet gekoppeld: log in met wachtwoord en 2FA en "
                                      "koppel het onder ⚿ → authentik")
    assert (await authed.get("/api/auth/state")).json()["user"] is None
    failed = await _audit("login_failed_oidc")
    assert failed[-1].detail["username"] == "Jonas" and failed[-1].detail["sub"] == SUB and failed[-1].user_id is None

    # Wachtwoord en 2FA werken gewoon; na het koppelen staat de checklist in orde.
    await _password_login(authed)
    await _link(authed, provider)
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    assert rows["authentik"]["state"] == "ok"


@pytest.mark.parametrize("name", ["Jonas", "jonas", "JONAS"])
async def test_oidc_zelfde_naam_andere_sub(authed, provider, name):
    """Een ander Authentik-account met dezelfde naam (of een hoofdlettervariant) komt er niet in."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    await authed.post("/api/auth/logout")
    provider.claims = {"sub": hashlib.sha256(b"mallory").hexdigest(), "preferred_username": name,
                       "email": "mallory@example.com"}
    r = await _login(authed, provider)
    assert _target(r)[1]["login_error"] == oidc_router.NOT_LINKED
    assert (await authed.get("/api/auth/state")).json()["user"] is None
    assert (await _audit("login_failed_oidc"))[-1].detail["sub"] == provider.claims["sub"]
    assert (await _jonas()).oidc_sub == SUB


async def test_oidc_naam_gewijzigd(authed, provider):
    """Dezelfde sub met een andere naam bij Authentik: dat is hetzelfde account."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    await authed.post("/api/auth/logout")
    provider.claims = {"preferred_username": "jonas-nieuw"}
    r = await _login(authed, provider)
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"], r.text
    assert (await authed.get("/api/auth/oidc/settings")).json()["linked_name"] == "jonas-nieuw"


async def test_oidc_andere_uitgever(authed, provider):
    """Een sub geldt alleen bij de uitgever waar ze vandaan kwam."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    agen, db = await _db()
    await db.execute(update(User).values(oidc_issuer="https://auth.elders.be/application/o/homepage/"))
    await db.commit()
    await agen.aclose()
    await authed.post("/api/auth/logout")
    r = await _login(authed, provider)
    assert _target(r)[1]["login_error"] == oidc_router.NOT_LINKED



async def _authentik_row(c) -> dict:
    groups = (await c.get("/api/attention/setup")).json()["groups"]
    return next(x for g in groups for x in g["rows"] if x["key"] == "authentik")


async def test_oidc_issuer_veranderd(authed, provider):
    """Een andere issuer (een andere slug of hostnaam bij Authentik): inloggen zoekt op de issuer van nu, dus de oude
    koppeling telt niet meer als gekoppeld, en de checklist zegt dat je opnieuw moet koppelen."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    s = (await authed.get("/api/auth/oidc/settings")).json()
    assert (s["linked"], s["link_stale"]) == (True, False)
    assert (await _authentik_row(authed))["state"] == "ok"

    new = "https://auth.jbogaert.be/application/o/dashboard/"
    provider.issuer = new
    oidc._cache.clear()
    r = await authed.put("/api/auth/oidc/settings", json={**SETTINGS, "issuer": new})
    assert r.status_code == 200, r.text
    assert (r.json()["linked"], r.json()["link_stale"]) == (False, True)
    row = await _authentik_row(authed)
    assert row["state"] == "half" and "andere issuer" in row["text"]

    # Opnieuw koppelen: weer in orde, en inloggen werkt.
    await _link(authed, provider)
    s = (await authed.get("/api/auth/oidc/settings")).json()
    assert (s["linked"], s["link_stale"]) == (True, False)
    assert (await _authentik_row(authed))["state"] == "ok"
    await authed.post("/api/auth/logout")
    await _login(authed, provider)
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"]


async def test_oidc_naam_uit_claim_sub(authed, provider):
    """Staat "naam tonen uit claim" op sub, dan is een sub met de hashed ID nog altijd geen naam: koppelen lukt."""
    assert oidc.subject_is_name({"sub": SUB, "preferred_username": "Jonas"}, "sub") is False
    assert oidc.subject_is_name({"sub": "jonas", "preferred_username": "Jonas"}, "sub") is True
    await authed.put("/api/auth/oidc/settings", json={**SETTINGS, "username_claim": "sub"})
    r = await _link(authed, provider)
    assert "oidc_error" not in _target(r)[1]
    assert (await authed.get("/api/auth/oidc/settings")).json()["linked"] is True

@pytest.mark.parametrize("case,expect", [
    ("no_mfa", "geen 2FA"), ("unknown", "nog niet gekoppeld"), ("bad_sig", "Handtekening"), ("expired", "verlopen"),
    ("aud", "niet voor dit dashboard"), ("state", "verlopen of ongeldig"), ("none_alg", "niet toegelaten"),
    ("no_sub", "zonder sub"), ("empty_sub", "zonder sub"), ("not_json", "geen JSON"),
    ("json_list", "geen JSON-object"), ("no_id_token", "Geen ID-token"),
])
async def test_oidc_refused(authed, provider, case, expect):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    await authed.post("/api/auth/logout")
    if case == "no_mfa":
        provider.claims = {"amr": ["pwd"]}
    elif case == "unknown":
        provider.claims = {"sub": "iemand-anders", "preferred_username": "mallory"}
    elif case == "no_sub":
        provider.claims = {"sub": None}
    elif case == "empty_sub":
        provider.claims = {"sub": ""}
    elif case == "not_json":
        # Een proxy ertussen die een HTML-pagina geeft, met status 200.
        provider.token_response = httpx.Response(200, text="<html>Even geduld</html>")
    elif case == "json_list":
        provider.token_response = httpx.Response(200, json=["id_token"])
    elif case == "no_id_token":
        provider.token_response = httpx.Response(200, json={"access_token": "x", "id_token": 5})
    elif case == "bad_sig":
        provider.token_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif case == "expired":
        provider.claims = {"exp": time.time() - 3600}
    elif case == "aud":
        provider.claims = {"aud": "iets-anders"}
    elif case == "none_alg":
        provider.token_alg = "none"
        provider.id_token = lambda: b64(b'{"alg":"none"}') + "." + b64(json.dumps({"iss": ISSUER}).encode()) + "."
    if case == "state":
        await authed.get("/api/auth/oidc/start")
        r = await authed.get("/api/auth/oidc/callback", params={"code": "abc", "state": "vervalst"})
    else:
        r = await _login(authed, provider)
    assert r.status_code == 200 and "login_error" in r.text
    assert expect in _target(r)[1]["login_error"]
    assert (await authed.get("/api/auth/state")).json()["user"] is None


async def test_oidc_mfa_optional_and_hs256(authed, provider):
    await authed.put("/api/auth/oidc/settings", json={**SETTINGS, "require_mfa": False})
    await _link(authed, provider)
    await authed.post("/api/auth/logout")
    provider.claims = {"amr": None}
    provider.token_alg = "HS256"  # Authentik zonder signing key tekent met het client secret
    r = await _login(authed, provider)
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"], r.text


def test_es256_signature():
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "e1", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
    token = jwt({"a": 1}, key, "ES256", kid="e1")
    assert oidc.verify_signature(token, [jwk], None)[1] == {"a": 1}
    with pytest.raises(oidc.OidcError):
        oidc.verify_signature(token[:-4] + "AAAA", [jwk], None)


async def test_oidc_settings_need_recent_2fa(authed, provider):
    await _stale(authed)
    r = await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"


# --- koppelen ----------------------------------------------------------------------------------------------------

async def test_oidc_link_needs_recent_2fa_and_a_session(authed, provider):
    # Zolang Authentik uit staat, valt er niets te koppelen.
    r = await authed.post("/api/auth/oidc/link")
    assert r.status_code == 400 and "eerst aan" in r.json()["detail"]
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _stale(authed)
    r = await authed.post("/api/auth/oidc/link")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert "hp_oidc" not in r.headers.get("set-cookie", "")
    # Een POST zonder de eigen header (een ander domein) komt er niet door.
    r = await authed.post("/api/auth/oidc/link", headers={"X-Requested-With": ""})
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]
    await authed.post("/api/auth/logout")
    assert (await authed.post("/api/auth/oidc/link")).status_code == 401
    assert (await authed.delete("/api/auth/oidc/link")).status_code == 401


@pytest.mark.parametrize("claims", [
    {"sub": "Jonas"},  # Subject mode: op gebruikersnaam
    {"sub": "jonas@jbogaert.be"},  # op e-mailadres
    {"sub": "JONAS@jbogaert.be", "email": "jonas@jbogaert.be"},
])
async def test_oidc_link_refuses_name_as_sub(authed, provider, claims):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    provider.claims = claims
    r = await _link(authed, provider)
    path, q = _target(r)
    assert (path, q["open"], q["tab"]) == ("/", "security", "sso")
    assert "Subject mode" in q["oidc_error"] and "Based on the User's hashed ID" in q["oidc_error"]
    assert (await authed.get("/api/auth/oidc/settings")).json()["linked"] is False
    failed = await _audit("oidc_link_failed")
    assert len(failed) == 1 and failed[0].user_id == (await _jonas()).id
    assert not await _audit("oidc_linked")
    # Nog steeds ingelogd: koppelen raakt de sessie niet.
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"]


async def test_oidc_link_refused_without_sub_or_mfa(authed, provider):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    provider.claims = {"sub": None}
    assert "zonder sub" in _target(await _link(authed, provider))[1]["oidc_error"]
    provider.claims = {"amr": ["pwd"]}
    assert "geen 2FA" in _target(await _link(authed, provider))[1]["oidc_error"]
    assert (await _jonas()).oidc_sub is None and len(await _audit("oidc_link_failed")) == 2


async def test_oidc_link_after_logout(authed, provider):
    """De koppeling hoort bij de sessie die ze startte: wie intussen afmeldde, koppelt niets."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    r = await authed.post("/api/auth/oidc/link")
    q = parse_qs(urlsplit(r.json()["url"]).query)
    provider.nonce = q["nonce"][0]
    await authed.post("/api/auth/logout")
    r = await authed.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})
    assert "afgemeld" in _target(r)[1]["login_error"]
    assert (await _jonas()).oidc_sub is None
    assert (await _audit("oidc_link_failed"))[-1].detail["reason"].startswith("Koppelen mislukt")
    assert (await authed.get("/api/auth/state")).json()["user"] is None


async def test_oidc_login_flow_never_links(authed, provider):
    """Een gewone login via Authentik (GET /start) koppelt niets, ook niet als je al ingelogd bent."""
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    r = await _login(authed, provider)
    assert _target(r)[1]["login_error"] == oidc_router.NOT_LINKED
    assert (await _jonas()).oidc_sub is None and not await _audit("oidc_linked")


async def test_oidc_link_expired_state(authed, provider):
    from app.security import decrypt, encrypt
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    r = await authed.post("/api/auth/oidc/link")
    q = parse_qs(urlsplit(r.json()["url"]).query)
    provider.nonce = q["nonce"][0]
    # Elf minuten later teruggekomen: het state-cookie is te oud.
    saved = json.loads(decrypt(authed.cookies["hp_oidc"]))
    assert saved["m"] == "link" and saved["sid"] and saved["u"] == (await _jonas()).id
    authed.cookies.set("hp_oidc", encrypt(json.dumps({**saved, "t": saved["t"] - oidc_router.STATE_TTL - 60})),
                       domain="test.local", path="/api/auth/oidc")
    assert [c.name for c in authed.cookies.jar].count("hp_oidc") == 1
    r = await authed.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})
    assert _target(r)[1]["oidc_error"] == "Koppelen verlopen of ongeldig, probeer opnieuw"
    assert (await _jonas()).oidc_sub is None


async def test_oidc_link_taken_by_other_user(authed, provider):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    agen, db = await _db()
    db.add(User(username="oud", password_hash="x", oidc_issuer=ISSUER, oidc_sub=SUB))
    await db.commit()
    await agen.aclose()
    r = await _link(authed, provider)
    assert _target(r)[1]["oidc_error"] == "Dit Authentik-account is al gekoppeld aan oud"
    assert (await _jonas()).oidc_sub is None


async def test_oidc_unlink(authed, provider):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await _link(authed, provider)
    await _stale(authed)
    r = await authed.delete("/api/auth/oidc/link")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await _jonas()).oidc_sub == SUB

    r = await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 200, r.text
    r = await authed.delete("/api/auth/oidc/link")
    assert r.status_code == 200 and r.json()["linked"] is False and r.json()["linked_name"] == ""
    user = await _jonas()
    assert (user.oidc_sub, user.oidc_issuer, user.oidc_name) == (None, None, None)
    unlinked = await _audit("oidc_unlinked")
    assert len(unlinked) == 1 and unlinked[0].detail == {"name": "Jonas", "sub": SUB}
    titles = [i["title"] for i in (await authed.get("/api/timeline")).json()["items"]]
    assert "Authentik-account ontkoppeld" in titles

    await authed.post("/api/auth/logout")
    r = await _login(authed, provider)
    assert _target(r)[1]["login_error"] == oidc_router.NOT_LINKED
    assert (await authed.get("/api/auth/state")).json()["user"] is None


async def test_oidc_no_transaction_during_provider_calls(authed, provider, monkeypatch):
    """Koppelen en inloggen praten met Authentik zonder een databasetransactie open te houden."""
    from .test_verbindingen import _idle_in_transaction
    seen = []

    async def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.path, await _idle_in_transaction()))
        return provider(req)
    c = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(oidc_router, "_clients", {False: c, True: c})
    # Ook bewaren: dat vraagt de discovery opnieuw op.
    oidc._cache.clear()
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    assert [p for p, _ in seen] == ["/application/o/homepage/.well-known/openid-configuration"]
    assert all(idle == 0 for _, idle in seen), seen
    oidc._cache.clear()
    seen.clear()
    await _link(authed, provider)
    await authed.post("/api/auth/logout")
    oidc._cache.clear()
    await _login(authed, provider)
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"]
    paths = [p for p, _ in seen]
    assert paths.count("/application/o/token/") == 2 and any(p.endswith("openid-configuration") for p in paths)
    assert all(idle == 0 for _, idle in seen), seen
