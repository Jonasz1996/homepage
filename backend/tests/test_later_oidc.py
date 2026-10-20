import base64
import hashlib
import html
import hmac
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import oidc
from app.routers import oidc as oidc_router

ISSUER = "https://auth.jbogaert.be/application/o/homepage/"


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

    def id_token(self) -> str:
        c = {"iss": ISSUER, "aud": "homepage", "exp": time.time() + 300, "iat": time.time(), "nonce": self.nonce,
             "preferred_username": "Jonas", "amr": ["pwd", "mfa"], **self.claims}
        return jwt({k: v for k, v in c.items() if v is not None}, self.token_key, self.token_alg, secret="geheim")

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": "https://auth.jbogaert.be/application/o/authorize/",
                                             "token_endpoint": "https://auth.jbogaert.be/application/o/token/",
                                             "jwks_uri": "https://auth.jbogaert.be/application/o/homepage/jwks/"})
        if p.endswith("/jwks/"):
            return httpx.Response(200, json={"keys": [rsa_jwk(self.key)]})
        if p.endswith("/token/"):
            assert req.headers["authorization"] == "Basic " + base64.b64encode(b"homepage:geheim").decode()
            self.form = parse_qs(req.content.decode())
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
    assert q["redirect_uri"] == ["http://test/api/auth/oidc/callback"]
    prov.nonce = q["nonce"][0]
    return await c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0], **cb})


async def test_oidc_login(authed, provider):
    assert (await authed.get("/api/auth/oidc")).json() == {"enabled": False, "label": "Authentik"}
    r = await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    assert r.status_code == 200, r.text
    assert r.json()["has_secret"] and "client_secret" not in r.json()
    assert (await authed.get("/api/auth/oidc")).json()["enabled"]
    await authed.post("/api/auth/logout")
    assert (await authed.get("/api/auth/state")).json()["user"] is None

    r = await _login(authed, provider)
    assert r.status_code == 200 and 'content="0;url=/"' in r.text
    # PKCE: de verifier hoort bij de challenge.
    assert provider.form["code_verifier"] and provider.form["grant_type"] == ["authorization_code"]
    st = (await authed.get("/api/auth/state")).json()
    assert st["user"]["username"] == "jonas" and st["mfa_ok"]
    audit = (await authed.get("/api/auth/audit", params={"action": "login"})).json()["items"]
    assert audit[0]["detail"]["method"] == "oidc"


@pytest.mark.parametrize("case,expect", [
    ("no_mfa", "geen 2FA"), ("unknown", "Geen gebruiker"), ("bad_sig", "Handtekening"), ("expired", "verlopen"),
    ("aud", "niet voor dit dashboard"), ("state", "verlopen of ongeldig"), ("none_alg", "niet toegelaten"),
])
async def test_oidc_refused(authed, provider, case, expect):
    await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    await authed.post("/api/auth/logout")
    if case == "no_mfa":
        provider.claims = {"amr": ["pwd"]}
    elif case == "unknown":
        provider.claims = {"preferred_username": "mallory"}
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
    assert "login_error" in r.text
    target = html.unescape(r.text.split('content="0;url=')[1].split('"')[0])
    assert expect in parse_qs(urlsplit(target).query)["login_error"][0]
    assert (await authed.get("/api/auth/state")).json()["user"] is None


async def test_oidc_mfa_optional_and_hs256(authed, provider):
    await authed.put("/api/auth/oidc/settings", json={**SETTINGS, "require_mfa": False})
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
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from app.models import Session
    from .test_capacity import _db
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    r = await authed.put("/api/auth/oidc/settings", json=SETTINGS)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await agen.aclose()
