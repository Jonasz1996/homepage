"""Inloggen via Authentik (of een andere OpenID Connect-provider).

Authorization code flow met PKCE, state en nonce. Het ID-token wordt gecontroleerd met de sleutels van de
provider (JWKS, RS256/ES256) of, als Authentik geen signing key heeft, met het client secret (HS256).
Alleen bestaande gebruikers kunnen zo inloggen: de gebruikersnaam bij Authentik moet gelijk zijn aan die
in het dashboard. 2FA gebeurt dan bij Authentik; standaard eist het dashboard dat het ID-token dat ook zegt.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

DISCOVERY_TTL = 600
LEEWAY = 60
# amr-waarden die op een tweede factor wijzen (RFC 8176 en wat Authentik gebruikt).
MFA_AMR = {"mfa", "otp", "totp", "hwk", "swk", "webauthn", "sms", "mca"}


class OidcError(Exception):
    """Fout die we zo aan de gebruiker tonen."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def pkce_pair() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(48))
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


_cache: dict[str, tuple[float, dict]] = {}


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await client.get(url, timeout=8)
    except httpx.HTTPError as e:
        raise OidcError(f"Provider niet bereikbaar ({type(e).__name__})") from e
    if r.status_code != 200:
        raise OidcError(f"Provider antwoordt HTTP {r.status_code} op {url.split('?')[0]}")
    try:
        return r.json()
    except ValueError as e:
        raise OidcError("Provider gaf geen JSON terug") from e


async def discovery(client: httpx.AsyncClient, issuer: str, fresh: bool = False) -> dict:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    hit = _cache.get(url)
    if hit and not fresh and hit[0] > time.monotonic():
        return hit[1]
    data = await _get_json(client, url)
    for k in ("authorization_endpoint", "token_endpoint", "issuer"):
        if not data.get(k):
            raise OidcError(f"Discovery mist {k}")
    _cache[url] = (time.monotonic() + DISCOVERY_TTL, data)
    return data


async def jwks(client: httpx.AsyncClient, url: str, fresh: bool = False) -> list[dict]:
    hit = _cache.get(url)
    if hit and not fresh and hit[0] > time.monotonic():
        return hit[1]["keys"]
    data = await _get_json(client, url)
    _cache[url] = (time.monotonic() + DISCOVERY_TTL, data)
    return data.get("keys") or []


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[jwk["crv"]]
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise OidcError(f"Sleuteltype {jwk.get('kty')} niet ondersteund")


HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


def verify_signature(token: str, keys: list[dict], client_secret: str | None) -> tuple[dict, dict]:
    """Controleert de handtekening en geeft (header, claims). Gooit OidcError als het niet klopt."""
    try:
        h64, p64, s64 = token.split(".")
        header = json.loads(b64url_decode(h64))
        claims = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except (ValueError, json.JSONDecodeError) as e:
        raise OidcError("ID-token is onleesbaar") from e
    alg = str(header.get("alg") or "")
    signed = f"{h64}.{p64}".encode()
    bits = alg[2:]
    if bits not in HASHES or alg[:2] not in ("RS", "ES", "HS"):
        raise OidcError(f"Algoritme {alg or 'none'} niet toegelaten")
    if alg.startswith("HS"):
        if not client_secret:
            raise OidcError("HS-token maar geen client secret ingesteld")
        digest = getattr(hashlib, f"sha{bits}")
        if not hmac.compare_digest(hmac.new(client_secret.encode(), signed, digest).digest(), sig):
            raise OidcError("Handtekening van het ID-token klopt niet")
        return header, claims
    kid = header.get("kid")
    candidates = [k for k in keys if (not kid or k.get("kid") == kid) and k.get("use", "sig") == "sig"]
    if not candidates:
        raise OidcError("Geen passende sleutel bij de provider gevonden")
    for jwk in candidates:
        try:
            key = _public_key(jwk)
            if alg.startswith("RS") and isinstance(key, rsa.RSAPublicKey):
                key.verify(sig, signed, padding.PKCS1v15(), HASHES[bits]())
                return header, claims
            if alg.startswith("ES") and isinstance(key, ec.EllipticCurvePublicKey):
                half = len(sig) // 2
                der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
                key.verify(der, signed, ec.ECDSA(HASHES[bits]()))
                return header, claims
        except (InvalidSignature, KeyError, ValueError):
            continue
    raise OidcError("Handtekening van het ID-token klopt niet")


def check_claims(claims: dict, issuer: str, client_id: str, nonce: str, now: float | None = None) -> None:
    now = now or time.time()
    if claims.get("iss") != issuer:
        raise OidcError("ID-token komt van een andere uitgever")
    aud = claims.get("aud")
    if client_id not in (aud if isinstance(aud, list) else [aud]):
        raise OidcError("ID-token is niet voor dit dashboard bedoeld")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") not in (None, client_id):
        raise OidcError("ID-token is niet voor dit dashboard bedoeld")
    try:
        exp = float(claims["exp"])
    except (KeyError, TypeError, ValueError) as e:
        raise OidcError("ID-token zonder vervaldatum") from e
    if exp < now - LEEWAY:
        raise OidcError("ID-token is verlopen")
    if claims.get("nonce") != nonce:
        raise OidcError("Nonce klopt niet (oude of vervalste login)")


def has_mfa(claims: dict) -> bool:
    amr = claims.get("amr") or []
    return bool(set(amr if isinstance(amr, list) else [amr]) & MFA_AMR)
