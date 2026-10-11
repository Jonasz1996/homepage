"""Geheimen uit tekst halen voor alles wat het dashboard laat zien of laat downloaden: de proefmodus, de diagnose
en de logs van de processen.

Twee lagen:
- bekende waarden: de geheimen die het dashboard zelf bewaart (de diagnose geeft ze mee). Die worden overal
  vervangen, ook url-gecodeerd en als base64 van "gebruiker:wachtwoord".
- patronen: alles wat eruitziet als een token, een sleutel of een wachtwoord in een url, header of key=value,
  ook als het dashboard de waarde zelf niet kent.

Token-ID's en gebruikersnamen blijven leesbaar: "PVEAPIToken=homepage@pve!dashboard=***".
"""

import base64
import re
from collections import Counter
from typing import Iterable
from urllib.parse import quote

MASK = "***"
# Kortere waarden zouden gewone woorden verminken.
MIN_KNOWN = 4

_SECRET_NAME = r"[\w.-]{0,40}(?:passw(?:or)?d|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|psk)[\w.-]{0,40}"

PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("sleutel", re.compile(r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----", re.S),
     r"-----BEGIN \1PRIVATE KEY----- *** -----END \1PRIVATE KEY-----"),
    ("token", re.compile(r"(PVEAPIToken=[^=\s\"',;]+=)[^\s\"',;]+"), r"\1***"),
    ("token", re.compile(r"(PBSAPIToken=[^:\s\"',;]+:)[^\s\"',;]+"), r"\1***"),
    ("header", re.compile(r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie|set-cookie)"
                          r"(\"?'?\s*[:=]\s*\"?'?)(?!\*\*\*)[^\"'\n]+"), r"\1\2***"),
    ("token", re.compile(r"(?i)\b(bearer|basic)\s+(?!\*\*\*)[A-Za-z0-9._~+/=-]{12,}"), r"\1 ***"),
    ("url", re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)([^/\s@:\"']{0,200}):[^/\s@\"']{1,500}@"), r"\1\2:***@"),
    ("url", re.compile(r"(?i)([?&;]" + _SECRET_NAME + r"=)(?!\*\*\*)[^&\s\"'#]+"), r"\1***"),
    ("url", re.compile(r"(?i)([?&;](?:key|auth|sig|signature|session|sid|code)=)(?!\*\*\*)[^&\s\"'#]+"), r"\1***"),
    ("url", re.compile(r"(/api/(?:push|hooks)/)[A-Za-z0-9_-]{16,}"), r"\1***"),
    ("versleuteld", re.compile(r"gAAAAA[A-Za-z0-9_=-]{20,}"), MASK),
    ("token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), MASK),
    ("sessie", re.compile(r"(hp_session=)[^;\s\"']+"), r"\1***"),
    ("waarde", re.compile(r"(?i)\b(?!(?:PVE|PBS)APIToken=)(" + _SECRET_NAME + r")"
                          r"(\"?'?\s*[:=]\s*\"?'?)(?!\*\*\*)[^\s\"',;&}]+"), r"\1\2***"),
]


def variants(values: Iterable[str]) -> list[str]:
    """De bekende geheimen plus hun url-gecodeerde vorm, langste eerst."""
    out: set[str] = set()
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if len(v) < MIN_KNOWN:
            continue
        out.add(v)
        q = quote(v, safe="")
        if q != v:
            out.add(q)
    return sorted(out, key=len, reverse=True)


def basic(user: str | None, password: str | None) -> str | None:
    """Base64 van "gebruiker:wachtwoord", zoals in een Authorization: Basic-header."""
    if not user or not password:
        return None
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def mask(text: str, known: Iterable[str] = (), counts: Counter | None = None) -> str:
    if not text:
        return text
    for v in known:
        if v in text:
            if counts is not None:
                counts["bekend"] += text.count(v)
            text = text.replace(v, MASK)
    for kind, rx, repl in PATTERNS:
        text, n = rx.subn(repl, text)
        if n and counts is not None:
            counts[kind] += n
    return text


def mask_tree(obj, known: Iterable[str] = (), counts: Counter | None = None):
    """Maskeert elke tekst in een structuur van dicts en lijsten (sleutels ook), voor die naar JSON gaat."""
    known = list(known)
    if isinstance(obj, str):
        return mask(obj, known, counts)
    if isinstance(obj, dict):
        return {mask(str(k), known, counts) if isinstance(k, str) else k: mask_tree(v, known, counts)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_tree(v, known, counts) for v in obj]
    return obj
