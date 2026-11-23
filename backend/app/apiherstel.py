"""API's terugzetten uit een back-up (na een fabrieksreset of een nieuwe installatie).

Een back-up is een pg_dump (-Fc): de dagelijkse in /var/backups/homepage (die blijft staan bij een fabrieksreset) of
de volledige back-up die je vlak voor de reset downloadde. pg_restore haalt er alleen de tabellen api_connections en
api_calls uit (als COPY-tekst, zonder een database aan te raken); die worden hier ingelezen en als nieuwe API's
toegevoegd, met hun eigen calls.

- Een API met dezelfde soort en hetzelfde adres als een die er al is, slaat het over (dus twee keer drukken kan).
- De sleutels blijven versleuteld zoals in de back-up. Dat werkt met dezelfde /etc/homepage/secret.key (een
  fabrieksreset laat die staan). Kan deze homepage ze niet lezen (een back-up van een andere installatie), dan komt
  de API zonder sleutels: plak die dan opnieuw.
- Tegels worden niet aan de API's gekoppeld: die komen uit ClusterForge of je import. Wat hier terugkomt is wat je
  anders opnieuw moet plakken.
"""

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .integrations import REGISTRY
from .models import ApiCall, ApiConnection
from .security import decrypt_json

TIMEOUT = 300
TABLES = ("api_connections", "api_calls")
_COPY = re.compile(r"^COPY (?:\"?[\w]+\"?\.)?\"?(\w+)\"? \((.*)\) FROM stdin;$")
_ESC = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\"}
CONN_COLS = ("name", "category", "kind", "template", "url", "config", "secrets")
CALL_COLS = ("name", "method", "path", "query", "headers", "body", "show", "fields", "table", "confirm", "position")


class HerstelFout(Exception):
    pass


def pg_restore_exe() -> str | None:
    found = shutil.which("pg_restore")
    if found:
        return found
    versions = sorted(Path("/usr/lib/postgresql").glob("*/bin/pg_restore"), key=lambda p: p.parent.parent.name)
    return str(versions[-1]) if versions else None


def _unescape(v: str) -> str | None:
    """Eén veld uit COPY-tekst: \\N is NULL, backslash-codes worden tekens."""
    if v == "\\N":
        return None
    if "\\" not in v:
        return v
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c != "\\" or i + 1 >= len(v):
            out.append(c)
            i += 1
            continue
        n = v[i + 1]
        if n in _ESC:
            out.append(_ESC[n])
            i += 2
        elif n in "01234567":
            j = i + 1
            while j < len(v) and j < i + 4 and v[j] in "01234567":
                j += 1
            out.append(chr(int(v[i + 1:j], 8)))
            i = j
        elif n == "x":
            j = i + 2
            while j < len(v) and j < i + 4 and v[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(chr(int(v[i + 2:j], 16)) if j > i + 2 else "x")
            i = j
        else:
            out.append(n)
            i += 2
    return "".join(out)


def parse_copy(sql: str) -> dict[str, list[dict]]:
    """{tabel: [rij als dict]} uit de uitvoer van pg_restore -f - (alleen de COPY-blokken)."""
    tables: dict[str, list[dict]] = {}
    lines = iter(sql.splitlines())
    for line in lines:
        m = _COPY.match(line)
        if not m:
            continue
        name = m.group(1)
        cols = [c.strip().strip('"') for c in m.group(2).split(",")]
        rows = tables.setdefault(name, [])
        for row in lines:
            if row == "\\.":
                break
            vals = row.split("\t")
            if len(vals) == len(cols):
                rows.append({c: _unescape(v) for c, v in zip(cols, vals, strict=True)})
    return tables


async def read_dump(path: Path) -> dict[str, list[dict]]:
    exe = pg_restore_exe()
    if not exe:
        raise HerstelFout("pg_restore staat niet op deze container")
    args = [exe, "--data-only", "--no-owner", "-f", "-"]
    for t in TABLES:
        args += ["-t", t]
    args.append(str(path))
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as e:
        raise HerstelFout(f"pg_restore start niet: {type(e).__name__}") from e
    try:
        out, err = await asyncio.wait_for(proc.communicate(), TIMEOUT)
    except (TimeoutError, asyncio.CancelledError):
        proc.kill()
        raise
    if proc.returncode != 0:
        text = err.decode(errors="replace").strip()
        raise HerstelFout("Dit is geen back-up van de homepage (pg_restore: " + (text.splitlines() or ["?"])[-1][:200] + ")")
    tables = parse_copy(out.decode("utf-8", errors="replace"))
    if "api_connections" not in tables:
        raise HerstelFout("Geen API's in deze back-up")
    return tables


def _json(v: str | None, default: Any) -> Any:
    if v is None:
        return default
    try:
        return json.loads(v)
    except ValueError:
        return default


def _secrets_ok(secrets: str | None) -> bool:
    if not secrets:
        return True
    try:
        decrypt_json(secrets)
        return True
    except Exception:  # noqa: BLE001 - een andere secret.key: niet te lezen, dan zonder sleutels
        return False


def _key(kind: str | None, url: str | None) -> tuple[str, str]:
    return (str(kind or "").lower(), str(url or "").strip().rstrip("/").lower())


async def restore(db: AsyncSession, tables: dict[str, list[dict]]) -> dict:
    """Voegt de API's uit de back-up toe. Geeft terug wat er kwam, wat al bestond en wat zonder sleutels kwam."""
    have = {_key(a.kind, a.url) for a in (await db.execute(select(ApiConnection))).scalars().all()}
    calls_by: dict[str, list[dict]] = {}
    for c in tables.get("api_calls") or []:
        calls_by.setdefault(str(c.get("connection_id")), []).append(c)
    added, skipped, no_keys = [], [], []
    for row in tables.get("api_connections") or []:
        kind = row.get("kind") or "rest"
        if kind not in REGISTRY and kind != "rest":
            skipped.append(f"{row.get('name')} (soort {kind} onbekend)")
            continue
        k = _key(kind, row.get("url"))
        if not row.get("url") or k in have:
            skipped.append(str(row.get("name")))
            continue
        have.add(k)
        secrets = row.get("secrets")
        if not _secrets_ok(secrets):
            secrets = None
            no_keys.append(str(row.get("name")))
        a = ApiConnection(name=str(row.get("name") or kind)[:80], category=str(row.get("category") or "overig")[:40],
                          kind=kind, template=row.get("template"), url=str(row.get("url"))[:500],
                          config=_json(row.get("config"), {}) or {}, secrets=secrets)
        for i, c in enumerate(sorted(calls_by.get(str(row.get("id")), []),
                                     key=lambda c: (int(c.get("position") or 0), int(c.get("id") or 0)))):
            a.calls.append(ApiCall(
                name=str(c.get("name") or "call")[:80], method=str(c.get("method") or "GET")[:8],
                path=str(c.get("path") or "")[:500], query=_json(c.get("query"), {}) or {},
                headers=_json(c.get("headers"), {}) or {}, body=c.get("body"), show=str(c.get("show") or "tile")[:8],
                fields=_json(c.get("fields"), []) or [], table=_json(c.get("table"), {}) or {},
                confirm=str(c.get("confirm") or "t").lower() in ("t", "true", "1"), position=i))
        db.add(a)
        added.append(a.name)
    await db.flush()
    return {"added": added, "skipped": skipped, "no_keys": no_keys}
