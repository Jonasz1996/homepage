"""Eigen API-calls uit API-beheer: uitvoeren, waarden uit het antwoord halen en tonen.

Een call is een dict zoals ApiCall (zie models.py):
  {"id", "name", "method", "path", "query", "headers", "body", "show": tile|detail|action,
   "fields": [{"label", "path", "format", "suffix", "warn", "err", "equals"}],
   "table": {"path", "columns": [{"label", "path", "format"}]}, "confirm"}

Een pad in het antwoord is met punten: "queue.speed", "records.0.title". Een * loopt over een lijst:
"records.*.size" met format "sum" telt alles op, "data.*.health" met format "count" en equals "down" telt de
targets die down zijn.
"""

import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .base import Integration, IntegrationError, cell, field

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
FORMATS = ("auto", "number", "percent", "bytes", "duration", "date", "count", "sum", "avg", "min", "max", "bool", "text")
MAX_TILE_FIELDS = 8
MAX_ROWS = 50
_VAR = re.compile(r"\{(\w+)\}")
_MISSING = object()


def call_dict(c) -> dict:
    """ApiCall (model) → dict, zodat de integratie niets met de database te maken heeft."""
    return {"id": c.id, "name": c.name, "method": c.method, "path": c.path, "query": c.query or {},
            "headers": c.headers or {}, "body": c.body, "show": c.show, "fields": c.fields or [],
            "table": c.table or {}, "confirm": c.confirm}


def render(text: str, values: dict, encode: bool = False) -> str:
    """{variabele} vervangen door een instelling van de tegel of API (bv. {node}). In een pad url-gecodeerd."""
    def sub(m: re.Match) -> str:
        v = values.get(m.group(1))
        if v is None or isinstance(v, (dict, list)):
            raise IntegrationError(f"Variabele {{{m.group(1)}}} ontbreekt: zet \"{m.group(1)}\" in de instellingen van de tegel")
        return quote(str(v), safe="") if encode else str(v)
    return _VAR.sub(sub, text)


def check_path(path: str) -> str:
    """Een pad blijft altijd op de API zelf: "@andere.host/..." of "//..." zou anders een ander adres worden."""
    path = (path or "").strip()
    if path and not path.startswith(("/", "?")):
        raise IntegrationError("Een pad begint met / (bv. /api/v3/queue)")
    if "://" in path or path.startswith("//") or "\\" in path or any(ord(ch) < 33 for ch in path):
        raise IntegrationError("Ongeldig pad")
    return path


async def run(integ: Integration, call: dict) -> Any:
    """Voert één call uit en geeft het antwoord terug (JSON, of tekst)."""
    method = str(call.get("method") or "GET").upper()
    if method not in METHODS:
        raise IntegrationError("Onbekende methode")
    values = {k: v for k, v in integ.config.items() if isinstance(v, (str, int, float, bool))}
    path = check_path(render(call.get("path") or "", values, encode=True))
    kw = await (integ.call_auth() if method == "GET" else integ.write_auth())
    headers = {**(kw.pop("headers", None) or {})}
    for k, v in (call.get("headers") or {}).items():
        headers.setdefault(str(k), render(str(v), values))  # de aanmelding van de API gaat voor
    params = {**(kw.pop("params", None) or {}), **{str(k): render(str(v), values) for k, v in (call.get("query") or {}).items()}}
    body = call.get("body")
    if body and method != "GET":
        text = render(body, values)
        try:
            kw["json"] = json.loads(text)
        except ValueError:
            kw["content"] = text.encode()
    r = await integ._send(method, integ.call_prefix + path, headers=headers, params=params or None, **kw)
    if not r.content:
        return None
    try:
        return r.json()
    except ValueError:
        return r.text[:20000]


def pick(data: Any, path: str) -> Any:
    """Waarde op een pad; met * een lijst van waarden."""
    if path in (None, "", "."):
        return data
    parts = str(path).split(".")
    for i, part in enumerate(parts):
        if part == "*":
            items = data if isinstance(data, list) else list(data.values()) if isinstance(data, dict) else []
            rest = ".".join(parts[i + 1:])
            out = []
            for it in items:
                v = pick(it, rest) if rest else it
                out.extend(v if isinstance(v, list) and "*" in rest else [v])
            return out
        if isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(part)
        else:
            return None
    return data


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip().rstrip("%"))
        except ValueError:
            return None
    return None


def _duration(s: float) -> str:
    s = int(s)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    return f"{d}d {h}u" if d else f"{h}u {m}m" if h else f"{m}m {s % 60}s"


def _date(v: Any) -> str:
    try:
        if isinstance(v, (int, float)):
            ts = datetime.fromtimestamp(v / 1000 if v > 1e11 else v, timezone.utc)
        else:
            ts = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return str(v)
    diff = time.time() - ts.timestamp()
    if abs(diff) < 86400 * 2:
        return ("over " if diff < 0 else "") + _duration(abs(diff)) + ("" if diff < 0 else " geleden")
    return ts.astimezone().strftime("%d/%m/%Y")


def value(data: Any, f: dict) -> tuple[Any, float | None]:
    """(tekst voor op het scherm, getal voor de drempels) voor één veld."""
    raw = pick(data, f.get("path") or "")
    fmt = f.get("format") or "auto"
    if isinstance(raw, list) and fmt in ("count", "sum", "avg", "min", "max"):
        if fmt == "count":
            if f.get("equals") not in (None, ""):
                want = str(f["equals"]).lower()
                n = sum(1 for x in raw if str(x).lower() == want)
            else:
                n = sum(1 for x in raw if x not in (None, False, "", [], {}))
            return n, n
        nums = [x for x in (_num(x) for x in raw) if x is not None]
        if not nums:
            return "—", None
        n = {"sum": sum(nums), "avg": sum(nums) / len(nums), "min": min(nums), "max": max(nums)}[fmt]
        raw = n
    elif fmt == "count":
        n = len(raw) if isinstance(raw, (list, dict)) else (_num(raw) or 0)
        return int(n), n
    elif isinstance(raw, list) and "*" in str(f.get("path") or "") and fmt in ("auto", "number", "bytes", "duration", "percent"):
        # Over alle items (records.*.size) als getal: opgeteld.
        nums = [x for x in (_num(x) for x in raw) if x is not None]
        raw = sum(nums) if nums else None
    if raw is None:
        return "—", None
    num = _num(raw)
    suffix = str(f.get("suffix") or "")
    if fmt == "bool":
        on = raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "on", "yes", "ja", "ok", "up", "enabled")
        return ("ja" if on else "nee"), float(on)
    # Bytes en duur als {"bytes"}/{"uptime"}: de browser toont ze zoals bij de ingebouwde integraties.
    if fmt == "bytes" and num is not None:
        return {"bytes": num}, num
    if fmt == "duration" and num is not None:
        return {"uptime": num}, num
    if fmt == "date":
        return _date(raw), None
    if fmt == "percent" and num is not None:
        return f"{num:.0f}%", num
    if fmt == "text" or isinstance(raw, str):
        return (str(raw)[:80] + suffix), num
    if isinstance(raw, (dict, list)):
        return (f"{len(raw)} items" if isinstance(raw, list) else "…"), None
    if isinstance(raw, bool):
        return ("ja" if raw else "nee"), float(raw)
    if num is not None:
        shown = int(num) if num == int(num) else round(num, 2)
        return (f"{shown}{suffix}" if suffix else shown), num
    return str(raw), None


def level(num: float | None, f: dict) -> str | None:
    """Drempels: warn en err. Is warn groter dan err, dan is lager slechter (bv. vrije ruimte)."""
    warn, err = _num(f.get("warn")), _num(f.get("err"))
    if num is None or (warn is None and err is None):
        return None
    lower_worse = warn is not None and err is not None and warn > err
    def past(limit: float | None) -> bool:
        return limit is not None and (num <= limit if lower_worse else num >= limit)
    return "err" if past(err) else "warn" if past(warn) else "ok"


def fields_of(data: Any, call: dict) -> list[dict]:
    out = []
    for f in call.get("fields") or []:
        shown, num = value(data, f)
        out.append(field(str(f.get("label") or f.get("path") or "?")[:30], shown, level(num, f)))
    return out


def table_of(data: Any, call: dict) -> dict | None:
    t = call.get("table") or {}
    cols = [c for c in t.get("columns") or [] if isinstance(c, dict)]
    rows = pick(data, t.get("path") or "")
    if not cols or not isinstance(rows, (list, dict)):
        return None
    rows = rows if isinstance(rows, list) else list(rows.values())
    out = []
    for r in rows[:MAX_ROWS]:
        cells = []
        for c in cols:
            shown, num = value(r, c)
            cells.append(cell(shown, level(num, c)))
        out.append(cells)
    return {"kind": "table", "title": call.get("name") or "tabel", "columns": [str(c.get("label") or c.get("path")) for c in cols],
            "rows": out, "more": max(0, len(rows) - MAX_ROWS)}


async def tile_fields(integ: Integration) -> list[dict]:
    """Velden van de calls die op de tegel staan. Een fout bij één call kost alleen die velden."""
    out = []
    for c in integ.calls:
        if c["show"] != "tile" or not c["fields"]:
            continue
        try:
            out += fields_of(await run(integ, c), c)
        except IntegrationError as e:
            out.append({**field(c["name"][:30], "fout", "err"), "title": str(e)})
        if len(out) >= MAX_TILE_FIELDS:
            break
    return out[:MAX_TILE_FIELDS]


async def sections(integ: Integration) -> list[dict]:
    """Secties voor het mini dashboard: per call de velden, een tabel of het ruwe antwoord, en de actieknoppen."""
    out = []
    actions = []
    for c in integ.calls:
        if c["show"] == "action":
            actions.append({"id": f"call:{c['id']}", "label": c["name"], "confirm": bool(c["confirm"]),
                            "danger": c["method"] == "DELETE"})
            continue
        try:
            data = await run(integ, c)
        except IntegrationError as e:
            out.append({"kind": "kv", "title": c["name"], "items": [field("fout", str(e), "err")]})
            continue
        if c["fields"]:
            out.append({"kind": "kv", "title": c["name"], "items": fields_of(data, c)})
        tbl = table_of(data, c)
        if tbl:
            out.append(tbl)
        if not c["fields"] and not tbl:
            text = data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False)
            out.append({"kind": "code", "title": c["name"], "text": text[:8000]})
    if actions:
        out.append({"kind": "kv", "title": "eigen acties", "items": [], "actions": actions})
    return out


async def action(integ: Integration, action_id: str) -> str:
    try:
        cid = int(action_id.removeprefix("call:"))
    except ValueError as e:
        raise IntegrationError("Onbekende actie") from e
    c = next((c for c in integ.calls if c["id"] == cid and c["show"] == "action"), None)
    if c is None:
        raise IntegrationError("Onbekende actie")
    await run(integ, c)
    return f"{c['name']} uitgevoerd"
