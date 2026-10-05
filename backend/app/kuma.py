"""Uptime Kuma vervangen door het dashboard: de monitors van Kuma ophalen (via /metrics), vergelijken met de tegels en
checks van het dashboard, en wat nog ontbreekt als tegel met een check voorstellen.

De API-sleutel van Kuma wordt nergens bewaard: hij is alleen nodig voor deze ene vergelijking.
"""

import re
from urllib.parse import urlsplit

import httpx

from .integrations import IntegrationError
from .monitoring.checks import target_for

LINE = re.compile(r"^(\w+)\{(.*)\}\s+(\S+)")
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
STATUS = {"1": "up", "0": "down", "2": "pending", "3": "onderhoud"}
HTTP = {"http", "keyword", "json-query", "real-browser", "grpc-keyword"}
PING = {"ping", "tailscale-ping"}
SKIP = {"docker": "container: volg die via Portainer (containerlogs, image-updates)",
        "push": "push-monitor: Kuma wacht op een signaal; gebruik cron → bewaken of een webhook",
        "group": None}


def _val(v: str | None) -> str | None:
    return None if v in (None, "", "null", "undefined") else v


def parse(text: str) -> list[dict]:
    """De monitors uit de Prometheus-uitvoer van Kuma (monitor_status, met naam, type, url, host en poort)."""
    out = {}
    for line in text.splitlines():
        m = LINE.match(line.strip())
        if not m or m.group(1) != "monitor_status":
            continue
        labels = {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in LABEL.findall(m.group(2))}
        name = labels.get("monitor_name")
        if not name:
            continue
        out[name] = {"name": name, "type": labels.get("monitor_type") or "?", "url": _val(labels.get("monitor_url")),
                     "host": _val(labels.get("monitor_hostname")), "port": _val(labels.get("monitor_port")),
                     "status": STATUS.get(m.group(3).split(".")[0], "?")}
    return sorted(out.values(), key=lambda x: x["name"].lower())


async def fetch(url: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    base = url.strip().rstrip("/")
    if not base.lower().startswith(("http://", "https://")):
        raise IntegrationError("Adres van Uptime Kuma als http://192.168.0.20:3001")
    try:
        r = await client.get(base + "/metrics", auth=("", api_key), timeout=15)
    except httpx.HTTPError as e:
        raise IntegrationError(f"Uptime Kuma niet bereikbaar: {e or type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise IntegrationError("Uptime Kuma weigert de API-sleutel (Instellingen → API-sleutels)")
    if r.status_code != 200 or "monitor_status" not in r.text:
        raise IntegrationError(f"Geen monitors gevonden op {base}/metrics (HTTP {r.status_code})")
    return parse(r.text)


def proposal(m: dict) -> tuple[dict | None, str | None]:
    """De tegel en check die deze monitor vervangen, of waarom niet."""
    kind = m["type"]
    if kind in SKIP:
        return None, SKIP[kind]
    if kind in HTTP and m["url"]:
        why = "trefwoord of JSON-query: zet die zelf op de check" if kind in ("keyword", "json-query") else None
        return {"name": m["name"], "url": m["url"], "check": {"type": "http", "interval": 60}}, why
    host = m["host"] or (urlsplit(m["url"]).hostname if m["url"] else None)
    if not host:
        return None, "geen adres in Kuma"
    if kind in PING:
        return {"name": m["name"], "url": f"http://{host}", "check": {"type": "ping", "target": host, "interval": 60}}, None
    if kind == "dns":
        return {"name": m["name"], "url": f"http://{host}", "check": {"type": "dns", "target": host, "interval": 300}}, None
    if m["port"] and m["port"].isdigit():
        why = None if kind == "port" else f"{kind}: het dashboard kijkt alleen of de poort open is"
        return {"name": m["name"], "url": f"http://{host}:{m['port']}",
                "check": {"type": "tcp", "target": f"{host}:{m['port']}", "interval": 60}}, why
    return None, f"type {kind} zonder poort"


def _keys(url: str | None, check: dict | None) -> set[str]:
    """Waarmee een tegel te herkennen is: host en host:poort van de url en van het checkdoel."""
    out = set()
    for u in (url, target_for(check or {}, url) if (check or {}).get("type") else None):
        if not u:
            continue
        p = urlsplit(u if "://" in u else f"x://{u}")
        if p.hostname:
            out.add(p.hostname.lower())
            if p.port:
                out.add(f"{p.hostname.lower()}:{p.port}")
    return out


def compare(monitors: list[dict], services: list) -> list[dict]:
    """Per monitor: gedekt (tegel met check), zonder-check (tegel maar geen check), ontbreekt, of niet-overnemen."""
    by_key: dict[str, object] = {}
    by_name: dict[str, object] = {}
    for s in services:
        by_name.setdefault(s.name.strip().lower(), s)
        for k in _keys(s.url, s.check):
            by_key.setdefault(k, s)
    rows = []
    for m in monitors:
        prop, why = proposal(m)
        keys = _keys(prop["url"], prop["check"]) if prop else _keys(m["url"], None) | ({m["host"].lower()} if m["host"] else set())
        # Met een poort telt alleen dezelfde host én poort (een andere dienst op dezelfde machine is iets anders).
        port_key = next((k for k in keys if ":" in k), None)
        svc = (by_key.get(port_key) if port_key else next((by_key[k] for k in keys if k in by_key), None)) \
            or by_name.get(m["name"].strip().lower())
        if m["type"] == "group":
            continue
        if svc is not None:
            state = "gedekt" if (svc.check or {}).get("type") else "zonder-check"
        else:
            state = "ontbreekt" if prop else "niet-overnemen"
        rows.append({**m, "state": state, "why": why, "proposal": prop,
                     "service": {"id": svc.id, "name": svc.name} if svc is not None else None})
    return rows
