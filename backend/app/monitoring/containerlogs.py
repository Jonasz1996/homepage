"""Containerlogs uit Portainer in de logviewer: elke 30 s de nieuwe regels van elke draaiende container ophalen
en als logregel opslaan (host = containernaam, app = "docker"). Zo werken zoeken, filters, live meekijken en de
meldingsregels er net zoals bij syslog.

Uit te zetten per Portainer-tegel met de instelling logs = false.
"""

import logging
import re
import time
from datetime import datetime, timezone

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..integrations import IntegrationError, build
from ..models import AppState, LogEntry, LogRule, Service
from ..syslog.parse import Parsed, _clean
from ..syslog.server import Rules
from .checks import HttpClients

log = logging.getLogger("homepage.containerlogs")

STATE_KEY = "containerlogs"
EVERY = 30
TAIL = 500
FIRST_SPAN = 300
APP = "docker"
_rules = Rules()

# Ernst uit de regel zelf halen: de meeste containers loggen "ERROR", "level=warn", "[WRN]" en dergelijke.
_LEVELS = (
    (2, re.compile(r"\b(fatal|panic|crit(ical)?|emerg(ency)?)\b|\[(FTL|CRT)\]", re.I)),
    (3, re.compile(r"\b(error|err|exception|traceback)\b|\[(ERR|ERROR)\]|level=error", re.I)),
    (4, re.compile(r"\b(warn|warning)\b|\[(WRN|WARN)\]|level=warn", re.I)),
    (7, re.compile(r"\b(debug|trace)\b|\[(DBG|TRC)\]|level=debug", re.I)),
)


def severity(msg: str, stderr: bool) -> int:
    head = msg[:200]
    for sev, rx in _LEVELS:
        if rx.search(head):
            return sev
    return 5 if stderr else 6


def frames(raw: bytes) -> list[tuple[bool, str]]:
    """Docker-logstroom ontleden: zonder TTY gemultiplexed (8 bytes kop per stuk: stroom, 0, 0, 0, lengte),
    met TTY gewone tekst. Geeft (stderr, regel) terug."""
    out: list[tuple[bool, str]] = []
    if len(raw) >= 8 and raw[0] in (0, 1, 2) and raw[1:4] == b"\0\0\0":
        i, chunks = 0, {False: b"", True: b""}
        while i + 8 <= len(raw):
            size = int.from_bytes(raw[i + 4:i + 8], "big")
            chunks[raw[i] == 2] += raw[i + 8:i + 8 + size]
            for err in (False, True):  # per stroom op regels splitsen, onvolledige regel bewaren
                *lines, chunks[err] = chunks[err].split(b"\n")
                out.extend((err, ln.decode("utf-8", "replace")) for ln in lines)
            i += 8 + size
        out.extend((err, c.decode("utf-8", "replace")) for err, c in chunks.items() if c)
    else:
        out = [(False, ln) for ln in raw.decode("utf-8", "replace").split("\n")]
    return [(err, ln.rstrip("\r")) for err, ln in out if ln.strip()]


def stamp(line: str) -> tuple[float | None, str]:
    """'2026-10-05T10:00:00.123456789Z bericht' -> (epoch, bericht)."""
    ts, _, msg = line.partition(" ")
    try:
        whole, _, frac = ts.rstrip("Z").partition(".")
        d = datetime.fromisoformat(whole).replace(tzinfo=timezone.utc)
        return d.timestamp() + float("0." + (frac[:9] or "0")), msg
    except ValueError:
        return None, line


async def _container(px, env: int, cid: str, name: str, since: float, rows: list, notes: list) -> float:
    r = await px._send("GET", f"/api/endpoints/{env}/docker/containers/{cid}/logs?stdout=1&stderr=1"
                              f"&timestamps=1&since={since:.6f}&tail={TAIL}", headers=px.headers())
    newest = since
    for err, line in frames(r.content):
        ts, msg = stamp(line)
        if ts is not None and ts <= since:  # since is inclusief: de laatste regel van vorige keer niet opnieuw
            continue
        ts = ts or time.time()
        newest = max(newest, ts)
        msg = _clean(msg)
        if not msg:
            continue
        p = Parsed(ts=datetime.fromtimestamp(ts, timezone.utc), host=name[:255], facility=1,
                   severity=severity(msg, err), app=APP, msg=msg)
        rows.append({"ts": p.ts, "host": p.host, "source_ip": None, "facility": 1, "severity": p.severity,
                     "app": APP, "msg": msg})
        notes.extend(_rules.match(p))
    return newest


async def run_containerlogs(db: AsyncSession, http: HttpClients) -> dict:
    st = await db.get(AppState, STATE_KEY)
    prev = dict(st.value) if st else {}
    cursors: dict = dict(prev.get("cursors") or {})
    errors: dict = {}
    services = list((await db.execute(select(Service).where(Service.type == "portainer").order_by(Service.id))).scalars())
    if time.monotonic() - _rules.loaded > 30:
        _rules.set(list((await db.execute(select(LogRule).where(LogRule.enabled))).scalars()))
    await db.close()  # geen databaseverbinding vasthouden terwijl Portainer antwoordt
    rows: list = []
    notes: list = []
    now = time.time()
    seen = set()
    for svc in services:
        if str((svc.config or {}).get("logs", "")).strip().lower() in ("false", "0", "nee", "uit", "no"):
            continue
        try:
            px = build(svc, http)
            for e in await px.envs():
                if e.get("Status") != 1:
                    continue
                for c in await px.containers(e["Id"]):
                    key = f"{svc.id}/{e['Id']}/{c.get('Id', '')[:12]}"
                    running = c.get("State") == "running"
                    if not running and key not in cursors:
                        continue
                    name = (c.get("Names") or ["/?"])[0].lstrip("/")
                    since = float(cursors.get(key) or now - FIRST_SPAN)
                    try:
                        newest = await _container(px, e["Id"], c["Id"], name, since, rows, notes)
                    except IntegrationError as err:
                        errors[name] = str(err)
                        continue
                    if running:
                        cursors[key] = newest
                        seen.add(key)
        except IntegrationError as err:
            errors[svc.name] = str(err)
            # Bij een storing de cursors van deze tegel houden, anders ontbreken er straks regels.
            seen.update(k for k in cursors if k.startswith(f"{svc.id}/"))
    cursors = {k: v for k, v in cursors.items() if k in seen}
    if rows:
        await db.execute(insert(LogEntry), rows)
    db.add_all(notes)
    st = await db.get(AppState, STATE_KEY)
    value = {"at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "cursors": cursors,
             "errors": errors, "lines": len(rows)}
    if st:
        st.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value

