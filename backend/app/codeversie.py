"""Draait dit proces de code die op schijf staat? Na een nieuwe bouw zonder herstart (bv. `homepage-ctl.sh bouwen` op
een ClusterForge-node) praat de nieuwe frontend met de oude API of worker: nieuwe knoppen geven dan 404 en fixes in de
backend zijn niet actief. Daarom houdt elk proces bij het starten een vingerafdruk van zijn Python-code bij (aantal
bestanden en laatste wijziging onder app/), en vergelijkt het die met wat nu op schijf staat."""

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path

APP = Path(__file__).resolve().parent
_CACHE: dict[str, float | str] = {}


def fingerprint() -> str:
    try:
        files = [p.stat() for p in APP.rglob("*.py")]
    except OSError:
        return "?"
    raw = f"{len(files)}:{max((s.st_mtime_ns for s in files), default=0)}:{sum(s.st_size for s in files)}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


STARTED = fingerprint()
STARTED_AT = datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def on_disk() -> str:
    """De vingerafdruk van nu (hoogstens elke 30 s opnieuw berekend)."""
    now = time.monotonic()
    if now - float(_CACHE.get("at", 0)) > 30:
        _CACHE.update(at=now, fp=fingerprint())
    return str(_CACHE["fp"])


def api_stale() -> bool:
    return on_disk() not in (STARTED, "?")


def worker_stale(heartbeat: dict | None) -> bool:
    code = (heartbeat or {}).get("code")
    return bool(code) and on_disk() not in (code, "?")
