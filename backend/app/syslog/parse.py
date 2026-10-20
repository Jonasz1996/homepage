"""Syslog-berichten ontleden: RFC 5424 en het klassieke RFC 3164-formaat (standaard bij rsyslog-forwarding)."""

import re
from dataclasses import dataclass
from datetime import datetime, timezone

MAX_MSG = 8192
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+)\s?(.*)$", re.S)
_3164 = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$", re.S)
_TAG = re.compile(r"^([^\s:\[]{1,64})(?:\[(\d+)\])?:\s?(.*)$", re.S)


@dataclass
class Parsed:
    ts: datetime
    host: str
    facility: int
    severity: int
    app: str | None
    msg: str


def _clean(s: str) -> str:
    # Controletekens (behalve tab) weg, BOM weg; NUL-bytes kan PostgreSQL niet opslaan.
    s = s.lstrip("\ufeff")
    return "".join(c for c in s if c == "\t" or c >= " " or c == "\n").strip()[:MAX_MSG]


def parse(raw: bytes, source_ip: str | None, now: datetime | None = None) -> Parsed:
    now = now or datetime.now(timezone.utc)
    text = raw.decode("utf-8", errors="replace").rstrip("\r\n\x00")
    facility, severity = 1, 5
    m = _PRI.match(text)
    if m:
        pri = min(int(m.group(1)), 191)
        facility, severity = pri >> 3, pri & 7
        text = text[m.end():]

    host, app, ts = source_ip or "onbekend", None, now
    m5 = _5424.match(text)
    if m5:
        stamp, h, a, _pid, _msgid, _sd, msg = m5.groups()
        if stamp != "-":
            try:
                ts = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = now
        host = h if h != "-" else host
        app = a if a != "-" else None
    else:
        m3 = _3164.match(text)
        if m3:
            # Klassieke tijdstempel heeft geen jaar en geen tijdzone: ontvangsttijd is betrouwbaarder.
            _stamp, h, rest = m3.groups()
            host = h
            text = rest
        mt = _TAG.match(text)
        if mt:
            app, _pid, msg = mt.groups()
        else:
            msg = text
    # Te ver in de toekomst (verkeerde klok op de bron)? Dan de ontvangsttijd.
    if abs((ts - now).total_seconds()) > 86400:
        ts = now
    return Parsed(ts=ts, host=_clean(host)[:255] or "onbekend", facility=facility, severity=severity,
                  app=_clean(app)[:64] if app else None, msg=_clean(msg) or "(leeg)")
