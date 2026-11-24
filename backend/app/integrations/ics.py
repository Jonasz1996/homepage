"""Agenda uit een ICS-feed (iCalendar), zoals de agenda van agenda.jbogaert.be, Nextcloud of Google Agenda.

Zoals homepage.dev: het dashboard haalt de feed af en toe op (standaard elke 15 minuten, niet bij elke verversing
van de tegels) en toont de komende afspraken. Herhalingen (RRULE met DAILY, WEEKLY, MONTHLY, YEARLY, INTERVAL,
COUNT, UNTIL, BYDAY, BYMONTHDAY, BYMONTH), uitzonderingen (EXDATE), verplaatste afspraken (RECURRENCE-ID) en
geannuleerde afspraken (STATUS:CANCELLED) worden meegenomen; tijdzones via TZID.

config: {"url": "https://agenda.jbogaert.be/ics", "days": 14, "refresh": 15, "tz": "Europe/Brussels", "insecure": false}
secrets (optioneel): {"token": "..."} als Bearer, of {"username": "...", "password": "..."} als basic auth.
Een sleutel in de url zelf (?token=...) blijft gewoon staan.
"""

import calendar
import hashlib
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .base import Integration, IntegrationError, cell, field

DEFAULT_TZ = "Europe/Brussels"
DEFAULT_DAYS = 14
DEFAULT_REFRESH = 15  # minuten
MAX_BYTES = 5_000_000
MAX_EVENTS = 5000  # VEVENTs in één feed
MAX_STEPS = 20000  # herhalingen doorlopen per afspraak
STALE_MAX = 24 * 3600  # een oude kopie tonen als de feed even weg is, tot een dag oud

DAYS_NL = ("ma", "di", "wo", "do", "vr", "za", "zo")
WEEKDAYS = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}

# feed-url -> (opgehaald op (monotonic), opgehaald op (epoch), tekst)
_FEEDS: dict[str, tuple[float, float, str]] = {}


# --- ICS lezen ---------------------------------------------------------------------------------------------------

@dataclass
class Prop:
    name: str
    params: dict[str, str]
    value: str


def _unfold(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and out:
            out[-1] += raw[1:]
        elif raw.strip():
            out.append(raw)
    return out


def _split_line(line: str) -> Prop | None:
    # NAME;PARAM=a;PARAM2="b:c":waarde  (een : binnen aanhalingstekens hoort bij de parameter)
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == ":" and not quoted:
            head, value = line[:i], line[i + 1:]
            break
    else:
        return None
    parts = re.findall(r'(?:[^;"]|"[^"]*")+', head)
    if not parts:
        return None
    params = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        params[k.strip().upper()] = v.strip().strip('"')
    return Prop(parts[0].strip().upper(), params, value)


def parse(text: str) -> list[dict[str, list[Prop]]]:
    """Alle VEVENTs als {NAAM: [Prop, ...]}. Geneste blokken (VALARM) worden overgeslagen."""
    events: list[dict[str, list[Prop]]] = []
    stack: list[str] = []
    cur: dict[str, list[Prop]] | None = None
    for line in _unfold(text):
        p = _split_line(line)
        if p is None:
            continue
        if p.name == "BEGIN":
            stack.append(p.value.strip().upper())
            if stack == ["VCALENDAR", "VEVENT"] or stack == ["VEVENT"]:
                cur = {}
            continue
        if p.name == "END":
            if stack:
                block = stack.pop()
                if block == "VEVENT" and cur is not None:
                    events.append(cur)
                    cur = None
                    if len(events) >= MAX_EVENTS:
                        break
            continue
        if cur is not None and stack and stack[-1] == "VEVENT":
            cur.setdefault(p.name, []).append(p)
    return events


def unescape(v: str) -> str:
    return re.sub(r"\\([\\;,nN])", lambda m: "\n" if m.group(1) in "nN" else m.group(1), v)


def _zone(name: str | None, default: ZoneInfo) -> ZoneInfo:
    if not name:
        return default
    name = name.strip().strip("/")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        # Outlook schrijft Windows-namen ("Romance Standard Time"): dan de eigen tijdzone.
        return default


def parse_dt(p: Prop, tz: ZoneInfo) -> tuple[datetime, bool]:
    """(tijdstip met tijdzone, hele dag?) uit DTSTART, DTEND, EXDATE of RECURRENCE-ID."""
    v = p.value.strip().split(",")[0]
    if p.params.get("VALUE", "").upper() == "DATE" or re.fullmatch(r"\d{8}", v):
        d = datetime.strptime(v[:8], "%Y%m%d")
        return d.replace(tzinfo=tz), True
    m = re.fullmatch(r"(\d{8})T(\d{4})(\d{2})?(Z?)", v)
    if not m:
        raise ValueError(f"onbekende datum {v!r}")
    d = datetime.strptime(m.group(1) + m.group(2) + (m.group(3) or "00"), "%Y%m%d%H%M%S")
    if m.group(4):
        return d.replace(tzinfo=timezone.utc), False
    return d.replace(tzinfo=_zone(p.params.get("TZID"), tz)), False


def _all_values(props: list[Prop], tz: ZoneInfo) -> list[tuple[datetime, bool]]:
    out = []
    for p in props:
        for v in p.value.split(","):
            if v.strip():
                try:
                    out.append(parse_dt(Prop(p.name, p.params, v), tz))
                except ValueError:
                    pass
    return out


_DUR = re.compile(r"([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def parse_duration(v: str) -> timedelta | None:
    m = _DUR.fullmatch(v.strip())
    if not m:
        return None
    w, d, h, mi, s = (int(x or 0) for x in m.groups()[1:])
    td = timedelta(weeks=w, days=d, hours=h, minutes=mi, seconds=s)
    return -td if m.group(1) == "-" else td


# --- herhalingen -------------------------------------------------------------------------------------------------

def _rule(v: str) -> dict[str, str]:
    return {k.upper(): val for k, _, val in (x.partition("=") for x in v.split(";")) if k}


def _byday(v: str) -> list[tuple[int | None, int]]:
    out = []
    for x in v.split(","):
        m = re.fullmatch(r"([+-]?\d{1,2})?(MO|TU|WE|TH|FR|SA|SU)", x.strip().upper())
        if m:
            out.append((int(m.group(1)) if m.group(1) else None, WEEKDAYS[m.group(2)]))
    return out


def _ints(v: str | None) -> list[int]:
    out = []
    for x in (v or "").split(","):
        try:
            out.append(int(x))
        except ValueError:
            pass
    return out


def _month_days(year: int, month: int, rule: dict, start: date) -> list[int]:
    """De dagen van een maand die bij de regel horen (MONTHLY en YEARLY)."""
    last = calendar.monthrange(year, month)[1]
    days: set[int] = set()
    by_md = _ints(rule.get("BYMONTHDAY"))
    by_day = _byday(rule.get("BYDAY", ""))
    if by_md:
        for d in by_md:
            d = d if d > 0 else last + 1 + d
            if 1 <= d <= last:
                days.add(d)
    if by_day:
        hits: set[int] = set()
        for n, wd in by_day:
            same = [d for d in range(1, last + 1) if date(year, month, d).weekday() == wd]
            if n is None:
                hits.update(same)
            elif 1 <= abs(n) <= len(same):
                hits.add(same[n - 1] if n > 0 else same[n])
        days = days & hits if by_md else hits
    if not by_md and not by_day and start.day <= last:
        days.add(start.day)
    return sorted(days)


def _candidates(start: datetime, rule: dict):
    """Alle tijdstippen (in de wandklok van de start) volgens de regel, oplopend, vanaf de start."""
    freq = rule.get("FREQ", "").upper()
    interval = max(1, _ints(rule.get("INTERVAL"))[0] if _ints(rule.get("INTERVAL")) else 1)
    wall = start.replace(tzinfo=None)
    t = wall.time()
    d0 = wall.date()
    months = _ints(rule.get("BYMONTH"))
    if freq == "DAILY":
        days = {wd for _, wd in _byday(rule.get("BYDAY", ""))}
        k = 0
        while k < MAX_STEPS:
            d = d0 + timedelta(days=k * interval)
            if (not days or d.weekday() in days) and (not months or d.month in months):
                yield datetime.combine(d, t)
            k += 1
    elif freq == "WEEKLY":
        days = sorted({wd for _, wd in _byday(rule.get("BYDAY", ""))}) or [d0.weekday()]
        week0 = d0 - timedelta(days=d0.weekday())  # WKST=MO
        k = 0
        while k < MAX_STEPS:
            w = week0 + timedelta(weeks=k * interval)
            for wd in days:
                d = w + timedelta(days=wd)
                if d >= d0 and (not months or d.month in months):
                    yield datetime.combine(d, t)
            k += 1
    elif freq == "MONTHLY":
        k = 0
        while k < MAX_STEPS:
            y, m = divmod(d0.month - 1 + k * interval, 12)
            y, m = d0.year + y, m + 1
            if not months or m in months:
                for dd in _month_days(y, m, rule, d0):
                    d = date(y, m, dd)
                    if d >= d0:
                        yield datetime.combine(d, t)
            k += 1
    elif freq == "YEARLY":
        k = 0
        while k < MAX_STEPS:
            y = d0.year + k * interval
            for m in sorted(months) or [d0.month]:
                for dd in _month_days(y, m, rule, d0):
                    d = date(y, m, dd)
                    if d >= d0:
                        yield datetime.combine(d, t)
            k += 1
    # andere (SECONDLY, MINUTELY, HOURLY): geen herhaling, alleen de start


def _starts(s0: datetime, rule: dict):
    """Het begin (telt altijd als eerste keer, ook als het niet bij de regel past) en daarna de regel."""
    yield s0
    for wall in _candidates(s0, rule):
        s = wall.replace(tzinfo=s0.tzinfo)
        if s != s0:
            yield s


@dataclass
class Occurrence:
    start: datetime
    end: datetime
    all_day: bool
    summary: str
    location: str
    description: str
    uid: str


def _text(ev: dict, name: str) -> str:
    return unescape(ev[name][0].value).strip() if ev.get(name) else ""


def _key(dt: datetime, all_day: bool) -> Any:
    """Vergelijkt EXDATE en RECURRENCE-ID met een herhaling: op dag of op het precieze moment."""
    return dt.date() if all_day else dt.timestamp()


def expand(events: list[dict[str, list[Prop]]], start: datetime, end: datetime, tz: ZoneInfo) -> list[Occurrence]:
    """Alle afspraken die (deels) tussen start en end vallen, gesorteerd op begin."""
    out: list[Occurrence] = []
    # Verplaatste of aangepaste herhalingen: (uid, moment) -> vervangen
    moved: set[tuple[str, Any]] = set()
    for ev in events:
        if ev.get("RECURRENCE-ID") and ev.get("UID"):
            try:
                rid, ad = parse_dt(ev["RECURRENCE-ID"][0], tz)
            except ValueError:
                continue
            moved.add((_text(ev, "UID"), _key(rid, ad)))
    for ev in events:
        if not ev.get("DTSTART"):
            continue
        if _text(ev, "STATUS").upper() == "CANCELLED":
            continue
        try:
            s0, all_day = parse_dt(ev["DTSTART"][0], tz)
        except ValueError:
            continue
        dur: timedelta | None = None
        if ev.get("DTEND"):
            try:
                dur = parse_dt(ev["DTEND"][0], tz)[0] - s0
            except ValueError:
                dur = None
        elif ev.get("DURATION"):
            dur = parse_duration(ev["DURATION"][0].value)
        if dur is None or dur < timedelta(0):
            dur = timedelta(days=1) if all_day else timedelta(0)
        uid = _text(ev, "UID")
        base = dict(summary=_text(ev, "SUMMARY") or "(zonder titel)", location=_text(ev, "LOCATION"),
                    description=_text(ev, "DESCRIPTION"), uid=uid)
        is_override = bool(ev.get("RECURRENCE-ID"))
        rrule = None if is_override or not ev.get("RRULE") else _rule(ev["RRULE"][0].value)

        def add(s: datetime) -> None:
            if s < end and s + max(dur, timedelta(seconds=1)) > start:
                out.append(Occurrence(s, s + dur, all_day, **base))

        if not rrule or not rrule.get("FREQ"):
            add(s0)
            continue
        skip = {_key(dt, ad) for dt, ad in _all_values(ev.get("EXDATE", []), tz)}
        count = _ints(rrule.get("COUNT"))
        count_left = count[0] if count else None
        until = None
        if rrule.get("UNTIL"):
            try:
                until, until_day = parse_dt(Prop("UNTIL", {}, rrule["UNTIL"]), tz)
                if until_day:
                    until = until + timedelta(days=1) - timedelta(seconds=1)
            except ValueError:
                until = None
        for steps, s in enumerate(_starts(s0, rrule)):
            if steps >= MAX_STEPS or s >= end or (until is not None and s > until):
                break
            if count_left is not None:
                if count_left <= 0:
                    break
                count_left -= 1
            k = _key(s, all_day)
            if k not in skip and (uid, k) not in moved:
                add(s)
    out.sort(key=lambda o: (o.start, not o.all_day, o.summary.lower()))
    return out


# --- weergave ----------------------------------------------------------------------------------------------------

def when(o: Occurrence, now: datetime, tz: ZoneInfo) -> str:
    s = o.start.astimezone(tz)
    today = now.astimezone(tz).date()
    d = s.date()
    day = ("vandaag" if d == today else "morgen" if d == today + timedelta(days=1)
           else f"{DAYS_NL[d.weekday()]} {d.day}/{d.month}")
    if o.all_day:
        last = (o.end.astimezone(tz) - timedelta(seconds=1)).date()
        if last > d:
            return f"{day} t/m {DAYS_NL[last.weekday()]} {last.day}/{last.month}"
        return f"{day} (hele dag)"
    e = o.end.astimezone(tz)
    if e.date() == d and o.end > o.start:
        return f"{day} {s:%H:%M}–{e:%H:%M}"
    return f"{day} {s:%H:%M}"


class IcsAgenda(Integration):
    name = "ics"
    label = "Agenda (ICS)"
    config_help = {
        "url": "https://agenda.jbogaert.be/ics (ook webcal:// of met ?token=... in de url)",
        "days": f"hoeveel dagen vooruit (standaard {DEFAULT_DAYS})",
        "refresh": f"om de hoeveel minuten de feed opnieuw ophalen (standaard {DEFAULT_REFRESH})",
        "tz": f"tijdzone voor afspraken zonder tijdzone (standaard {DEFAULT_TZ})",
        "insecure": "true bij een zelfondertekend certificaat",
    }
    secret_help = {"token": "optioneel: Bearer-token", "username": "optioneel: basic auth", "password": "optioneel: basic auth"}

    def __init__(self, url, config, secrets, client):
        config = dict(config or {})
        raw = str(config.get("url") or url or "").strip()
        if raw.lower().startswith("webcal://"):
            raw = "https://" + raw[len("webcal://"):]
        config["url"] = raw
        super().__init__(raw, config, secrets, client)
        # Anders dan bij een API hoort de query bij de feed (bv. ?token=...): niet weggooien.
        parts = urlsplit(raw)
        self.base = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        self.path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.feed = raw
        self.tz = _zone(str(self.config.get("tz") or DEFAULT_TZ), ZoneInfo(DEFAULT_TZ))
        self.days = _num(self.config.get("days"), DEFAULT_DAYS, 1, 366)
        self.refresh = _num(self.config.get("refresh"), DEFAULT_REFRESH, 1, 24 * 60) * 60

    def _auth(self) -> dict:
        if self.secrets.get("token"):
            return {"headers": {"Authorization": f"Bearer {self.secrets['token']}"}}
        if self.secrets.get("username"):
            return {"auth": (self.secrets["username"], self.secrets.get("password", ""))}
        return {}

    async def call_auth(self) -> dict:
        return {"headers": {}, **self._auth()}

    async def fetch(self, force: bool = False) -> tuple[str, float, str | None]:
        """(tekst, opgehaald op (epoch), waarschuwing) met een eigen cache: de feed niet bij elke verversing ophalen."""
        key = self.feed + "|" + hashlib.sha256(repr(sorted(self.secrets.items())).encode()).hexdigest()[:16]
        hit = _FEEDS.get(key)
        if hit and not force and time.monotonic() - hit[0] < self.refresh:
            return hit[2], hit[1], None
        try:
            auth = self._auth()
            headers = {"Accept": "text/calendar, */*;q=0.5", **auth.get("headers", {})}
            r = await self._send("GET", self.path, headers=headers, **({"auth": auth["auth"]} if "auth" in auth else {}))
            body = r.content[:MAX_BYTES + 1]
            if len(body) > MAX_BYTES:
                raise IntegrationError("Feed te groot (meer dan 5 MB)")
            text = body.decode(r.encoding or "utf-8", errors="replace")
            if "BEGIN:VCALENDAR" not in text[:2000].upper():
                raise IntegrationError(f"Geen ICS-agenda op {self.base}{urlsplit(self.feed).path}: het antwoord begint niet met BEGIN:VCALENDAR")
        except IntegrationError as e:
            # Even weg: de vorige kopie tonen (tot een dag oud), met de reden erbij.
            if hit and time.monotonic() - hit[0] < STALE_MAX:
                return hit[2], hit[1], str(e)
            raise
        _FEEDS[key] = (time.monotonic(), time.time(), text)
        return text, time.time(), None

    async def upcoming(self, now: datetime | None = None) -> tuple[list[Occurrence], float, str | None, int]:
        text, at, warn = await self.fetch()
        now = now or datetime.now(timezone.utc)
        events = parse(text)
        midnight = now.astimezone(self.tz).replace(hour=0, minute=0, second=0, microsecond=0)
        occ = expand(events, now, midnight + timedelta(days=self.days + 1), self.tz)
        return occ, at, warn, len(events)

    async def health(self) -> dict:
        text, _, warn = await self.fetch()
        if warn:
            raise IntegrationError(warn)
        return {"events": len(parse(text))}

    async def summary(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        occ, at, warn, _ = await self.upcoming(now)
        today = now.astimezone(self.tz).date()
        n_today = sum(1 for o in occ if o.start.astimezone(self.tz).date() <= today)
        week_end = today + timedelta(days=7)
        n_week = sum(1 for o in occ if o.start.astimezone(self.tz).date() < week_end)
        busy = next((o for o in occ if o.start <= now < o.end and not o.all_day), None)
        nxt = next((o for o in occ if o.start > now or (o.all_day and o.start.astimezone(self.tz).date() >= today)), None)
        fields = []
        if busy:
            fields.append(field("nu", busy.summary, "ok"))
        fields.append(field("volgende", f"{when(nxt, now, self.tz)} · {nxt.summary}" if nxt else "niets gepland"))
        fields.append(field("vandaag", n_today))
        fields.append(field("7 dagen", n_week))
        if warn:
            fields.append(field("feed", f"oude kopie ({_age(at)}): {warn}", "warn"))
        return fields

    async def detail(self) -> dict:
        now = datetime.now(timezone.utc)
        occ, at, warn, total = await self.upcoming(now)
        rows = []
        for o in occ[:200]:
            lvl = "ok" if o.start <= now < o.end and not o.all_day else None
            rows.append([cell(when(o, now, self.tz), lvl), cell(o.summary), cell(o.location or "—")])
        info = [field("afspraken in de feed", total), field("komende", len(occ)),
                field("periode", f"{self.days} dagen"), field("opgehaald", _age(at), "warn" if warn else None)]
        if warn:
            info.append(field("fout bij ophalen", warn, "warn"))
        return {"sections": [
            {"kind": "table", "title": "komende afspraken", "columns": ["wanneer", "wat", "waar"], "rows": rows},
            {"kind": "kv", "title": "feed", "items": info},
        ]}


def _num(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        return min(hi, max(lo, int(v)))
    except (TypeError, ValueError):
        return default


def _age(at: float) -> str:
    s = max(0, int(time.time() - at))
    if s < 90:
        return "net"
    if s < 5400:
        return f"{s // 60} min geleden"
    return f"{s // 3600} u geleden"
