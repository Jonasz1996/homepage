"""Schema's lezen en uitrekenen: crontab ("30 3 * * 1-5"), en de kalendernotatie van systemd en Proxmox
("mon..fri 02:30", "*/15", "*-*-01 04:00"). Alles komt neer op dezelfde Spec: welke minuten, uren, dagen,
maanden en weekdagen. Daarmee rekenen we de volgende keren uit en beschrijven we het schema in gewone taal.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
NL_DAYS = ["zo", "ma", "di", "wo", "do", "vr", "za"]
NL_MONTHS = ["jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec"]

CRON_SPECIAL = {"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
                "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}
CAL_SPECIAL = {"minutely": "*-*-* *:*:00", "hourly": "*-*-* *:00:00", "daily": "*-*-* 00:00:00",
               "weekly": "Mon *-*-* 00:00:00", "monthly": "*-*-01 00:00:00", "yearly": "*-01-01 00:00:00",
               "annually": "*-01-01 00:00:00", "quarterly": "*-01,04,07,10-01 00:00:00",
               "semiannually": "*-01,07-01 00:00:00"}


class BadSchedule(ValueError):
    pass


@dataclass
class Spec:
    minutes: set[int]
    hours: set[int]
    doms: set[int] = field(default_factory=lambda: set(range(1, 32)))
    months: set[int] = field(default_factory=lambda: set(range(1, 13)))
    dows: set[int] = field(default_factory=lambda: set(range(7)))  # 0 = zondag
    # Cron: staan dag van de maand én weekdag allebei vast, dan volstaat één van de twee.
    either_day: bool = False

    def day_ok(self, d: datetime) -> bool:
        if d.month not in self.months:
            return False
        dow = (d.weekday() + 1) % 7
        if self.either_day:
            return d.day in self.doms or dow in self.dows
        return d.day in self.doms and dow in self.dows


def _num(tok: str, names: list[str] | None, lo: int) -> int:
    t = tok.strip().lower()
    if names:
        for i, n in enumerate(names):
            if t[:3] == n and t.isalpha():
                return i + lo
    if not t.isdigit():
        raise BadSchedule(tok)
    return int(t)


def _field(text: str, lo: int, hi: int, names: list[str] | None = None, rng: str = "-") -> set[int]:
    out: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise BadSchedule(text)
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) == 0:
                raise BadSchedule(text)
            step = int(s)
        if part in ("*", ""):
            a, b = lo, hi
        elif rng in part:
            x, y = part.split(rng, 1)
            a, b = _num(x, names, lo), _num(y, names, lo)
        else:
            a = _num(part, names, lo)
            b = hi if step > 1 else a
        if a < lo or b > hi or a > b:
            # Weekdagen mogen rondlopen (fri..mon) en 7 = zondag.
            if names is DAYS and lo == 0:
                vals = [v % 7 for v in range(a, (b if b >= a else b + 7) + 1, step)]
                out.update(vals)
                continue
            raise BadSchedule(text)
        out.update(range(a, b + 1, step))
    return out


def parse_cron(expr: str) -> Spec:
    expr = CRON_SPECIAL.get(expr.strip().lower(), expr.strip())
    parts = expr.split()
    if len(parts) != 5:
        raise BadSchedule(expr)
    m, h, dom, mon, dow = parts
    dows = {d % 7 for d in _field(dow, 0, 7, DAYS)}
    return Spec(minutes=_field(m, 0, 59), hours=_field(h, 0, 23), doms=_field(dom, 1, 31),
                months=_field(mon, 1, 12, MONTHS), dows=dows,
                either_day=not dom.startswith("*") and not dow.startswith("*"))


def _cal_part(text: str, lo: int, hi: int, names: list[str] | None = None) -> set[int]:
    return _field(text.replace("..", "-"), lo, hi, names)


def parse_calendar(expr: str) -> Spec:
    """systemd OnCalendar en Proxmox-schema's (vzdump, replicatie, PBS-jobs)."""
    text = CAL_SPECIAL.get(expr.strip().lower(), expr.strip())
    toks = text.split()
    if not toks:
        raise BadSchedule(expr)
    spec = Spec(minutes={0}, hours={0})
    time_seen = False
    for tok in toks:
        low = tok.lower()
        if re.fullmatch(r"[a-z]{3}[a-z]*((\.\.|,)[a-z]{3}[a-z]*)*", low):
            spec.dows = {d % 7 for d in _cal_part(low, 0, 7, DAYS)}
        elif ":" in tok:
            bits = tok.split(":")
            if len(bits) not in (2, 3):
                raise BadSchedule(expr)
            spec.hours = _cal_part(bits[0], 0, 23)
            spec.minutes = _cal_part(bits[1], 0, 59)
            time_seen = True
        elif "-" in tok and not tok.startswith("-"):
            bits = tok.split("-")
            if len(bits) == 3:
                _, mon, day = bits
            elif len(bits) == 2:
                mon, day = bits
            else:
                raise BadSchedule(expr)
            if "~" in day:
                raise BadSchedule(expr)
            spec.months = _cal_part(mon, 1, 12)
            spec.doms = _cal_part(day, 1, 31)
        elif re.fullmatch(r"[\d*/.,]+", tok) and not time_seen:
            # Proxmox: een los getal of "*/5" zijn minuten, elk uur.
            spec.minutes = _cal_part(tok, 0, 59)
            spec.hours = set(range(24))
            time_seen = True
        else:
            raise BadSchedule(expr)
    return spec


def tz_of(name: str | None) -> timezone | ZoneInfo:
    try:
        return ZoneInfo(name) if name else timezone.utc
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def occurrences(spec: Spec, start: datetime, end: datetime, tz=timezone.utc, limit: int = 2000) -> list[datetime]:
    """Alle tijdstippen (UTC) tussen start en end, in de tijdzone van de machine uitgerekend."""
    out: list[datetime] = []
    local = start.astimezone(tz)
    day = datetime(local.year, local.month, local.day)
    last = end.astimezone(tz).replace(tzinfo=None)
    hours, minutes = sorted(spec.hours), sorted(spec.minutes)
    while day <= last and len(out) < limit:
        if spec.day_ok(day):
            for h in hours:
                for m in minutes:
                    t = day.replace(hour=h, minute=m, tzinfo=tz).astimezone(timezone.utc)
                    if start <= t < end:
                        out.append(t)
                        if len(out) >= limit:
                            return out
        day += timedelta(days=1)
    return out


def next_after(spec: Spec, after: datetime, tz=timezone.utc, horizon_days: int = 400) -> datetime | None:
    step = timedelta(days=7)
    t = after
    while t < after + timedelta(days=horizon_days):
        hit = occurrences(spec, t, t + step, tz, limit=1)
        if hit:
            return hit[0]
        t += step
    return None


def prev_before(spec: Spec, before: datetime, tz=timezone.utc, horizon_days: int = 40) -> datetime | None:
    step = timedelta(days=1)
    t = before
    while t > before - timedelta(days=horizon_days):
        hits = occurrences(spec, t - step, t, tz)
        if hits:
            return hits[-1]
        t -= step
    return None


def per_day(spec: Spec) -> int:
    return len(spec.hours) * len(spec.minutes)


# --- In gewone taal --------------------------------------------------------------

def _days_text(spec: Spec) -> str:
    all_dom, all_dow = len(spec.doms) == 31, len(spec.dows) == 7
    parts = []
    if not all_dow:
        d = sorted(spec.dows)
        if d == [1, 2, 3, 4, 5]:
            parts.append("ma–vr")
        elif d == [0, 6]:
            parts.append("in het weekend")
        else:
            parts.append(", ".join(NL_DAYS[x] for x in sorted(d, key=lambda x: (x + 6) % 7)))
    if not all_dom:
        doms = sorted(spec.doms)
        if len(doms) <= 3:
            parts.append("op de " + ", ".join(f"{x}e" for x in doms) + (" van de maand" if len(spec.months) == 12 else ""))
        elif doms == list(range(doms[0], doms[-1] + 1)):
            parts.append(f"tussen de {doms[0]}e en de {doms[-1]}e")
        else:
            parts.append(f"op {len(doms)} dagen van de maand")
    if len(spec.months) < 12:
        parts.append("in " + ", ".join(NL_MONTHS[m - 1] for m in sorted(spec.months)))
    if not parts:
        return "elke dag"
    return (" of " if spec.either_day else " ").join(parts)


def _step(values: list[int], span: int) -> int | None:
    if len(values) < 2:
        return None
    d = values[1] - values[0]
    if all(b - a == d for a, b in zip(values, values[1:])) and values[0] < d and values[-1] + d >= span:
        return d
    return None


def describe(spec: Spec) -> str:
    mins, hrs = sorted(spec.minutes), sorted(spec.hours)
    days = _days_text(spec)
    every_day = days == "elke dag"
    if len(mins) == 60 and len(hrs) == 24:
        return "elke minuut" + ("" if every_day else f", {days}")
    if len(hrs) == 24:
        st = _step(mins, 60)
        what = (f"elke {st} minuten" + (f" (vanaf :{mins[0]:02d})" if mins[0] else "")) if st else (f"elk uur om :{mins[0]:02d}" if len(mins) == 1 else
                                                    "elk uur om " + ", ".join(f":{m:02d}" for m in mins[:6]))
        return what + ("" if every_day else f", {days}")
    if len(mins) == 1:
        st = _step(hrs, 24)
        if st and len(hrs) > 3:
            what = f"elke {st} uur om :{mins[0]:02d}"
        elif len(hrs) > 4 and hrs == list(range(hrs[0], hrs[-1] + 1)):
            what = f"elk uur om :{mins[0]:02d} van {hrs[0]:02d} tot {hrs[-1]:02d} u"
        elif len(hrs) <= 4:
            what = "om " + " en ".join(f"{h:02d}:{mins[0]:02d}" for h in hrs)
        else:
            what = f"om :{mins[0]:02d} na " + ", ".join(str(h) for h in hrs) + " u"
        return what if every_day and what.startswith("elke") else f"{days} {what}"
    n = len(mins) * len(hrs)
    if n <= 4:
        return f"{days} om " + " en ".join(f"{h:02d}:{m:02d}" for h in hrs for m in mins)
    return f"{days}, {n} keer per dag tussen {hrs[0]:02d}:00 en {hrs[-1]:02d}:59"


# --- Monotone systemd-timers ("OnUnitActiveSec=1d") ------------------------------

_DUR = {"us": 1e-6, "ms": 1e-3, "s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hr": 3600, "d": 86400,
        "w": 604800, "month": 2629800, "M": 2629800, "y": 31557600}


def parse_duration(text: str) -> float | None:
    total, found = 0.0, False
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?", text or ""):
        total += float(num) * _DUR.get(unit or "s", _DUR.get((unit or "").lower(), 0) or 0)
        found = True
    return total if found and total > 0 else None


def describe_interval(seconds: float) -> str:
    for unit, n in (("dag", 86400), ("uur", 3600), ("minuten", 60)):
        if seconds >= n and seconds % n == 0:
            k = int(seconds // n)
            if unit == "dag":
                return "elke dag" if k == 1 else f"elke {k} dagen"
            if unit == "uur":
                return "elk uur" if k == 1 else f"elke {k} uur"
            return "elke minuut" if k == 1 else f"elke {k} minuten"
    return f"elke {int(seconds)} s"
