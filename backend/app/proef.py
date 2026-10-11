"""Proefmodus: tonen wat een actie zou doen (op welke machine, via SSH of welke API, als wie, met welk commando en in
welke volgorde), zonder het uit te voeren.

Elke functie die machines verandert, bouwt haar plan met dezelfde code die ze zelf uitvoert, zodat de proef niet kan
afwijken van het echte werk. Een plan bevat nooit een geheim: alleen gebruikersnamen, token-ID's, adressen en
commando's. plan() maskeert voor de zekerheid nog alles wat op een geheim lijkt.

Een plan is gewone JSON:
    {proef: true, title, at,
     checks:   [{what, ok: true|false|null, detail}],          wat vooraf nagekeken is (null = niet na te gaan)
     steps:    [{nr, machine, via, who, call, data, wait, when, on_fail, note}],
     skipped:  [{what, why}],                                   wat niet zou gebeuren en waarom
     after:    [tekst],                                         wat daarna volgt (meldingen, tijdlijn, een scan)
     warnings: [tekst]}
"""

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from .deps import event
from .masking import mask_tree
from .models import SshHost
from .ssh_login import Login

# Begin van de titel van elke gebeurtenis die een automatische run in proefmodus op de tijdlijn zet.
EVENT_PREFIX = "Proef: "

VIA = {"ssh": "SSH", "proxmox-api": "Proxmox-API", "portainer-api": "Portainer-API", "adguard-api": "AdGuard-API",
       "pbs-api": "PBS-API", "api": "API", "dashboard": "dashboard"}


def ssh_who(login: Login) -> str:
    return "root" if login.username == "root" else f"{login.username} met sudo -n"


def ssh_machine(h: SshHost, login: Login | None = None, vmid: int | None = None) -> str:
    user = (login.username if login else h.username) or "root"
    s = f"{h.name} ({user}@{h.host}:{h.port})"
    return s + (f" → CT {vmid} via pct exec" if vmid is not None else "")


def api_who(token_id: str | None) -> str:
    # Geen "token-id: x": de maskering zou dat als geheim zien.
    return f"API-token {token_id}" if token_id else "API-token ?"


def step(machine: str, via: str, call: str, *, who: str | None = None, data: dict | None = None,
         wait: str | None = None, when: str | None = None, on_fail: str | None = None, note: str | None = None) -> dict:
    s = {"machine": machine, "via": via, "who": who, "call": call, "data": data, "wait": wait, "when": when,
         "on_fail": on_fail, "note": note}
    return {k: v for k, v in s.items() if v is not None}


def check(what: str, ok: bool | None, detail: str | None = None) -> dict:
    return {"what": what, "ok": ok, "detail": detail}


def skip(what: str, why: str) -> dict:
    return {"what": what, "why": why}


def plan(title: str, steps: list[dict], *, checks=(), skipped=(), after=(), warnings=(),
         now: datetime | None = None, **extra) -> dict:
    out = {"proef": True, "title": title, "at": (now or datetime.now(timezone.utc)).isoformat(),
           "checks": list(checks), "steps": [{"nr": i, **s} for i, s in enumerate(steps, 1)],
           "skipped": list(skipped), "after": list(after), "warnings": list(warnings), **extra}
    return mask_tree(out)


def text(p: dict) -> str:
    """Het plan als platte tekst, voor de tijdlijn en de diagnose."""
    lines = [p.get("title") or "Proef"]
    for c in p.get("checks") or []:
        mark = "✓" if c.get("ok") is True else "✕" if c.get("ok") is False else "?"
        lines.append(f"{mark} {c['what']}" + (f": {c['detail']}" if c.get("detail") else ""))
    for s in p.get("steps") or []:
        how = VIA.get(s.get("via"), s.get("via") or "")
        who = f" als {s['who']}" if s.get("who") else ""
        lines.append(f"{s['nr']}. {s['machine']} via {how}{who}" + (f" (alleen {s['when']})" if s.get("when") else ""))
        lines.append(f"   {s['call']}")
        if s.get("data"):
            lines.append(f"   {s['data']}")
        for label, k in (("wacht", "wait"), ("als dit mislukt", "on_fail"), ("let op", "note")):
            if s.get(k):
                lines.append(f"   {label}: {s[k]}")
    if not p.get("steps"):
        lines.append("Er zou niets gebeuren.")
    for x in p.get("skipped") or []:
        lines.append(f"overgeslagen: {x['what']}: {x['why']}")
    for a in p.get("after") or []:
        lines.append(f"daarna: {a}")
    for w in p.get("warnings") or []:
        lines.append(f"let op: {w}")
    return "\n".join(lines)


def record(db: AsyncSession, kind: str, title: str, p: dict, service_id: int | None = None) -> None:
    """Een automatische run in proefmodus: alleen op de tijdlijn (geen melding, geen push)."""
    event(db, kind, EVENT_PREFIX + title, text(p)[:20000], level="info", service_id=service_id,
          data={"proef": True, "plan": p})
