"""Veiligheidscheck (hw → beveiliging): wat er aan de beveiliging van het dashboard nog beter kan.

Elke controle geeft {key, title, level, text, items, fix}: level ok, info, warn of err; fix zegt welk venster het
oplost (de frontend maakt er een knop van).
"""

import asyncio
import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..integrations import IntegrationError, build, from_api
from ..models import ApiConnection, AppState, AuditLog, Service, Session, SshHost, User
from ..ssh_pin import STATE_KEY as PIN_KEY
from .selfcheck import STATE_KEY as SELF_KEY

SECRET_SAVED = "secret_key_saved"
# Rechten waarmee een Proxmox-token iets kan veranderen. Een leestoken hoort er geen te hebben.
WRITE_PRIVS = {
    "VM.PowerMgmt", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.Allocate", "VM.Clone", "VM.Migrate", "VM.Backup",
    "VM.Console", "VM.Config.Disk", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options",
    "VM.Config.HWType", "VM.Config.Cloudinit", "VM.Config.CDROM", "Sys.Modify", "Sys.PowerMgmt", "Sys.Console",
    "Sys.Incoming", "Datastore.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate",
    "Permissions.Modify", "User.Modify", "Group.Allocate", "Realm.Allocate", "Realm.AllocateUser", "Pool.Allocate",
    "SDN.Allocate", "Mapping.Modify",
}
# Wat het dashboard nooit nodig heeft: wie dit token heeft, kan rechten uitdelen, een console openen of nodes uitzetten.
ADMIN_PRIVS = {"Permissions.Modify", "User.Modify", "Group.Allocate", "Realm.Allocate", "Realm.AllocateUser",
               "Sys.Console", "Sys.PowerMgmt"}
SESSIONS_RECENT = timedelta(days=14)


def item(key: str, title: str, level: str, text: str, items: list | None = None, fix: dict | None = None) -> dict:
    return {"key": key, "title": title, "level": level, "text": text, "items": items or [], "fix": fix}


async def _state(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value or {}) if st else {}


def _public(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def check_2fa(db: AsyncSession) -> dict:
    users = list((await db.execute(select(User))).scalars())
    without = [u.username for u in users if not u.totp_enabled]
    oidc = await _state(db, "oidc")
    if without:
        return item("2fa", "2FA voor elk account", "warn", f"Zonder 2FA: {', '.join(without)}. Die accounts kunnen niet "
                    "inloggen tot 2FA klaar is; verwijder ze als je ze niet kent.")
    if oidc.get("enabled") and not oidc.get("require_mfa", True):
        return item("2fa", "2FA voor elk account", "warn", "Inloggen via Authentik vraagt geen 2FA: zet 'Authentik moet "
                    "2FA melden' weer aan.", fix={"window": "security", "tab": "sso"})
    via = " Authentik moet ook 2FA melden." if oidc.get("enabled") else ""
    return item("2fa", "2FA voor elk account", "ok", f"Staat aan voor {len(users)} account{'s' if len(users) != 1 else ''}.{via}")


async def check_secret_key(db: AsyncSession) -> dict:
    off = (await _state(db, SELF_KEY)).get("offsite") or {}
    saved = await _state(db, SECRET_SAVED)
    if off.get("enabled") and off.get("key"):
        return item("secret", "Kopie van secret.key", "ok", f"Versleuteld mee in de kopie buiten de container ({off.get('dir')}).")
    if saved.get("at"):
        return item("secret", "Kopie van secret.key", "ok", f"Je bevestigde op {saved['at'][:10]} dat je een kopie bewaarde.")
    return item("secret", "Kopie van secret.key", "warn",
                "Zonder /etc/homepage/secret.key zijn alle opgeslagen wachtwoorden en API-sleutels onleesbaar, ook in een "
                "back-up. Zet de kopie buiten de container aan met een wachtzin (hw → homepage zelf), of bewaar het "
                "bestand zelf in je wachtwoordkluis en bevestig dat hier.", fix={"action": "secret_saved"})


async def check_offsite(db: AsyncSession) -> dict:
    off = (await _state(db, SELF_KEY)).get("offsite") or {}
    if not off.get("enabled"):
        return item("offsite", "Back-up buiten de container", "warn", "Staat uit: valt de container of zijn node weg, dan "
                    "is ook de back-up van het dashboard weg.", fix={"window": "health", "tab": "homepage"})
    if off.get("error"):
        return item("offsite", "Back-up buiten de container", "warn", off["error"], fix={"window": "health", "tab": "homepage"})
    return item("offsite", "Back-up buiten de container", "ok",
                f"{off.get('count') or 0} kopieën in {off.get('dir')}" + (f", laatste {off['at'][:16].replace('T', ' ')}" if off.get("at") else ""))


async def check_sessions(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(Session).where(Session.mfa_ok.is_(True)))).scalars()
    out = []
    for s in rows:
        expires = s.expires_at.replace(tzinfo=s.expires_at.tzinfo or timezone.utc)
        seen = s.last_seen_at or s.created_at
        seen = seen.replace(tzinfo=seen.tzinfo or timezone.utc)
        if expires > now and now - seen < SESSIONS_RECENT and _public(s.ip):
            out.append({"ip": s.ip, "country": s.country, "seen": seen.isoformat(), "user_agent": (s.user_agent or "")[:80]})
    failed = (await db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action.like("login_failed%"), AuditLog.ts > now - timedelta(days=7)))).scalar_one()
    extra = f" {failed} mislukte logins de laatste 7 dagen." if failed else ""
    if out:
        return item("sessions", "Sessies van buitenaf", "warn",
                    f"{len(out)} sessie{'s' if len(out) != 1 else ''} vanaf een publiek IP. Ken je ze allemaal? Afmelden kan "
                    f"in het sessie-overzicht.{extra}", items=out, fix={"window": "security", "tab": "sessions"})
    level = "warn" if failed >= 20 else "ok"
    return item("sessions", "Sessies van buitenaf", level, f"Geen actieve sessies vanaf een publiek IP.{extra}",
                fix={"window": "security", "tab": "audit"} if failed else None)


async def _privs(integ) -> set[str]:
    data = await integ.request("GET", "/api2/json/access/permissions", headers=integ.headers())
    perms = (data or {}).get("data") or {}
    return {p for v in perms.values() if isinstance(v, dict) for p, on in v.items() if on}


async def _proxmox_one(name: str, integ) -> dict:
    try:
        read = await asyncio.wait_for(_privs(integ), 10)
    except (IntegrationError, asyncio.TimeoutError) as e:
        return {"name": name, "level": "info", "text": f"rechten niet op te vragen: {e}"}
    if not integ.split:
        admin = sorted(read & ADMIN_PRIVS)
        if admin:
            return {"name": name, "level": "err", "text": f"één token dat ook {', '.join(admin)} mag: maak tokens met "
                    "alleen de rechten die het dashboard nodig heeft"}
        write = sorted(read & WRITE_PRIVS)
        if write:
            return {"name": name, "level": "warn", "text": f"één token voor alles, ook om te veranderen ({', '.join(write[:5])}"
                    f"{'…' if len(write) > 5 else ''}); voeg een actietoken toe en maak dit token alleen-lezen"}
        return {"name": name, "level": "ok", "text": "alleen-lezen token (acties kunnen niet)"}
    write = sorted(read & WRITE_PRIVS)
    if write:
        return {"name": name, "level": "warn", "text": f"het leestoken mag ook {', '.join(write[:5])}{'…' if len(write) > 5 else ''}: "
                "geef het alleen PVEAuditor"}
    integ.secrets = {**integ.secrets, "username": integ.secrets["action_username"], "password": integ.secrets["action_password"]}
    try:
        act = await asyncio.wait_for(_privs(integ), 10)
    except (IntegrationError, asyncio.TimeoutError) as e:
        return {"name": name, "level": "warn", "text": f"leestoken in orde, actietoken werkt niet: {e}"}
    admin = sorted(act & ADMIN_PRIVS)
    if admin:
        return {"name": name, "level": "warn", "text": f"leestoken in orde; het actietoken mag meer dan nodig ({', '.join(admin)})"}
    return {"name": name, "level": "ok", "text": "twee tokens: alleen-lezen voor monitoring, een apart voor acties"}


async def proxmox_tokens(db: AsyncSession, clients) -> list[tuple[str, object]]:
    """(naam, integratie) per Proxmox-token, dezelfde cluster met hetzelfde token maar één keer."""
    todo = []
    for a in (await db.execute(select(ApiConnection).where(ApiConnection.kind == "proxmox"))).scalars():
        try:
            todo.append((f"API {a.name}", from_api(a, {}, clients)))
        except IntegrationError:
            continue
    for s in (await db.execute(select(Service).where(Service.type == "proxmox", Service.api_id.is_(None)))).scalars():
        try:
            todo.append((s.name, build(s, clients)))
        except IntegrationError:
            continue
    # Dezelfde cluster met hetzelfde token maar één keer vragen.
    seen, uniq = set(), []
    for name, integ in todo:
        k = (integ.base, integ.secrets.get("username"), integ.secrets.get("action_username"))
        if integ.secrets.get("username") and k not in seen:
            seen.add(k)
            uniq.append((name, integ))
    return uniq


async def check_tokens(db: AsyncSession, clients) -> dict:
    uniq = await proxmox_tokens(db, clients)
    if not uniq:
        return item("tokens", "Rechten van de Proxmox-tokens", "info", "Nog geen Proxmox-token ingesteld.")
    res = await asyncio.gather(*(_proxmox_one(n, i) for n, i in uniq))
    rank = {"ok": 0, "info": 1, "warn": 2, "err": 3}
    level = max((r["level"] for r in res), key=rank.__getitem__)
    text = {"ok": "Leestoken en actietoken zijn gescheiden.", "info": "Niet alles kon nagekeken worden.",
            "warn": "Een token heeft meer rechten dan nodig.", "err": "Een token kan rechten uitdelen of een console openen."}[level]
    return item("tokens", "Rechten van de Proxmox-tokens", level, text, items=res, fix={"window": "api"})


async def check_outside(db: AsyncSession) -> dict:
    cfg = await outside.settings(db)
    always, hour = [], []
    for key, (label, _) in outside.FEATURES.items():
        ok, mode, until = outside.allowed(cfg, key)
        if mode == "aan":
            always.append(label)
        elif ok:
            left = max(1, round((datetime.fromisoformat(until) - datetime.now(timezone.utc)).total_seconds() / 60))
            hour.append(f"{label} (nog {left} min)")
    fix = {"window": "security", "tab": "outside"}
    if always:
        return item("outside", "Van buitenaf", "warn", f"Altijd aan van buitenaf: {', '.join(always)}. Wie je login "
                    "overneemt, kan dat dan ook.", fix=fix)
    if hour:
        return item("outside", "Van buitenaf", "info", f"Tijdelijk aan: {', '.join(hour)}.", fix=fix)
    return item("outside", "Van buitenaf", "ok", "Terminal, updates, acties en downloads staan uit van buitenaf; kijken kan wel.",
                fix=fix)


async def check_access(db: AsyncSession) -> dict:
    seen = await _state(db, outside.SEEN_KEY)
    last = seen.get("last")
    fix = {"window": "net", "tab": "firewall"}
    if not last:
        return item("access", "Slot voor het dashboard", "info", "Nog geen bezoek van buitenaf gezien. Bij het eerste bezoek "
                    "via Cloudflare zie je hier of Cloudflare Access of Authentik ervoor staat.", fix=fix)
    if last.get("access"):
        name = {"cloudflare-access": "Cloudflare Access", "authentik": "Authentik"}.get(last["access"], last["access"])
        return item("access", "Slot voor het dashboard", "ok", f"{name} stond voor het laatste bezoek van buitenaf.", fix=fix)
    return item("access", "Slot voor het dashboard", "warn",
                "Het laatste bezoek van buitenaf kwam zonder Cloudflare Access of Authentik binnen: iedereen krijgt het "
                "loginscherm te zien. Zet er een slot voor in Cloudflare of NPM.", fix=fix)


async def check_ssh_pin(db: AsyncSession) -> dict:
    st = await _state(db, PIN_KEY)
    hosts = {h.id: h.name for h in (await db.execute(select(SshHost))).scalars()}
    fix = {"window": "ssh-keys"}
    if not hosts:
        return item("sshpin", "SSH-sleutel vastgezet", "info", "Nog geen SSH-hosts.")
    if not st.get("checked_at"):
        return item("sshpin", "SSH-sleutel vastgezet", "info", "Nog niet nagekeken: open de terminal → ssh-keygen → vastzetten.", fix=fix)
    res = {int(k): v for k, v in (st.get("hosts") or {}).items() if int(k) in hosts}
    loose = [hosts[i] for i, r in res.items() if r.get("state") in ("los", "anders")]
    pinned = [hosts[i] for i, r in res.items() if r.get("state") == "vast"]
    unknown = [n for i, n in hosts.items() if i not in res]
    if loose:
        return item("sshpin", "SSH-sleutel vastgezet", "warn", f"Werkt nog vanaf elk IP op {len(loose)} host"
                    f"{'s' if len(loose) != 1 else ''}: {', '.join(loose[:6])}{'…' if len(loose) > 6 else ''}.", fix=fix)
    if pinned:
        more = f" {len(unknown)} nieuwe host{'s' if len(unknown) != 1 else ''} nog niet nagekeken." if unknown else ""
        return item("sshpin", "SSH-sleutel vastgezet", "info" if unknown else "ok",
                    f"Vast op het dashboard bij {len(pinned)} host{'s' if len(pinned) != 1 else ''}.{more}", fix=fix)
    return item("sshpin", "SSH-sleutel vastgezet", "info", "Geen host met een sleutel van het dashboard gevonden.", fix=fix)


async def run(db: AsyncSession, clients) -> dict:
    checks = [await check_2fa(db), await check_secret_key(db), await check_offsite(db), await check_sessions(db),
              await check_outside(db), await check_access(db), await check_ssh_pin(db), await check_tokens(db, clients)]
    return {"checks": checks, "checked_at": datetime.now(timezone.utc).isoformat()}
