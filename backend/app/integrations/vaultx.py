"""VaultX: de wachtwoordkluis, notities, links en appcatalogus van VaultX, via zijn lees-API voor dashboards.

VaultX geeft op GET /api/v1/stats enkel tellingen en tijdstippen, nooit inhoud (geen wachtwoorden, namen of URL's van
kluisitems). De sleutel (vxk_…, VaultX: je account → API-sleutels voor je dashboard → Sleutel aanmaken) kan niets
wijzigen en werkt op geen enkel ander pad, dus deze integratie heeft geen acties.

Een sleutel van een instantiebeheerder geeft de cijfers van heel VaultX ("scope": "instance", met gebruikers), een
gewone gebruiker enkel de eigen cijfers ("scope": "user").
"""

from datetime import datetime
from typing import Any

import httpx

from .base import Integration, IntegrationError, ago, cell, field

STATS = "/api/v1/stats"
READY = "/health/ready"

# Zoals de catalogus van VaultX ze noemt.
APP_STATUS = {"protected": ("beschermd (Authentik)", "ok"), "restricted": ("beperkt", None),
              "unprotected": ("onbeschermd", "warn"), "offline": ("offline", "warn"), "removed": ("verwijderd", None),
              "unknown": ("onbekend", None)}
ITEM_TYPES = (("logins", "logins"), ("notes", "notities"), ("cards", "kaarten"), ("identities", "identiteiten"),
              ("ssh_keys", "SSH-sleutels"), ("other", "andere"))


def since(ts: Any) -> dict | None:
    """Een ISO-tijdstip van VaultX ("2026-11-16T21:40:00Z") als {"age": seconden}; het dashboard toont "… geleden"."""
    if not ts:
        return None
    try:
        return {"age": ago(datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp())}
    except ValueError:
        return None


def _n(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def npm_problems(stats: dict) -> list[str]:
    """NPM-koppelingen die aanstaan en waarvan de laatste synchronisatie mislukte."""
    conns = (stats.get("catalog") or {}).get("npm_connections") or []
    return [f"NPM-sync {c.get('name') or '?'} mislukt" for c in conns
            if c.get("enabled") and c.get("last_sync_status") not in (None, "", "ok")]


class VaultX(Integration):
    name = "vaultx"
    label = "VaultX"
    config_help = {
        "url": "http://<IP van VaultX> (rechtstreeks op IP: poort 80 op de Debian-container, 8080 met Docker; zonder /api)",
        "link": "optioneel: adres waarmee je VaultX in de browser opent (bv. https://vaultx.jbogaert.be); "
                "standaard het adres van de API",
        "insecure": "true bij https met het zelfondertekende certificaat van VaultX",
    }
    secret_help = {"token": "API-sleutel vxk_… (VaultX: je account → API-sleutels voor je dashboard → Sleutel aanmaken)"}
    # Eigen calls uit API-beheer: alleen /api/v1/stats is toegelaten met deze sleutel.
    call_prefix = "/api/v1"
    # VaultX zegt bij een 401 waarom (verlopen, ingetrokken, account gedeactiveerd): dat tonen we.
    explain_401 = True

    # --- aanmelding en calls ------------------------------------------------------

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.need('token')[0]}", "Accept": "application/json"}

    async def call_auth(self) -> dict:
        return {"headers": self.headers()}

    def _error_detail(self, r: httpx.Response) -> str | None:
        # VaultX geeft {"error": ..., "detail": ...}; /health/ready geeft {"database": "down"} met 503.
        try:
            body = r.json() or {}
        except ValueError:
            return None
        if not isinstance(body, dict):
            return None
        if body.get("database") == "down":
            return f"VaultX: database onbereikbaar (HTTP {r.status_code})"
        msg = body.get("detail")
        if isinstance(msg, str) and msg:
            return f"VaultX: {msg[:200]} (HTTP {r.status_code})"
        return None

    async def stats(self) -> dict:
        data = await self.request("GET", STATS, headers=self.headers())
        if not isinstance(data, dict) or "vault" not in data:
            raise IntegrationError("Geen antwoord van de lees-API: klopt de url (http://<IP van VaultX>, zonder /api)?")
        return data

    def link(self) -> str:
        base = str(self.config.get("link") or "").strip().rstrip("/")
        return base if base.lower().startswith(("http://", "https://")) else self.base

    # --- check van de tegel --------------------------------------------------------

    async def health(self) -> dict:
        """Voor de api-check: rood als de database van VaultX weg is, de sleutel niet meer werkt of een NPM-sync faalt."""
        await self.request("GET", READY)  # zonder sleutel; 503 = database down
        s = await self.stats()
        bad = npm_problems(s)
        if bad:
            raise IntegrationError("; ".join(bad)[:200])
        return {"scope": s.get("scope"), "version": s.get("version")}

    # --- tegel ---------------------------------------------------------------------

    @staticmethod
    def summary_fields(s: dict) -> list[dict]:
        vault = s.get("vault") or {}
        items = vault.get("items") or {}
        dev = vault.get("devices") or {}
        act = s.get("activity_last_24h") or {}
        cat = s.get("catalog") or {}
        failed = _n(act.get("failed_logins")) + _n(act.get("failed_vault_logins"))
        logins = _n(act.get("logins")) + _n(act.get("vault_logins"))
        active = dev.get("active_last_30_days")
        out = [
            field("kluisitems", _n(items.get("total"))),
            field("toestellen", f"{_n(dev.get('total'))} ({_n(active)} actief)" if active is not None else _n(dev.get("total"))),
            field("sessies", _n((s.get("sessions") or {}).get("active"))),
            field("logins 24u", f"{logins} ({failed} mislukt)" if failed else logins, "warn" if failed else "ok"),
        ]
        if cat.get("applications"):
            by = cat.get("by_status") or {}
            weak = _n(by.get("unprotected")) + _n(by.get("offline"))
            out.append(field("apps", f"{_n(cat.get('applications'))} ({weak} onbeschermd/offline)" if weak
                             else _n(cat.get("applications")), "warn" if weak else "ok"))
        bad = npm_problems(s)
        if bad:
            out.append(field("NPM", "sync mislukt", "err"))
        return out

    async def summary(self) -> list[dict]:
        return self.summary_fields(await self.stats())

    # --- mini dashboard ---------------------------------------------------------------

    async def detail(self) -> dict:
        s = await self.stats()
        vault = s.get("vault") or {}
        items = vault.get("items") or {}
        dev = vault.get("devices") or {}
        act = s.get("activity_last_24h") or {}
        cat = s.get("catalog") or {}
        notes = s.get("notes") or {}
        links = s.get("links") or {}
        sess = s.get("sessions") or {}
        instance = s.get("scope") == "instance"
        att = vault.get("attachments") or {}

        overview = self.summary_fields(s) + [
            field("versie", s.get("version") or "—"),
            field("cijfers van", "heel VaultX (beheerder)" if instance else "enkel jouw account"),
        ]
        sections: list[dict] = [{"kind": "kv", "title": "overzicht", "items": overview, "href": self.link()}]

        kluis = [field(label, _n(items.get(key))) for key, label in ITEM_TYPES if _n(items.get(key)) or key == "logins"]
        kluis += [
            field("favorieten", _n(items.get("favorites"))),
            field("gearchiveerd", _n(items.get("archived"))),
            field("in prullenbak", _n(items.get("in_trash"))),
            field("mappen", _n(vault.get("folders"))),
            field("bijlagen", _n(att.get("count"))),
            field("bijlagen samen", {"bytes": _n(att.get("bytes"))}),
            field("kluisaccounts", _n(vault.get("accounts"))),
            field("met tweestaps", f"{_n(vault.get('with_two_factor'))}/{_n(vault.get('accounts'))}",
                  "ok" if _n(vault.get("accounts")) and _n(vault.get("with_two_factor")) >= _n(vault.get("accounts"))
                  else "warn" if _n(vault.get("accounts")) else None),
            field("laatste wijziging", since(vault.get("last_change_at"))),
        ]
        sections.append({"kind": "kv", "title": "kluis", "items": kluis})

        by_type = dev.get("by_type") or {}
        sections.append({"kind": "table", "title": "toestellen", "columns": ["soort", "aantal"],
                         "empty": "Geen ingelogde toestellen.",
                         "rows": [[cell(k), cell(_n(v))] for k, v in by_type.items()]})
        sections.append({"kind": "kv", "title": "toestellen en sessies", "items": [
            field("ingelogd", _n(dev.get("total"))),
            field("actief (30 dagen)", _n(dev.get("active_last_30_days"))),
            field("laatst gezien", since(dev.get("last_seen_at"))),
            field("sessies webinterface", _n(sess.get("active"))),
            field("gebruikers met sessie", _n(sess.get("users"))),
        ]})

        failed = _n(act.get("failed_logins"))
        vfailed = _n(act.get("failed_vault_logins"))
        sections.append({"kind": "kv", "title": "activiteit laatste 24 uur", "items": [
            field("gebeurtenissen", _n(act.get("events"))),
            field("logins VaultX", _n(act.get("logins"))),
            field("mislukte logins", failed, "warn" if failed else "ok"),
            field("logins kluis (apps)", _n(act.get("vault_logins"))),
            field("mislukte kluislogins", vfailed, "warn" if vfailed else "ok"),
        ]})

        if instance and s.get("users"):
            u = s["users"]
            sections.append({"kind": "kv", "title": "gebruikers", "items": [
                field("totaal", _n(u.get("total"))),
                field("actief", _n(u.get("active"))),
                field("beheerders", _n(u.get("admins"))),
                field("met Authentik", _n(u.get("with_authentik"))),
                field("met wachtwoord", _n(u.get("with_password"))),
                field("ingelogd 24u", _n(u.get("logged_in_last_24h"))),
                field("vergrendeld", _n(u.get("locked")), "warn" if _n(u.get("locked")) else "ok"),
            ]})

        if cat.get("applications") or cat.get("npm_connections"):
            by = cat.get("by_status") or {}
            hosts = _n(cat.get("hosts"))
            online = _n(cat.get("hosts_online"))
            ssl = _n(cat.get("hosts_with_ssl"))
            items_cat = [field("apps", _n(cat.get("applications"))), field("automatisch inloggen", _n(cat.get("auto_login")))]
            items_cat += [field(APP_STATUS.get(k, (k, None))[0], _n(v), APP_STATUS.get(k, (k, None))[1] if _n(v) else None)
                          for k, v in by.items()]
            items_cat += [
                field("hosts online", f"{online}/{hosts}", "warn" if online < hosts else "ok" if hosts else None),
                field("hosts met SSL", f"{ssl}/{hosts}", "warn" if ssl < hosts else "ok" if hosts else None),
            ]
            sections.append({"kind": "kv", "title": "appcatalogus", "items": items_cat})
            conns = cat.get("npm_connections") or []
            sections.append({"kind": "table", "title": "NPM-koppelingen", "columns": ["naam", "aan", "NPM", "laatste sync", "status"],
                             "empty": "Geen NPM-koppeling.", "rows": [[
                                 cell(c.get("name")),
                                 cell(bool(c.get("enabled"))),
                                 cell(c.get("npm_version") or "—"),
                                 cell(since(c.get("last_sync_at"))),
                                 cell(c.get("last_sync_status") or "—",
                                      None if not c.get("enabled") or not c.get("last_sync_status")
                                      else "ok" if c.get("last_sync_status") == "ok" else "err"),
                             ] for c in conns]})

        sections.append({"kind": "kv", "title": "notities en links", "items": [
            field("notities", _n(notes.get("total"))),
            field("notities in prullenbak", _n(notes.get("in_trash"))),
            field("notitie gewijzigd", since(notes.get("last_change_at"))),
            field("links", _n(links.get("total"))),
            field("vastgepind", _n(links.get("pinned"))),
            field("collecties", _n(links.get("collections"))),
            field("tags", _n(links.get("tags"))),
            field("laatste link", since(links.get("last_added_at"))),
        ]})
        return {"sections": sections}
