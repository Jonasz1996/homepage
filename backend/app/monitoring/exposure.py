"""Blootstelling (Netwerk › publiek): per publieke naam of iemand op internet erbij kan, en wat ervoor staat.

Elk uur (worker) en met "vernieuwen" leest het dashboard, alleen lezend:
- Cloudflare (hetzelfde token als de tegel Cloudflare Tunnel): zones, DNS-records, alle tunnels met hun instellingen,
  de apps van Cloudflare Access en "Always Use HTTPS";
- Nginx Proxy Manager: proxy hosts (met hun access list, eigen nginx-config en https), access lists, redirection- en
  404-hosts;
- de nachtelijke kopie van OPNsense uit de database: welke poorten van het thuis-IP naar NPM gaan, en voor wie;
- 1.1.1.1 (DNS over HTTPS): bestaat een externe naam waar een CNAME naar wijst nog.

Per naam volgt het elke weg naar binnen (tunnel, oranje wolk, grijze wolk, en rechtstreeks via het thuis-IP als poort
443 open staat voor iedereen) en kijkt het welke login er op die weg echt voor staat: Cloudflare Access, Authentik of
een andere forward-auth, een access list van NPM. Rood = van buitenaf bereikbaar zonder login ervoor. Of de app zelf
een login heeft, ziet het dashboard niet: zo'n naam markeer je als bewust open (met 2FA).

Geen tabel, geen migratie: de uitkomst staat in AppState (exposure), met een kleine samenvatting (exposure_summary)
voor het hoofdscherm, Aandacht, de checklist en de diagnose, en de markeringen apart (exposure_intended). Geheimen
(token, wachtwoorden, de eigen nginx-config, de regels van Access, config.xml) komen nooit in de uitkomst.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import socket
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import proef
from ..config import get_settings
from ..db import ensure_state
from ..deps import notify
from ..integrations import IntegrationError, build, from_api
from ..integrations.base import Forbidden
from ..models import ApiConnection, AppState, ConfigVersion, Service
from ..security import decrypt
from . import configs, routes
from .integrationchecks import _clean

log = logging.getLogger("homepage.exposure")

STATE_KEY = "exposure"              # de volledige uitkomst
SUMMARY_KEY = "exposure_summary"    # klein, na de markeringen: hoofdscherm, Aandacht, checklist, diagnose
MARKS_KEY = "exposure_intended"     # namen die bewust open (of bewust zo) zijn
EVERY = 3600
STALE_AFTER = 3 * 3600
REFRESH_GAP = 30
RUN_TIMEOUT = 60                    # het hele ophalen (de proxy van Cloudflare wacht 100 s)
MAX_LOOKUPS = 40                    # vragen aan 1.1.1.1 per ronde (de oudste eerst), 24 uur onthouden
LOOKUP_PARALLEL = 8
LOOKUP_TIMEOUT = 3.0
LOOKUP_KEEP = 24 * 3600
FETCH_PARALLEL = 4                  # zoveel calls tegelijk naar Cloudflare per bron
MAX_NOTIFY = 5
IP_GRACE = 24 * 3600                # zo lang telt een vorig publiek IP nog als thuis
ADDR = ("A", "AAAA", "CNAME")
AUTH_PREFIXES = ("auth", "authentik", "sso")
PLACEHOLDERS = {"192.0.2.1", "100::"}       # plaatshouders van Cloudflare voor een naam zonder server (oranje wolk)
PRIVATE_TLDS = ("lan", "local", "home.arpa", "internal", "localdomain", "home", "corp")
DOH = "https://1.1.1.1/dns-query"
MARKABLE = ("open", "wildcard", "wees", "verborgen", "elders")
# Een kopie van de blokken van Cloudflare in deploy/nginx-map.conf (een test houdt ze gelijk).
CF_NETS = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32"))
# Wat niet van het internet komt: privé (RFC 1918, ULA), loopback, link-local, CGNAT (Tailscale). Bewust niet
# ipaddress.is_private: daar vallen ook de documentatieblokken onder, en die zijn hier gewoon "elders".
_INTERN = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
    "::1/128", "::/128", "fc00::/7", "fe80::/10"))

# Alles wat de gebruiker leest, in gewone taal.
WHY = {
    "open": "Van buitenaf bereikbaar zonder login ervoor (geen Cloudflare Access, Authentik of toegangslijst).",
    "open_thuis": "Via je thuis-IP komt iedereen rechtstreeks bij NPM (poort 443 staat open), en NPM laat deze naam "
                  "zonder login door{access}.",
    "open_tunnel_direct": "De tunnel gaat rechtstreeks naar {service}, langs NPM heen, zonder Cloudflare Access.",
    "open_ip_tunnel": "De toegangslijst '{al}' laat je LAN toe, en via de tunnel komt elk bezoek van je LAN: iedereen "
                      "komt binnen.",
    "open_wildcard": "Elke naam onder {zone} komt bij de wildcard-host {host} in NPM, zonder login.",
    "overname_ip": "Wijst naar {ip}, al meer dan een dag niet meer je publieke IP. Wie dat adres nu heeft, kan deze naam "
                   "bedienen. Wijzig of verwijder het record.",
    "overname_cname": "Wijst naar {target}, en die naam bestaat niet meer. Wie hem registreert, neemt deze naam over. "
                      "Verwijder het record.",
    "wees_npm": "NPM kent deze naam niet. Gebruik je hem voor iets anders (VPN, DDNS, game)? Markeer hem dan als bewust; "
                "anders opruimen in Cloudflare.",
    "wees_uit": "Staat in Cloudflare, maar de host staat uit in NPM.",
    "wees_tunnel_npm": "De tunnel stuurt deze naam naar NPM, maar NPM kent hem niet.",
    "wees_tunnel_weg": "Wijst naar tunnel {name}, en die is verwijderd. Verwijder het record.",
    "wees_tunnel_onbekend": "Tunnel niet gevonden in dit account (verwijderd, of een ander account?).",
    "wees_kapot": "Wijst naar {target}, maar die naam bestaat niet in je zone.",
    "verborgen": "Geen publiek DNS-record, maar poort 443 van je thuis-IP staat open en NPM laat deze naam zonder login "
                 "door. Wie de naam kent (bv. uit de certificaatlogboeken), komt binnen.",
    "onbekend_zone": "Valt in een zone die het Cloudflare-token niet ziet ({zone}): niet na te gaan of de naam publiek is.",
    "onbekend_tunnel": "De tunnel gaat naar {service}. Is dat NPM, dan kent NPM deze naam niet; is het een app, dan staat "
                       "hij open. Zet de naam van NPM bij npm_names (API-beheer, NPM).",
    "onbekend_access": "Niet na te gaan: Cloudflare Access is niet leesbaar (token), en verder staat er geen login voor.",
    "onbekend_npm": "NPM kent deze naam niet als proxy host, en de redirection- en 404-hosts zijn niet leesbaar.",
    "onbekend_geen_npm": "Gaat naar NPM, maar er is geen NPM-tegel of -API: niet na te gaan of er een login voor staat.",
    "wildcard": "Elke naam onder {zone} bestaat publiek en komt bij {to}.",
    "slot": "Login ervoor: {login}.",
    "dicht": "Van buitenaf dicht: {why}.",
    "intern": "Geen publiek DNS-record: alleen op je eigen netwerk.",
    "elders_ip": "Wijst naar {ip}, niet naar je thuis-IP. Is dat adres nog van jou?",
    "elders_ip_onbekend": "Wijst naar {ip}. Je publieke IP is niet gekend: niet na te gaan of dat je thuis-IP is.",
    "elders_ipv6": "IPv6 rechtstreeks naar {ip}, langs NPM heen: de login in NPM telt daar niet.",
    "elders_intern": "Publiek record met een intern adres ({ip}): werkt niet van buitenaf, maar verraadt je netwerk.",
    "elders_cname": "Wijst naar {target}, buiten je eigen zones.",
    "anker": "Anker voor {n} andere namen (CNAME): laat staan.",
    "placeholder": "Cloudflare-regel of Worker ({ip} is een plaatshouder).",
    "doorverwijzing": "NPM stuurt deze naam door.",
    "bewust": "Bewust zo: {reason}",
    "npm_leeg": "NPM gaf geen enkele proxy host: ziet de NPM-gebruiker alle items?",
    "geen_zone": "Het Cloudflare-token ziet geen zone {zone}: geef Zone → Zone → Read en Zone → DNS → Read, met Zone "
                 "Resources → {zone}.",
    "geen_dns": "Het Cloudflare-token mag de DNS-records van {zone} niet lezen: geef Zone → DNS → Read.",
    "zone_leeg": "Het Cloudflare-token ziet geen enkel record in {zone}, maar NPM heeft er {n} namen onder: geef Zone → "
                 "DNS → Read, met Zone Resources → {zone}.",
    "te_lang": "Nakijken duurde langer dan een minuut; de vorige uitkomst blijft staan.",
}
NOTE = {
    "dns_only": "Grijze wolk: je thuis-IP is zichtbaar, en Cloudflare Access werkt hier niet.",
    "no_https": "http wordt niet naar https doorgestuurd.",
    "partial": "Deels zonder login: {what}.",
    "ip_tunnel": "Een IP-slot dat je LAN toelaat, telt niet via de tunnel: cloudflared komt van je LAN.",
    "single_host": "De toegangslijst laat alleen {ip} toe. Is dat de machine van cloudflared, dan komt via de tunnel "
                   "iedereen binnen.",
    "xrealip": "IP-slot achter Cloudflare: werkt zolang NPM X-Real-IP van Cloudflare niet gelooft. Zeker: "
               "set_real_ip_from 192.0.2.255/32 bij deze host (README, Cloudflare).",
    "al_unknown": "Toegangslijst #{id} is niet leesbaar (NPM: Access Lists → View): niet na te gaan of ze via de tunnel "
                  "werkt.",
    "access_everyone": "Cloudflare Access laat iedereen met een e-mailadres toe (eenmalige code): dat is geen echte drempel.",
    "access_bypass": "Cloudflare Access staat op Bypass voor iedereen: telt niet als login.",
    "access_path": "Cloudflare Access alleen voor {path}.",
    "origin_unknown": "Niet na te gaan of NPM ook rechtstreeks via je thuis-IP bereikbaar is. Is poort 443 open voor "
                      "iedereen, dan is Cloudflare Access te omzeilen.",
    "origin_lock": "NPM vraagt het client-certificaat van Cloudflare: via je thuis-IP komt niemand binnen.",
    "jwt_presence": "NPM kijkt alleen of de Access-header er is, niet of hij echt is: wie rechtstreeks komt, stuurt die "
                    "zelf mee.",
    "tunnel_local": "De tunnel wordt lokaal beheerd (config.yml): het dashboard gaat ervan uit dat hij naar NPM gaat.",
    "tunnel_unread": "Waar tunnel {name} deze naam heen stuurt, is niet leesbaar: het dashboard gaat ervan uit dat hij "
                     "naar NPM gaat.",
    "tunnel_guess": "De tunnel gaat naar {service}: aangenomen dat dat NPM is (Docker). Klopt het, zet die naam dan bij "
                    "npm_names.",
    "tunnel_path": "De tunnel stuurt {path} van deze naam naar {service}.",
    "ip_wissel": "Wijst nog naar je vorige IP {ip} (gewijzigd {when}): DNS nog niet bijgewerkt na de IP-wissel.",
    "ip_unknown": "Je publieke IP is niet gekend ({why}): oude IP's en records zonder host zijn niet nagekeken.",
    "lookup_unknown": "Niet na te gaan of {target} nog bestaat (geen antwoord van 1.1.1.1).",
    "other_forwards": "Je OPNsense stuurt ook {ports} door: hoort deze naam daarbij?",
    "npm_unused": "NPM heeft ook een host voor deze naam, maar het record wijst elders heen.",
    "locations": "Aparte locaties in NPM ({paths}) gaan naar een eigen doel.",
    "mark_old": "Was bewust gemarkeerd, maar er veranderde iets. Bevestig opnieuw als het zo mag.",
    "self": "Dit dashboard: Cloudflare Access of Authentik ervoor is nog beter (Netwerk › firewall).",
}
NOTE_WARN = {"dns_only", "no_https", "partial", "al_unknown", "access_everyone", "access_path", "origin_unknown",
             "tunnel_local", "tunnel_unread", "tunnel_guess", "ip_wissel", "ip_unknown", "single_host", "jwt_presence",
             "locations", "mark_old"}
ORIGIN = {
    "opnsense": "OPNsense stuurt poort {ports} van je thuis-IP door naar NPM, voor {source}.",
    "cloudflare": "OPNsense laat alleen Cloudflare door naar NPM. (Dat zijn wel alle klanten van Cloudflare: "
                  "Authenticated Origin Pulls sluit dat helemaal.)",
    "geen_doorverwijzing": "OPNsense stuurt geen poort door naar NPM: alleen de tunnel komt binnen.",
    "dns": "Er staan records naar je thuis-IP voor namen van NPM ({names}): poort 443 staat dus open. Of alleen voor "
           "Cloudflare, weet het dashboard pas met een kopie van OPNsense.",
    "ipv6": "AAAA-records wijzen rechtstreeks naar NPM ({names}).",
    "onbekend": "Geen kopie van OPNsense en geen record naar je thuis-IP: niet na te gaan of poort 443 open staat.",
}
# Rechten per laag (zie de README): zonder "run" mislukt de ronde, zonder "needed" worden namen "niet na te gaan",
# zonder "optional" ontbreekt alleen een detail.
NEEDED = {"tunnel_config": "Account → Cloudflare Tunnel → Read (instellingen van de tunnels)",
          "access_read": "Account → Access: Apps and Policies → Read",
          "npm_access_lists": "NPM: View op Access Lists",
          "npm_redirects": "NPM: View op Redirection Hosts en 404 Hosts"}
OPTIONAL = {"zone_settings": "Zone → Zone Settings → Read",
            "access_zone": "Zone → Access: Apps and Policies → Read"}

LEVELS = ("err", "warn", "info", "ok", "muted")
STATES = ("open", "overname", "wildcard", "wees", "verborgen", "onbekend", "slot", "dicht", "elders", "doorverwijzing",
          "intern", "bewust")


# --- gegevens per bron ---------------------------------------------------------------------------------------------

@dataclass
class CfData:
    """Eén Cloudflare-bron (dezelfde account en hetzelfde token maar één keer)."""
    label: str
    zones: list[dict] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    tunnels: list[dict] = field(default_factory=list)
    configs: dict[str, dict | None] = field(default_factory=dict)
    apps: list[dict] = field(default_factory=list)
    https: dict[str, bool | None] = field(default_factory=dict)
    rights: dict[str, bool | None] = field(default_factory=dict)
    error: str | None = None


@dataclass
class NpmData:
    """Eén NPM (hetzelfde adres met dezelfde gebruiker maar één keer)."""
    label: str
    ip: str | None = None
    names: set[str] = field(default_factory=set)
    ipv6: set[str] = field(default_factory=set)
    proxy: list[dict] = field(default_factory=list)
    redirects: list[dict] | None = None
    dead: list[dict] | None = None
    lists: dict[int, dict] | None = None
    rights: dict[str, bool | None] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Ctx:
    ip_known: bool = False
    ip_why: str | None = None
    public_ip: str | None = None
    home_ips: set[str] = field(default_factory=set)       # het publieke IP + vorige IP's van minder dan een dag
    recent: dict[str, str] = field(default_factory=dict)  # vorig IP → tot wanneer (nog binnen de dag)
    old_ips: set[str] = field(default_factory=set)        # vorige IP's van langer dan een dag geleden
    npm_lan: set[str] = field(default_factory=set)        # de LAN-adressen van NPM
    npm_names: set[str] = field(default_factory=set)
    npm_ipv6: set[str] = field(default_factory=set)
    dashboard_ip: str | None = None
    auth_hosts: set[str] = field(default_factory=set)
    resolved: dict[str, list[str] | None] = field(default_factory=dict)
    lookups: dict[str, dict] = field(default_factory=dict)
    forwards: dict | None = None


# --- kleine hulpjes ------------------------------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ip(text) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    return routes._is_ip(str(text or "")) if text else None


def _net(text) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _intern_net(n) -> bool:
    return n is not None and any(n.version == x.version and n.subnet_of(x) for x in _INTERN)


def _intern(ip) -> bool:
    return ip is not None and (ip.is_multicast or _intern_net(ipaddress.ip_network(ip)))


def _in_cf(text) -> bool:
    n = _net(text)
    return n is not None and any(n.version == c.version and n.subnet_of(c) for c in CF_NETS)


def _local(value) -> str:
    dt = value if isinstance(value, datetime) else routes._at(value)
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%d/%m %H:%M") if dt else "?"


def _zone_guess(names) -> str | None:
    """De meest voorkomende zone (laatste twee labels) van een lijst namen, bv. jbogaert.be."""
    c = Counter(".".join(n.split(".")[-2:]) for n in names if n.count(".") >= 1 and not _ip(n) and not n.startswith("*."))
    return c.most_common(1)[0][0] if c else None


def _under(name: str, zone: str) -> bool:
    return name == zone or name.endswith("." + zone)


def _list(items, n: int = 3) -> str:
    items = list(items)
    return ", ".join(items[:n]) + (" …" if len(items) > n else "")


# --- OPNsense: welke poorten van het thuis-IP waarheen gaan --------------------------------------------------------

_WAN_ADDR = {"dhcp", "pppoe", "dhcp6"}
_NAT_SKIP = ("source", "snat", "outbound", "onetoone", "one_to_one", "npt")
_PORTS = {"http": 80, "https": 443}


def _t(el, *paths: str) -> str | None:
    for p in paths:
        x = el.find(p)
        if x is not None:
            return (x.text or "").strip()
    return None


def _off(el, *paths: str) -> bool:
    """Staat dit element uit (<disabled>1</disabled> of een leeg <disabled/>)?"""
    for p in paths:
        x = el.find(p)
        if x is not None and (x.text or "1").strip() not in ("0", ""):
            return True
        if x is not None and (x.text or "") == "" and p.endswith("disabled"):
            return True
    return False


def _port_range(value: str | None, aliases: dict) -> tuple[int, int] | None:
    v = (value or "").strip().lower()
    if not v:
        return None
    if v in _PORTS:
        return _PORTS[v], _PORTS[v]
    a = aliases.get(value.strip())
    if a is not None:
        v = (re.split(r"[\s,]+", a["content"].strip()) or [""])[0]
    m = re.fullmatch(r"(\d{1,5})(?:[-:](\d{1,5}))?", v)
    if not m:
        return None
    lo = int(m[1])
    return lo, int(m[2] or lo)


def _alias_ips(name: str, aliases: dict, depth: int = 0) -> list[str]:
    a = aliases.get(name)
    if a is None or depth > 3:
        return [name] if _ip(name) else []
    out = []
    for e in re.split(r"[\s,]+", a["content"]):
        if e:
            out += _alias_ips(e, aliases, depth + 1) if e in aliases else [e] if _ip(e) else []
    return out


def _from_cf(src: str, aliases: dict, depth: int = 0) -> bool:
    """Komt deze bron alleen van Cloudflare (een alias met de lijst van Cloudflare, of alleen hun blokken)?"""
    if not src or src.lower() in ("any", "(self)") or depth > 3:
        return False
    a = aliases.get(src)
    if a is None:
        return _in_cf(src)
    if "cloudflare.com/ips" in f"{a['url']} {a['content']}".lower():
        return True
    if a["type"] in ("geoip", "asn", "dynipv6host", "mac", "external", "authgroup"):
        return False
    entries = [e for e in re.split(r"[\s,]+", a["content"]) if e]
    return bool(entries) and all(_from_cf(e, aliases, depth + 1) if e in aliases else _in_cf(e) for e in entries)


def wan_forwards(xml: str, size: int) -> dict:
    """De poortdoorverwijzingen op een WAN-interface uit config.xml: {status ok|onbekend, why, rules}. Alleen de velden
    van de doorverwijzing blijven over; de rest van de configuratie (wachtwoorden, sleutels) niet."""
    if size >= configs.MAX_SIZE:
        return {"status": "onbekend", "why": "de kopie is afgekapt (te groot)", "rules": []}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {"status": "onbekend", "why": "de kopie is geen leesbare config.xml", "rules": []}
    wan = {"wan"}
    for el in root.findall("interfaces/*"):
        if ((_t(el, "ipaddr") or "").lower() in _WAN_ADDR or (_t(el, "ipaddrv6") or "").lower() in _WAN_ADDR
                or _t(el, "gateway")):
            wan.add(el.tag.lower())
    aliases: dict[str, dict] = {}
    for a in root.iter("alias"):
        name = _t(a, "name")
        if name:
            aliases[name] = {"type": (_t(a, "type") or "").lower(), "url": _t(a, "url") or "",
                             "content": _t(a, "content", "address") or ""}

    raw = []  # (interface, protocol, extern, doel, lokale poort, bron, omgekeerd, omschrijving)
    nat = root.find("nat")
    for r in nat.findall("rule") if nat is not None else []:
        if _off(r, "disabled") or _off(r, "nordr"):
            continue
        src = r.find("source")
        frm = "any" if src is None or src.find("any") is not None else (_t(src, "network", "address") or "any")
        raw.append((_t(r, "interface"), _t(r, "protocol"), _t(r, "destination/port"), _t(r, "target"),
                    _t(r, "local-port"), frm, src is not None and src.find("not") is not None, _t(r, "descr")))
    mvc = root.find("OPNsense/Firewall")
    found_mvc = False
    for sec in list(mvc) if mvc is not None else []:
        tag = sec.tag.lower()
        if "nat" not in tag or any(s in tag for s in _NAT_SKIP):
            continue
        for r in sec.iter("rule"):
            found_mvc = True
            if _t(r, "enabled") == "0" or _off(r, "disabled"):
                continue
            raw.append((_t(r, "interface"), _t(r, "protocol"),
                        _t(r, "destination/port", "destination_port", "dst_port"),
                        _t(r, "target", "redirect_target_ip", "target_ip"),
                        _t(r, "local-port", "local_port", "target_port"),
                        _t(r, "source/network", "source_net", "source/address") or "any",
                        (_t(r, "source/not", "source_not") or "0") == "1", _t(r, "descr", "description")))
    if nat is None and not found_mvc:
        return {"status": "onbekend", "why": "geen NAT-instellingen gevonden: formaat onbekend", "rules": []}
    rules = []
    for iface, proto, ext, target, local, frm, inverted, descr in raw:
        ifaces = [x.strip().lower() for x in (iface or "").split(",") if x.strip()]
        if not any(i in wan for i in ifaces):
            continue
        if not target:
            return {"status": "onbekend", "why": "regel zonder doel: formaat onbekend", "rules": []}
        ext_range = _port_range(ext, aliases)
        to = _port_range(local, aliases) or ext_range
        if to and ext_range and to[0] == to[1] and ext_range[1] > ext_range[0]:
            to = (to[0], to[0] + ext_range[1] - ext_range[0])
        rule = {"iface": ",".join(ifaces), "proto": (proto or "any").lower(), "ext": ext or "any",
                "to_ip": ", ".join(_alias_ips(target, aliases) or [target]), "to_port": to[0] if to else None,
                "from": ("!" if inverted else "") + (frm or "any"),
                "from_cf": not inverted and _from_cf(frm or "any", aliases), "descr": (descr or "")[:80]}
        if to and to[1] != to[0]:
            rule["to_last"] = to[1]
        rules.append(rule)
    return {"status": "ok", "why": None, "rules": rules}


def _npm_ports(rule: dict) -> list[int]:
    lo = rule.get("to_port")
    if lo is None:
        return []
    hi = rule.get("to_last") or lo
    return [p for p in (80, 443) if lo <= p <= hi]


def _to_npm(rule: dict, npm_lan: set[str]) -> bool:
    return bool(_npm_ports(rule)) and any(ip in npm_lan for ip in str(rule.get("to_ip") or "").split(", "))


def origin_state(fw: dict | None, home_hits, v6_hits, npm_lan: set[str]) -> dict:
    """Kan iemand Cloudflare overslaan en rechtstreeks via het thuis-IP bij NPM? open True, False of None (niet na te
    gaan), met de basis waarop en een zin uitleg."""
    if v6_hits:
        return {"open": True, "basis": "ipv6", "text": ORIGIN["ipv6"].format(names=_list(sorted(v6_hits)))}
    if fw and fw.get("status") == "ok" and npm_lan:
        hits = [r for r in fw.get("rules") or [] if _to_npm(r, npm_lan)]
        bad = [r for r in hits if not r.get("from_cf")]
        if bad:
            ports = sorted({p for r in bad for p in _npm_ports(r)})
            frm = sorted({str(r.get("from") or "any") for r in bad})
            source = ("iedereen (van: any)" if "any" in frm
                      else f"meer dan alleen Cloudflare (van: {', '.join(frm)})")
            return {"open": True, "basis": "opnsense",
                    "text": ORIGIN["opnsense"].format(ports=" en ".join(map(str, ports)), source=source)}
        if hits:
            return {"open": False, "basis": "cloudflare", "text": ORIGIN["cloudflare"]}
        return {"open": False, "basis": "geen_doorverwijzing", "text": ORIGIN["geen_doorverwijzing"]}
    if home_hits:
        return {"open": True, "basis": "dns", "text": ORIGIN["dns"].format(names=_list(sorted(home_hits)))}
    return {"open": None, "basis": "onbekend", "text": ORIGIN["onbekend"]}


# --- NPM: wat er voor een host staat -------------------------------------------------------------------------------

_AUTH_REQUEST = re.compile(r"\bauth_request\s+([^;\s]+)\s*;")
_AUTH_BASIC = re.compile(r"\bauth_basic\s+([^;]+);")
_ALLOW = re.compile(r"\ballow\s+([^;\s]+)\s*;")
_DENY_ALL = re.compile(r"\bdeny\s+all\s*;")
_VERIFY = re.compile(r"\bssl_verify_client\s+on\s*;")
_JWT = re.compile(r"\$http_cf_access_jwt_assertion", re.I)
_REALIP = re.compile(r"\bset_real_ip_from\s+192\.0\.2\.255(?:/32)?\s*;")
_OFF_LOCATION = re.compile(r"location\s+([^{]+?)\s*\{[^{}]*\bauth_(?:request|basic)\s+off\s*;", re.S)
_OFF = re.compile(r"\bauth_(?:request|basic)\s+off\s*;")


def login_in_config(text: str | None) -> dict:
    """Wat de eigen nginx-config (Advanced in NPM) aan login doet. De tekst zelf blijft hier: alleen de vlaggen gaan
    verder. login: Authentik, Authelia, forward-auth of een wachtwoord; partial: paden met auth_* off; allows: een
    eigen IP-lijst (allow ... met deny all); origin_lock: ssl_verify_client on (alleen wie het certificaat van
    Cloudflare heeft); jwt_presence: kijkt alleen óf de Access-header er is (na te maken, dus geen login)."""
    t = routes._COMMENT.sub("", str(text or ""))
    low = t.lower()
    login = None
    if any(m[1].lower() != "off" for m in _AUTH_REQUEST.finditer(t)):
        login = ("Authentik" if "authentik" in low else "Authelia" if "authelia" in low else "forward-auth")
    elif any(m[1].strip().lower() != "off" for m in _AUTH_BASIC.finditer(t)):
        login = "wachtwoord (eigen nginx-config)"
    partial = [m[1].strip() for m in _OFF_LOCATION.finditer(t)]
    if not partial and _OFF.search(t):
        partial = ["een deel van de site"]
    return {"login": login, "partial": partial,
            "allows": [m[1] for m in _ALLOW.finditer(t)] if _DENY_ALL.search(t) else [],
            "origin_lock": bool(_VERIFY.search(t)), "jwt_presence": bool(_JWT.search(t)) and login is None,
            "realip": bool(_REALIP.search(t))}


def _single_host(address: str) -> str | None:
    n = _net(address)
    return str(n.network_address) if n is not None and n.num_addresses == 1 else None


def list_guard(al: dict | None, path: str, *, al_id=None, npm_ip: str | None = None, realip: bool = False) -> dict:
    """Wat een access list van NPM doet op deze weg (tunnel, proxied, dns-only of thuis): {login, closed, notes,
    ip_tunnel}. NPM zet "deny all" achter de regels: met regels is het dus een lijst van wie mag.
    Via de tunnel komt elk bezoek van cloudflared, dus van je LAN: een lijst die je LAN toelaat, houdt daar niemand
    tegen. Via Cloudflare (oranje wolk) of rechtstreeks ziet NPM het adres van Cloudflare of van de bezoeker."""
    out = {"login": None, "closed": None, "notes": [], "ip_tunnel": None}
    if al is None:
        if al_id:
            out["login"] = f"toegangslijst #{al_id}"
            if path == "tunnel":
                out["notes"].append(("al_unknown", {"id": al_id}))
        return out
    name = al.get("name") or f"#{al.get('id')}"
    clients = [c for c in al.get("clients") or [] if isinstance(c, dict)]
    allows = [c.get("address", "") for c in clients if c.get("directive") == "allow"]
    password = f"wachtwoord (toegangslijst '{name}')" if int(al.get("users") or 0) else None
    # Wat het IP-deel doet op deze weg: "door" (houdt niemand tegen), "dicht" of "login" (een publieke IP-lijst).
    ip, ip_why = "door", None
    if clients:
        if any(a.lower() in ("all", "0.0.0.0/0", "::/0") for a in allows):
            ip = "door"
        elif not allows:
            ip, ip_why = "dicht", f"toegangslijst '{name}' laat niemand toe"
        elif all(_intern_net(_net(a)) for a in allows):
            single = _single_host(allows[0]) if len(allows) == 1 else None
            sip = _ip(single)
            if path == "tunnel":
                if (single and single != npm_ip and sip is not None and not sip.is_loopback
                        and sip not in routes._DOCKER):
                    ip, ip_why = "dicht", f"toegangslijst '{name}' laat alleen {single} toe"
                    out["notes"].append(("single_host", {"ip": single}))
                else:
                    ip = "door"
                    out["notes"].append(("ip_tunnel", {}))
                    out["ip_tunnel"] = name
            else:
                ip, ip_why = "dicht", f"toegangslijst '{name}' laat alleen je eigen netwerk toe"
                if path == "proxied" and not realip:
                    out["notes"].append(("xrealip", {}))
        else:
            ip = "login"
    if not password:
        if ip == "dicht":
            out["closed"] = ip_why
        elif ip == "login":
            out["login"] = f"IP-lijst (toegangslijst '{name}')"
    elif not clients:
        out["login"] = password
    elif al.get("satisfy_any"):
        # Eén van de twee volstaat: laat het IP-deel iedereen door, dan is het wachtwoord geen drempel.
        if ip != "door":
            out["login"] = password
    elif ip == "dicht":
        out["closed"] = ip_why
    else:
        out["login"] = password
    if out["login"] or out["closed"]:
        out["ip_tunnel"] = None
    return out


# --- DNS -----------------------------------------------------------------------------------------------------------

def _nodes(by_name: dict) -> set[str]:
    """Elke naam die in DNS bestaat, ook de tussenliggende (een naam met records eronder bestaat, zonder records)."""
    out = set()
    for n in by_name:
        parts = n.split(".")
        out.update(".".join(parts[i:]) for i in range(len(parts)))
    return out


def public_records(name: str, by_name: dict, nodes: set[str] | None = None) -> tuple[list[dict], str | None]:
    """(A/AAAA/CNAME-records voor deze naam, de wildcard waar ze vandaan komen of None). Bestaat de naam (ook met
    alleen TXT of MX, of met namen eronder), dan geldt geen wildcard (RFC 4592); anders de wildcard bij de langste
    naam erboven die bestaat."""
    nodes = nodes if nodes is not None else _nodes(by_name)
    if name in nodes:
        return [r for r in by_name.get(name) or [] if r["type"] in ADDR], None
    labels = name.split(".")
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        wc = "*." + parent
        if wc in by_name:
            return [r for r in by_name[wc] if r["type"] in ADDR], wc
        if parent in nodes:
            break
    return [], None


def _own(name: str, zones) -> bool:
    return any(_under(name, z) for z in zones)


def follow(record: dict, by_name: dict, zones, lookups: dict, home_ips: set[str]) -> dict:
    """Waar een record uitkomt: een tunnel, een IP, een externe naam, of kapot (een eigen naam die niet bestaat of een
    lus). CNAME's binnen je zones volgt het (hoogstens 5 stappen)."""
    if record["type"] in ("A", "AAAA"):
        return {"kind": "ip", "ip": record["content"], "via": None}
    target, seen = record["content"], {record["name"]}
    for _ in range(5):
        if target.endswith(".cfargotunnel.com"):
            return {"kind": "tunnel", "id": target.split(".", 1)[0]}
        if not _own(target, zones):
            hit = lookups.get(target) or {}
            home = next((a for a in hit.get("a") or [] if a in home_ips), None)
            if home:
                return {"kind": "ip", "ip": home, "via": target}
            return {"kind": "extern", "target": target}
        if target in seen:
            return {"kind": "kapot", "target": target}
        seen.add(target)
        recs, _ = public_records(target, by_name)
        recs = sorted(recs, key=lambda r: ("A", "CNAME", "AAAA").index(r["type"]))
        if not recs:
            return {"kind": "kapot", "target": target}
        if recs[0]["type"] != "CNAME":
            return {"kind": "ip", "ip": recs[0]["content"], "via": target}
        target = recs[0]["content"]
    return {"kind": "kapot", "target": target}


def anchors(by_name: dict, zones) -> dict[str, int]:
    """Per eigen naam: hoeveel CNAME's ernaar wijzen (een DDNS-anker zoals home.jbogaert.be is nooit een wees)."""
    c: Counter = Counter()
    for recs in by_name.values():
        for r in recs:
            if r["type"] == "CNAME" and _own(r["content"], zones) and not r["content"].endswith(".cfargotunnel.com"):
                c[r["content"]] += 1
    return dict(c)


# --- tunnels en Cloudflare Access ----------------------------------------------------------------------------------

def tunnel_target(service: str | None, ctx: Ctx) -> str:
    """Waar een regel van de tunnel heen gaat: "npm", "npm?" (waarschijnlijk NPM, een gok), "direct" (langs NPM heen)
    of "dicht" (een vaste foutcode). NPM luistert op 80 en 443: een andere poort (ook 81, het beheer van NPM) is een
    app."""
    s = (service or "").strip()
    if s.startswith("http_status:"):
        return "dicht"
    try:
        u = urlsplit(s)
        scheme = u.scheme.lower()
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        return "direct"
    host = (u.hostname or "").lower()
    if scheme not in ("http", "https") or port not in (80, 443) or not host:
        return "direct"
    if host in ctx.npm_names:
        return "npm"
    ip = _ip(host)
    addrs = [str(ip)] if ip else ctx.resolved.get(host) or []
    if any(a in ctx.npm_lan for a in addrs):
        return "npm"
    if not addrs:
        return "npm?"  # een naam die het dashboard niet kan opzoeken (meestal een Docker-naam bij cloudflared)
    if any((x := _ip(a)) is not None and (x.is_loopback or x in routes._DOCKER) for a in addrs):
        return "npm?"
    return "direct"


def ingress_for(cfg: dict | None, name: str) -> list[dict]:
    """De regels van de tunnel die deze naam raken: eerst die met een pad, dan de eerste zonder (of de vangregel)."""
    out = []
    for rule in (cfg or {}).get("ingress") or []:
        host = rule.get("hostname")
        if host and not (host == name or (host.startswith("*.") and name.endswith(host[1:]))):
            continue
        out.append(rule)
        if not rule.get("path"):
            break
    return out


def access_for(apps: list[dict], name: str) -> tuple[str | None, str | None, str | None, list[str]]:
    """(oordeel, app, pad, zwakkere paden) van de app van Cloudflare Access die deze naam het best raakt: een exacte
    naam boven een wildcard, zonder pad boven met pad. Zwakkere paden: andere apps op een pad van deze naam die minder
    vragen (bv. Bypass voor /api)."""
    best, weaker = None, []
    rank = ("bypass", "everyone", "public_mail", "login")
    for app in apps:
        for h in app.get("hosts") or []:
            host = h.get("host") or ""
            exact = host == name
            if not (exact or (host.startswith("*.") and name.endswith(host[1:]))):
                continue
            key = (0 if exact else 1, 1 if h.get("path") else 0)
            if best is None or key < best[0]:
                best = (key, app, h.get("path"))
            if h.get("path"):
                weaker.append((h["path"], app["verdict"]))
    if best is None:
        return None, None, None, []
    verdict = best[1]["verdict"]
    weak = sorted({p for p, v in weaker if rank.index(v) < rank.index(verdict) and p != best[2]})
    return verdict, best[1].get("name") or "app", best[2], weak


# --- de analyse ------------------------------------------------------------------------------------------------------

def _res(path: str | None, state: str, level: str, why_key: str, **kw) -> dict:
    params = kw.pop("params", {})
    return {"path": path, "state": state, "level": level, "why_key": why_key,
            "why": kw.pop("why", None) or WHY[why_key].format(**params), "login": kw.pop("login", []),
            "notes": kw.pop("notes", []), "undecided": kw.pop("undecided", False), "https": kw.pop("https", None),
            "npm_key": kw.pop("npm_key", None), "tunnel": kw.pop("tunnel", None)}


def _level(r: dict) -> str:
    if r["state"] in ("slot", "dicht") and any(k in NOTE_WARN for k, _ in r["notes"]):
        return "warn"
    return r["level"]


def _worst(results: list[dict]) -> dict:
    return min(results, key=lambda r: (LEVELS.index(_level(r)), STATES.index(r["state"])))


def row_sig(state: str, path: str | None, targets: list[str], npm_target: str | None, service: str | None) -> str:
    """Vingerafdruk van wat een markering "bewust" geldig houdt: verandert dit, dan vervalt ze."""
    raw = "|".join([state, path or "", ",".join(sorted(targets)), npm_target or "", service or ""])
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _merge_rights(parts: list[dict]) -> dict:
    out: dict[str, bool | None] = {}
    for p in parts:
        for k, v in p.items():
            cur = out.get(k, True)
            out[k] = False if (v is False or cur is False) else None if (v is None or cur is None) else True
    return out


class _Analysis:
    def __init__(self, cfs: list[CfData], npms: list[NpmData], ctx: Ctx) -> None:
        self.ctx = ctx
        self.by_name: dict[str, list[dict]] = {}
        self.zones: dict[str, bool | None] = {}
        self.tunnels: dict[str, dict] = {}
        self.configs: dict[str, dict | None] = {}
        self.apps: list[dict] = []
        seen = set()
        for cf in cfs:
            for z in cf.zones:
                https = cf.https.get(z["name"])
                cur = self.zones.get(z["name"])
                self.zones[z["name"]] = True if (https or cur) else cur if cur is not None else https
            for r in cf.records:
                k = (r["name"], r["type"], r["content"], r["proxied"])
                if k not in seen:
                    seen.add(k)
                    self.by_name.setdefault(r["name"], []).append(r)
            for t in cf.tunnels:
                self.tunnels.setdefault(t["id"], t)
            for tid, cfg in cf.configs.items():
                if self.configs.get(tid) is None:
                    self.configs[tid] = cfg
            self.apps += cf.apps
        self.rights = _merge_rights([cf.rights for cf in cfs] + [n.rights for n in npms])
        self.has_npm = bool(npms)
        self.nodes = _nodes(self.by_name)
        self.anchors = anchors(self.by_name, self.zones)
        # NPM: naam (ook *.domein) → wat elke NPM ermee doet. Een naam in twee NPM's: de zwakste telt.
        self.hosts: dict[str, list[dict]] = {}
        for n in npms:
            for h in n.proxy:
                if isinstance(h, dict):
                    e = _proxy_entry(h, n)
                    for name in routes._names(h):
                        self.hosts.setdefault(name, []).append(e)
            for kind, items in (("redirect", n.redirects), ("dead", n.dead)):
                for h in items or []:
                    if isinstance(h, dict) and h.get("enabled", True):
                        for name in routes._names(h):
                            self.hosts.setdefault(name, []).append({"kind": kind, "enabled": True, "source": n.label})
        self.table = routes.Table({"hosts": {k: {"key": k} for k in self.hosts}})
        self.auth_targets = {e["target_hp"] for k, es in self.hosts.items() for e in es
                             if e["kind"] == "proxy" and e.get("target_hp") and self._is_auth(k)}
        home_hits, v6_hits = set(), set()
        for name in self.hosts:
            for r in public_records(name, self.by_name, self.nodes)[0]:
                f = follow(r, self.by_name, self.zones, ctx.lookups, ctx.home_ips)
                if f["kind"] == "ip" and f["ip"] in ctx.home_ips:
                    home_hits.add(name)
                if f["kind"] == "ip" and f["ip"] in ctx.npm_ipv6:
                    v6_hits.add(name)
        self.origin = origin_state(ctx.forwards, home_hits, v6_hits, ctx.npm_lan)
        fw = ctx.forwards or {}
        self.other_forwards = sorted({f"{r['ext']}/{r['proto']}" if r.get("proto") not in (None, "", "tcp") else str(r["ext"])
                                      for r in fw.get("rules") or [] if not _to_npm(r, ctx.npm_lan)})

    def _is_auth(self, name: str) -> bool:
        return name in self.ctx.auth_hosts or name.split(".")[0] in AUTH_PREFIXES

    def entries(self, name: str) -> tuple[str | None, list[dict]]:
        hit = self.table.entry(name)
        return (hit["key"], self.hosts[hit["key"]]) if hit else (None, [])

    def zone_of(self, name: str) -> str | None:
        return max((z for z in self.zones if _under(name, z)), key=len, default=None)

    # --- NPM op één weg ---

    def npm_eval(self, name: str, key: str | None, entries: list[dict], path: str, rule: dict | None = None) -> dict:
        if not self.has_npm:
            return _res(path, "onbekend", "warn", "onbekend_geen_npm", undecided=True)
        if not entries:
            return _res(path, "wees", "warn", "wees_tunnel_npm" if path == "tunnel" else "wees_npm")
        return _worst([self._entry_eval(name, key, e, path, rule) for e in entries])

    def _entry_eval(self, name: str, key: str | None, e: dict, path: str, rule: dict | None) -> dict:
        if e["kind"] == "redirect":
            return _res(path, "doorverwijzing", "muted", "doorverwijzing", npm_key=key)
        if e["kind"] == "dead":
            return _res(path, "dicht", "ok", "dicht", params={"why": "NPM antwoordt met een 404-pagina (404-host)"},
                        npm_key=key)
        if not e["enabled"]:
            return _res(path, "wees", "warn", "wees_uit", npm_key=key)
        ctx, cfg = self.ctx, e["config"]
        via_cf = path in ("proxied", "tunnel")
        notes: list[tuple[str, dict]] = []
        npm_login, closed, ip_tunnel = [], [], None
        guards = []
        if e["access_list_id"]:
            guards.append(list_guard(e["al"], path, al_id=e["access_list_id"], npm_ip=e["npm_ip"], realip=cfg["realip"]))
        if cfg["allows"]:
            own = {"name": "eigen nginx-config", "users": 0, "satisfy_any": False,
                   "clients": [{"directive": "allow", "address": a} for a in cfg["allows"]]}
            guards.append(list_guard(own, path, npm_ip=e["npm_ip"], realip=cfg["realip"]))
        for g in guards:
            notes += g["notes"]
            if g["login"]:
                npm_login.append(g["login"])
            if g["closed"]:
                closed.append(g["closed"])
            ip_tunnel = ip_tunnel or g["ip_tunnel"]
        if cfg["login"]:
            npm_login.append(cfg["login"])
        if e.get("target_hp") and e["target_hp"] in self.auth_targets:
            npm_login.append("Authentik zelf" if key and self._is_auth(key) else "Authentik (proxy)")
        if ctx.dashboard_ip and e.get("target_host") == ctx.dashboard_ip:
            npm_login.append("eigen login met 2FA (dit dashboard)")
            notes.append(("self", {}))
        if path in ("dns-only", "thuis") and cfg["origin_lock"]:
            closed.append("NPM vraagt het client-certificaat van Cloudflare")
            notes.append(("origin_lock", {}))
        cf_login = []
        if via_cf:
            verdict, app, apath, weaker = access_for(self.apps, name)
            if apath:
                notes.append(("access_path", {"path": apath}))
            elif verdict == "login":
                cf_login.append(f"Cloudflare Access ({app})")
            elif verdict in ("everyone", "public_mail"):
                cf_login.append("Cloudflare Access (iedereen met een e-mailadres)")
                notes.append(("access_everyone", {}))
            elif verdict == "bypass":
                notes.append(("access_bypass", {}))
            if weaker and (cf_login or npm_login):
                notes.append(("partial", {"what": f"{', '.join(weaker)} (Cloudflare Access)"}))
            if rule and rule.get("access_required"):
                cf_login.append("Cloudflare Access (tunnel)")
        login = npm_login + cf_login
        common = {"npm_key": key, "notes": notes}
        if (via_cf and self.rights.get("access_read") is False and not npm_login and not closed
                and not (rule and rule.get("access_required"))):
            return _res(path, "onbekend", "warn", "onbekend_access", undecided=True, **common)
        if closed:
            r = _res(path, "dicht", "ok", "dicht", params={"why": closed[0]}, login=login, **common)
        elif login:
            r = _res(path, "slot", "ok", "slot", params={"login": ", ".join(login)}, login=login, **common)
            if self.origin["open"] is None and via_cf and not npm_login:
                notes.append(("origin_unknown", {}))
        elif ip_tunnel:
            r = _res(path, "open", "err", "open_ip_tunnel", params={"al": ip_tunnel}, **common)
        elif path == "thuis":
            access = ": Cloudflare Access is zo te omzeilen" if access_for(self.apps, name)[0] else ""
            r = _res(path, "open", "err", "open_thuis", params={"access": access}, **common)
        else:
            r = _res(path, "open", "err", "open", **common)
        if path == "dns-only":
            notes.append(("dns_only", {}))
        zone_https = self.zones.get(self.zone_of(name) or "")
        r["https"] = bool(e["forced"] or (via_cf and zone_https))
        if r["state"] != "dicht" and path != "thuis" and not e["forced"]:
            if not via_cf or zone_https is False:
                notes.append(("no_https", {}))
        if cfg["partial"] and npm_login:
            notes.append(("partial", {"what": ", ".join(cfg["partial"])}))
        if e["locations"]:
            notes.append(("locations", {"paths": ", ".join(e["locations"][:4])}))
        if cfg["jwt_presence"]:
            notes.append(("jwt_presence", {}))
        return r

    # --- tunnel zonder NPM ---

    def direct_eval(self, name: str, rule: dict) -> dict:
        verdict, app, apath, _ = access_for(self.apps, name)
        login, notes = [], []
        if apath:
            notes.append(("access_path", {"path": apath}))
        elif verdict == "login":
            login.append(f"Cloudflare Access ({app})")
        elif verdict in ("everyone", "public_mail"):
            login.append("Cloudflare Access (iedereen met een e-mailadres)")
            notes.append(("access_everyone", {}))
        elif verdict == "bypass":
            notes.append(("access_bypass", {}))
        if rule.get("access_required"):
            login.append("Cloudflare Access (tunnel)")
        if login:
            return _res("tunnel", "slot", "ok", "slot", params={"login": ", ".join(login)}, login=login, notes=notes)
        if self.rights.get("access_read") is False:
            return _res("tunnel", "onbekend", "warn", "onbekend_access", undecided=True, notes=notes)
        return _res("tunnel", "open", "err", "open_tunnel_direct", params={"service": rule.get("service")}, notes=notes)

    # --- één record ---

    def record(self, name: str, rec: dict, key: str | None, entries: list[dict]) -> tuple[dict, dict, str]:
        """(uitkomst, regel voor de DNS-lijst, doel voor de vingerafdruk)."""
        ctx = self.ctx
        f = follow(rec, self.by_name, self.zones, ctx.lookups, ctx.home_ips)
        path = "proxied" if rec["proxied"] else "dns-only"
        dns = {"type": rec["type"], "to": rec["content"], "proxied": rec["proxied"], "wildcard": None,
               "zone": self.zone_of(rec["name"])}
        if f["kind"] == "tunnel":
            dns["proxied"] = True
            t = self.tunnels.get(f["id"])
            if t is None:
                dns["to"] = f"tunnel {f['id'][:8]}… (onbekend)"
                return _res("tunnel", "wees", "warn", "wees_tunnel_onbekend"), dns, f"tunnel:{f['id']}"
            dns["to"] = f"tunnel {t['name']}" + (" (verwijderd)" if t["deleted"] else "")
            if t["deleted"]:
                return _res("tunnel", "wees", "warn", "wees_tunnel_weg", params={"name": t["name"]}), dns, f"tunnel:{t['id']}"
            return self.tunnel(name, t, key, entries), dns, f"tunnel:{t['id']}"
        if f["kind"] == "extern":
            dns["to"] = f["target"]
            status = (ctx.lookups.get(f["target"]) or {}).get("status")
            if status == "nx":
                return _res("extern", "overname", "err", "overname_cname", params={"target": f["target"]}), dns, f["target"]
            if status == "ok":
                return _res("extern", "elders", "muted", "elders_cname", params={"target": f["target"]}), dns, f["target"]
            return (_res("extern", "elders", "info", "elders_cname", params={"target": f["target"]}, undecided=True,
                         notes=[("lookup_unknown", {"target": f["target"]})]), dns, f["target"])
        if f["kind"] == "kapot":
            dns["to"] = f"{f['target']} (bestaat niet)"
            return _res(path, "wees", "warn", "wees_kapot", params={"target": f["target"]}), dns, f["target"]
        addr = f["ip"]
        ip = _ip(addr)
        v6 = ip is not None and ip.version == 6
        home = not v6 and addr in ctx.home_ips
        via = f" (via {f['via']})" if f.get("via") and f["via"] != rec["content"] else ""
        sig_to = "thuis" if home else addr
        if addr in ctx.recent:
            dns["to"] = f"thuis-IP (vorig, tot {_local(ctx.recent[addr])})"
        elif home:
            dns["to"] = "thuis-IP"
        elif addr in ctx.old_ips:
            dns["to"] = f"{addr} (vroeger thuis-IP)"
        elif v6 and addr in ctx.npm_ipv6:
            dns["to"] = f"{addr} (NPM)"
        elif addr in PLACEHOLDERS or _intern(ip):
            dns["to"] = f"{addr} (intern)" if not (addr in PLACEHOLDERS and rec["proxied"]) else f"{addr} (plaatshouder)"
        else:
            dns["to"] = addr
        if f.get("via") and rec["type"] == "CNAME":
            dns["to"] = f"{f['via']} (→ {dns['to']})"
        if addr in PLACEHOLDERS:
            if rec["proxied"]:
                return _res(path, "elders", "muted", "placeholder", params={"ip": addr}), dns, sig_to
            return _res(path, "elders", "info", "elders_intern", params={"ip": addr}), dns, sig_to
        if ip is None or _intern(ip):
            return _res(path, "elders", "info", "elders_intern", params={"ip": addr}), dns, sig_to
        if not ctx.ip_known:
            note = [("ip_unknown", {"why": ctx.ip_why or "nog niet gekend"})]
            if not v6 and entries:
                r = self.npm_eval(name, key, entries, path)
                r["notes"] = r["notes"] + note
                r["undecided"] = True
                return r, dns, addr
            if v6 and addr in ctx.npm_ipv6:
                return self.npm_eval(name, key, entries, path), dns, sig_to
            return (_res(path, "elders", "info", "elders_ip_onbekend", params={"ip": addr}, notes=note, undecided=True),
                    dns, addr)
        if not v6 and addr in ctx.old_ips:
            return _res(path, "overname", "err", "overname_ip", params={"ip": addr}), dns, addr
        if home or (v6 and addr in ctx.npm_ipv6):
            if entries or not self.has_npm:
                r = self.npm_eval(name, key, entries, path)
                if addr in ctx.recent:
                    r["notes"] = r["notes"] + [("ip_wissel", {"ip": addr, "when": _local(ctx.recent[addr])})]
                return r, dns, sig_to
            if name in self.anchors:
                return _res(path, "elders", "muted", "anker", params={"n": self.anchors[name]}), dns, sig_to
            if self.rights.get("npm_redirects") is False:
                return _res(path, "onbekend", "warn", "onbekend_npm"), dns, sig_to
            notes = [("other_forwards", {"ports": ", ".join(self.other_forwards)})] if self.other_forwards else []
            return _res(path, "wees", "warn", "wees_npm", notes=notes), dns, sig_to
        if v6 and entries:
            return _res(path, "elders", "warn", "elders_ipv6", params={"ip": addr + via}), dns, addr
        notes = [("npm_unused", {})] if entries else []
        return _res(path, "elders", "info", "elders_ip", params={"ip": addr}, notes=notes), dns, addr

    def tunnel(self, name: str, t: dict, key: str | None, entries: list[dict]) -> dict:
        cfg = self.configs.get(t["id"])
        info = {"name": t["name"], "service": None, "target": "npm",
                "managed": None if cfg is None else cfg.get("source")}
        if cfg is None or cfg.get("source") != "cloudflare":
            r = self.npm_eval(name, key, entries, "tunnel")
            r["notes"] = r["notes"] + [("tunnel_local", {}) if cfg is not None else ("tunnel_unread", {"name": t["name"]})]
            r["tunnel"] = info
            return r
        rules = ingress_for(cfg, name)
        if not rules:
            r = _res("tunnel", "dicht", "ok", "dicht", params={"why": "de tunnel heeft geen regel voor deze naam"})
            r["tunnel"] = {**info, "target": "dicht"}
            return r
        results = []
        for rule in rules:
            target = tunnel_target(rule.get("service"), self.ctx)
            service = rule.get("service") or "?"
            if target == "dicht":
                r = _res("tunnel", "dicht", "ok", "dicht", params={"why": f"de tunnel antwoordt met {service}"})
            elif target == "npm":
                r = self.npm_eval(name, key, entries, "tunnel", rule)
            elif target == "npm?":
                if entries:
                    r = self.npm_eval(name, key, entries, "tunnel", rule)
                    r["notes"] = r["notes"] + [("tunnel_guess", {"service": service})]
                else:
                    r = _res("tunnel", "onbekend", "warn", "onbekend_tunnel", params={"service": service})
            else:
                r = self.direct_eval(name, rule)
            if rule.get("path"):
                r["notes"] = r["notes"] + [("tunnel_path", {"path": rule["path"], "service": service})]
            r["tunnel"] = {**info, "service": service, "target": target}
            results.append(r)
        worst = _worst(results)
        worst["notes"] = [n for r in results for n in r["notes"]]
        return worst

    def thuis(self, name: str, key: str | None, entries: list[dict]) -> dict | None:
        """De weg langs Cloudflare heen: wie poort 443 van je thuis-IP bereikt, kiest de naam zelf (SNI)."""
        if self.origin["open"] is not True:
            return None
        proxies = [e for e in entries if e["kind"] == "proxy" and e["enabled"]]
        return self.npm_eval(name, key, proxies, "thuis") if proxies else None

    # --- één naam ---

    def row(self, name: str) -> dict:
        key, entries = self.entries(name)
        zone = self.zone_of(name)
        results: list[dict] = []
        dns: list[dict] = []
        sig_to: list[str] = []
        if zone is None:
            thuis = self.thuis(name, key, entries)
            if _ip(name) or any(_under(name, t) for t in PRIVATE_TLDS):
                if thuis:
                    results.append(thuis)
                results.insert(0, _res(None, "verborgen", "warn", "verborgen") if thuis and thuis["state"] == "open"
                               else _res(None, "intern", "muted", "intern"))
            else:
                results = [_res(None, "onbekend", "warn", "onbekend_zone",
                                params={"zone": ".".join(name.split(".")[-2:])})] + ([thuis] if thuis else [])
            return self.finish(name, results, results[0], dns, sig_to, entries)
        recs, wc = public_records(name, self.by_name, self.nodes)
        for rec in recs:
            r, d, s = self.record(name, rec, key, entries)
            d["wildcard"] = wc
            results.append(r)
            dns.append(d)
            sig_to.append(s)
        if not any(r["path"] == "dns-only" and r.get("npm_key") for r in results) and not name.startswith("*."):
            thuis = self.thuis(name, key, entries)
            if thuis:
                results.append(thuis)
        if not recs:
            thuis = next((r for r in results if r["path"] == "thuis"), None)
            top = (_res(None, "verborgen", "warn", "verborgen") if thuis and thuis["state"] == "open"
                   else _res(None, "intern", "muted", "intern"))
            return self.finish(name, [top, *results], top, dns, sig_to, entries)
        worst = _worst(results)
        if name.startswith("*.") and wc is None and worst["state"] != "overname":
            open_wc = next((r for r in results if r["state"] == "open" and (r.get("npm_key") or "").startswith("*.")), None)
            if open_wc:
                worst = {**open_wc, "state": "wildcard", "level": "err", "why_key": "open_wildcard",
                         "why": WHY["open_wildcard"].format(zone=name[2:], host=open_wc["npm_key"])}
            else:
                worst = {**worst, "state": "wildcard", "level": "warn", "why_key": "wildcard",
                         "why": WHY["wildcard"].format(zone=name[2:], to=dns[0]["to"] if dns else "?")}
        return self.finish(name, results, worst, dns, sig_to, entries)

    def finish(self, name: str, results: list[dict], worst: dict, dns: list[dict], sig_to: list[str],
               entries: list[dict]) -> dict:
        notes, seen = [], set()
        for r in results:
            for k, params in r["notes"]:
                text = NOTE[k].format(**params)
                if (k, text) not in seen:
                    seen.add((k, text))
                    notes.append({"key": k, "level": "warn" if k in NOTE_WARN else "info", "text": text})
        level = worst["level"]
        if worst["state"] in ("slot", "dicht") and any(n["level"] == "warn" for n in notes):
            level = "warn"
        tunnel = next((r["tunnel"] for r in results if r.get("tunnel")), None)
        e = next((x for x in entries if x["kind"] == "proxy"), entries[0] if entries else None)
        npm = None
        if e is not None:
            al = None
            if e.get("access_list_id"):
                a = e.get("al")
                al = ({"name": a.get("name"), "users": int(a.get("users") or 0), "satisfy_any": bool(a.get("satisfy_any")),
                       "rules": [f"{c.get('directive')} {c.get('address')}" for c in a.get("clients") or []][:10]}
                      if a is not None else {"id": e["access_list_id"], "readable": False})
            npm = {"source": e.get("source"), "kind": e["kind"], "enabled": e["enabled"], "target": e.get("target"),
                   "cert": e.get("cert"), "forced": e.get("forced"), "hsts": e.get("hsts"), "access_list": al,
                   "config_login": (e.get("config") or {}).get("login")}
        row = {"name": name, "level": level, "state": worst["state"], "base": worst["state"], "why": worst["why"],
               "why_key": worst["why_key"], "path": worst["path"],
               "paths": [{"path": r["path"], "state": r["state"], "login": r["login"]} for r in results if r["path"]],
               "dns": dns, "tunnel": tunnel, "npm": npm, "login": worst["login"],
               "https_forced": worst.get("https"), "notes": notes, "undecided": any(r["undecided"] for r in results),
               "intended": None}
        row["sig"] = row_sig(row["base"], row["path"], sig_to, npm["target"] if npm else None,
                             tunnel["service"] if tunnel else None)
        return row


def _proxy_entry(h: dict, src: NpmData) -> dict:
    """Een proxy host van NPM, met alleen wat de analyse nodig heeft (de eigen nginx-config wordt vlaggen)."""
    fwd = routes._forward(h)
    locs = [loc for loc in h.get("locations") or [] if isinstance(loc, dict)]
    cfg = login_in_config("\n".join([str(h.get("advanced_config") or "")]
                                    + [str(loc.get("advanced_config") or "") for loc in locs]))
    off = [str(loc.get("path")) for loc in locs if _OFF.search(routes._COMMENT.sub("", str(loc.get("advanced_config") or "")))]
    if off:
        cfg["partial"] = sorted(set([p for p in cfg["partial"] if p != "een deel van de site"] + off))
    al_id = h.get("access_list_id") or None
    al = src.lists.get(al_id) if (al_id and src.lists is not None) else None
    return {"kind": "proxy", "enabled": bool(h.get("enabled", True)),
            "target": f"{fwd[0]}://{routes.endpoint(fwd[1], fwd[2])}" if fwd else None,
            "target_host": fwd[1] if fwd else None, "target_hp": f"{fwd[1]}:{fwd[2]}" if fwd else None,
            "access_list_id": al_id, "al": al, "forced": bool(h.get("ssl_forced") and h.get("certificate_id")),
            "cert": bool(h.get("certificate_id")), "hsts": bool(h.get("hsts_enabled")), "config": cfg,
            "locations": [str(loc.get("path")) for loc in locs if loc.get("path")], "source": src.label, "npm_ip": src.ip}


def analyse(cfs: list[CfData], npms: list[NpmData], ctx: Ctx) -> dict:
    """De uitkomst per naam (rows) en hoe het binnenkomt (inbound), zonder markeringen."""
    a = _Analysis(cfs, npms, ctx)
    names = set(a.hosts) | {n for n, recs in a.by_name.items() if any(r["type"] in ADDR for r in recs)}
    rows = [a.row(n) for n in names]
    rows.sort(key=lambda r: (min(LEVELS.index(r["level"]), 2), r["name"]))
    per_tunnel: Counter = Counter()
    paths: Counter = Counter()
    for r in rows:
        for kind in {("tunnel" if d["to"].startswith("tunnel ") else "proxied" if d["proxied"] else "dns-only")
                     for d in r["dns"]}:
            paths[kind] += 1
        for name in {d["to"].split(" ")[1] for d in r["dns"] if d["to"].startswith("tunnel ")}:
            per_tunnel[name] += 1
    tunnels = [{"name": t["name"], "status": t["status"], "deleted": t["deleted"], "names": per_tunnel.get(t["name"], 0),
                "managed": (a.configs.get(tid) or {}).get("source") if a.configs.get(tid) else None}
               for tid, t in sorted(a.tunnels.items(), key=lambda x: x[1]["name"])
               if not t["deleted"] or per_tunnel.get(t["name"])]
    inbound = {"public_ip": ctx.public_ip, "ip_known": ctx.ip_known, "ip_why": ctx.ip_why,
               "recent": [{"ip": ip, "until": until} for ip, until in sorted(ctx.recent.items())],
               "origin": a.origin, "forwards": ctx.forwards, "tunnels": tunnels,
               "paths": {k: paths.get(k, 0) for k in ("tunnel", "proxied", "dns-only")}}
    return {"rows": rows, "inbound": inbound, "rights": a.rights, "counts": _counts(rows)}


# --- markeringen, alarmen, samenvatting ----------------------------------------------------------------------------

def _counts(rows: list[dict]) -> dict:
    c = {"err": 0, "warn": 0, "ok": 0, "bewust": 0, "rest": 0}
    for r in rows:
        if r["state"] == "bewust":
            c["bewust"] += 1
        elif r["level"] in ("err", "warn", "ok"):
            c[r["level"]] += 1
        else:
            c["rest"] += 1
    return c


def apply_marks(value: dict, marks: dict) -> dict:
    """De uitkomst met de markeringen "bewust": een rij met dezelfde vingerafdruk wordt "bewust" (info), een
    markering op een rij die intussen veranderde, geeft een opmerking."""
    rows = []
    for r in value.get("rows") or []:
        m = marks.get(r["name"])
        if m and r["base"] in MARKABLE:
            if m.get("sig") == r["sig"]:
                r = {**r, "state": "bewust", "level": "info", "why_key": "bewust",
                     "why": WHY["bewust"].format(reason=m.get("reason") or ""),
                     "intended": {k: m.get(k) for k in ("reason", "by", "at")}}
            else:
                r = {**r, "notes": [*r["notes"], {"key": "mark_old", "level": "warn", "text": NOTE["mark_old"]}]}
        rows.append(r)
    rows.sort(key=lambda r: (min(LEVELS.index(r["level"]), 2), r["name"]))
    return {**value, "rows": rows, "counts": _counts(rows)}


def alarms(value: dict) -> dict[str, dict]:
    """Elke rode naam (na de markeringen): {"pub:<naam>": {title, why, kind}}."""
    out = {}
    for r in value.get("rows") or []:
        if r["level"] != "err":
            continue
        if r["state"] == "overname":
            title, kind = f"{r['name']}: DNS-record kan overgenomen worden", r.get("why_key") or "overname_ip"
        else:
            title, kind = f"{r['name']} staat open van buitenaf", "wildcard" if r["state"] == "wildcard" else "open"
        out[f"pub:{r['name']}"] = {"title": title, "why": r["why"], "kind": kind}
    return out


def summary(value: dict, now: datetime) -> dict:
    """Klein, voor het hoofdscherm, Aandacht, de checklist en de diagnose (value: al met de markeringen)."""
    rows = value.get("rows") or []
    rights = value.get("rights") or {}
    origin = ((value.get("inbound") or {}).get("origin") or {})
    o = origin.get("open")
    return {"at": value.get("at"), "checked_at": value.get("checked_at"), "errors": list(value.get("errors") or [])[:3],
            "missing": [k for k in NEEDED if rights.get(k) is False],
            "optional": [k for k in OPTIONAL if rights.get(k) is False],
            "never": not value.get("at"), "counts": value.get("counts") or _counts(rows),
            "public": sum(1 for r in rows if r.get("dns")),
            "origin": None if not origin else "open" if o is True else "onbekend" if o is None
            else "cf" if origin.get("basis") == "cloudflare" else "dicht",
            "origin_text": origin.get("text"),
            "red": [{"name": r["name"], "state": r["state"], "why": r["why"], "sig": r["sig"]}
                    for r in rows if r["level"] == "err"][:60],
            "wees": [r["name"] for r in rows if r["state"] == "wees"][:20],
            "wees_n": sum(1 for r in rows if r["state"] == "wees"),
            "verborgen_n": sum(1 for r in rows if r["state"] == "verborgen"),
            "wildcards": [{"name": r["name"], "why": r["why"], "sig": r["sig"]}
                          for r in rows if r["state"] == "wildcard" and r["level"] != "err"][:10],
            "made": now.isoformat()}


# --- ophalen --------------------------------------------------------------------------------------------------------

def _secret_hash(secrets: dict) -> str:
    return hashlib.sha256(json.dumps(secrets or {}, sort_keys=True).encode()).hexdigest()[:12]


async def sources(db: AsyncSession, kind: str, clients) -> list[tuple[str, object]]:
    """(naam, integratie) per bron van deze soort: elke API uit API-beheer en elke tegel zonder API. Dezelfde account
    of gebruiker met dezelfde sleutels maar één keer (zoals security.proxmox_tokens)."""
    todo = []
    for a in (await db.execute(select(ApiConnection).where(ApiConnection.kind == kind).order_by(ApiConnection.id))).scalars():
        try:
            todo.append((a.name, from_api(a, {}, clients)))
        except IntegrationError:
            continue
    for s in (await db.execute(select(Service).where(Service.type == kind, Service.api_id.is_(None))
                               .order_by(Service.id))).scalars():
        try:
            todo.append((s.name, build(s, clients)))
        except IntegrationError:
            continue
    seen, out = set(), []
    for name, integ in todo:
        k = (integ.base, str(integ.config.get("account") or integ.secrets.get("username") or ""),
             _secret_hash(integ.secrets))
        if k not in seen:
            seen.add(k)
            out.append((name, integ))
    return out


async def has_source(db: AsyncSession, kind: str) -> bool:
    q = select(or_(exists().where(Service.type == kind), exists().where(ApiConnection.kind == kind)))
    return bool((await db.execute(q)).scalar())


def _err(label: str, e: Exception, integ) -> str:
    return _clean(f"{label}: {e}", integ.secrets)[:300]


async def fetch_cf(label: str, integ, npm_names: set[str]) -> CfData:
    """Alles van één Cloudflare-bron. Alleen zones, records en de lijst met tunnels kunnen de ronde laten mislukken
    (error); zonder de andere rechten wordt een naam "niet na te gaan" of ontbreekt een detail (rights)."""
    d = CfData(label=label)
    want = integ.zone_names()
    guess = want[0] if want else _zone_guess(npm_names) or "?"
    try:
        zones = await integ.zones()
    except Forbidden:
        d.error = WHY["geen_zone"].format(zone=guess)
        return d
    except IntegrationError as e:
        d.error = _err(label, e, integ)
        return d
    names = {z["name"] for z in zones}
    missing = [z for z in want if z not in names]
    if not zones or missing:
        d.error = WHY["geen_zone"].format(zone=missing[0] if missing else guess)
        return d
    d.zones, d.rights["zone_read"] = zones, True
    sem = asyncio.Semaphore(FETCH_PARALLEL)

    async def limited(coro):
        async with sem:
            return await coro

    got = await asyncio.gather(*(limited(integ.dns_records(z["id"])) for z in zones), return_exceptions=True)
    for z, recs in zip(zones, got):
        if isinstance(recs, Forbidden):
            d.error = WHY["geen_dns"].format(zone=z["name"])
            return d
        if isinstance(recs, IntegrationError):
            d.error = _err(label, recs, integ)
            return d
        if isinstance(recs, BaseException):
            raise recs
        under = [n for n in npm_names if _under(n, z["name"])]
        if not recs and under:
            d.error = WHY["zone_leeg"].format(zone=z["name"], n=len(under))
            return d
        d.records += recs
    d.rights["dns_read"] = True
    try:
        d.tunnels = await integ.tunnel_list()
    except IntegrationError as e:
        d.error = _err(label, e, integ)
        return d
    d.rights["tunnel_read"] = True

    async def config(t: dict) -> None:
        try:
            d.configs[t["id"]] = await limited(integ.tunnel_config(t["id"]))
            d.rights.setdefault("tunnel_config", True)
        except Forbidden:
            d.configs[t["id"]] = None
            d.rights["tunnel_config"] = False
        except IntegrationError:
            d.configs[t["id"]] = None
            if d.rights.get("tunnel_config") is not False:
                d.rights["tunnel_config"] = None

    async def apps() -> None:
        try:
            d.apps += await limited(integ.access_apps())
            d.rights["access_read"] = True
        except Forbidden:
            d.rights["access_read"] = False
        except IntegrationError:
            d.rights["access_read"] = None

    async def zone_apps(z: dict) -> None:
        try:
            d.apps += await limited(integ.access_apps(z["id"]))
            d.rights.setdefault("access_zone", True)
        except Forbidden:
            d.rights["access_zone"] = False
        except IntegrationError:
            if d.rights.get("access_zone") is not False:
                d.rights["access_zone"] = None

    async def https(z: dict) -> None:
        try:
            d.https[z["name"]] = await limited(integ.always_https(z["id"]))
            d.rights.setdefault("zone_settings", True)
        except Forbidden:
            d.https[z["name"]] = None
            d.rights["zone_settings"] = False
        except IntegrationError:
            d.https[z["name"]] = None
            if d.rights.get("zone_settings") is not False:
                d.rights["zone_settings"] = None

    await asyncio.gather(*[config(t) for t in d.tunnels if not t["deleted"]], apps(),
                         *[zone_apps(z) for z in zones], *[https(z) for z in zones])
    return d


async def fetch_npm(label: str, integ) -> NpmData:
    """Alles van één NPM. Zonder proxy hosts mislukt de ronde; zonder access lists of redirection- en 404-hosts wordt
    een naam "niet na te gaan"."""
    split = lambda v: {x.strip().lower() for x in (v.split(",") if isinstance(v, str) else v or []) if str(x).strip()}  # noqa: E731
    d = NpmData(label=label, ip=await routes._npm_ip(integ.base), names=split(integ.config.get("npm_names")),
                ipv6={str(_ip(x)) for x in split(integ.config.get("npm_ipv6")) if _ip(x)})
    try:
        hosts = await integ.proxy_hosts()
    except IntegrationError as e:
        d.error = _err(label, e, integ)
        return d
    d.proxy = [h for h in hosts if isinstance(h, dict)] if isinstance(hosts, list) else []
    try:
        d.lists = {al["id"]: al for al in await integ.access_lists()}
        d.rights["npm_access_lists"] = True
    except Forbidden:
        d.rights["npm_access_lists"] = False
    except IntegrationError:
        d.rights["npm_access_lists"] = None
    d.redirects = await routes._list(integ, "/nginx/redirection-hosts")
    d.dead = await routes._list(integ, "/nginx/dead-hosts")
    d.rights["npm_redirects"] = d.redirects is not None and d.dead is not None
    return d


async def lookup(client: httpx.AsyncClient, targets, cached: dict, now: datetime | None = None) -> dict:
    """Bestaan deze externe namen nog (DNS over HTTPS bij 1.1.1.1)? {naam: {status nx|ok|?, a, at}}. Een antwoord
    blijft 24 uur geldig; per ronde hoogstens MAX_LOOKUPS vragen (wat het langst niet gevraagd is eerst), 8 tegelijk."""
    now = now or _now()
    out, todo = {}, []
    for t in sorted(set(targets)):
        c = cached.get(t) or {}
        at = routes._at(c.get("at"))
        if c.get("status") in ("nx", "ok") and at and (now - at).total_seconds() < LOOKUP_KEEP:
            out[t] = c
        else:
            todo.append((at or datetime.min.replace(tzinfo=timezone.utc), t))
    todo.sort()
    sem = asyncio.Semaphore(LOOKUP_PARALLEL)

    async def one(t: str) -> tuple[str, dict]:
        async with sem:
            try:
                r = await asyncio.wait_for(client.get(DOH, params={"name": t, "type": "A"},
                                                      headers={"accept": "application/dns-json"}, timeout=LOOKUP_TIMEOUT),
                                           LOOKUP_TIMEOUT)
                data = r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, asyncio.TimeoutError, TimeoutError, ValueError):
                data = {}
        status = data.get("Status") if isinstance(data, dict) else None
        if status == 3:
            return t, {"status": "nx", "a": [], "at": now.isoformat()}
        if status == 0:
            a = [str(x.get("data")) for x in data.get("Answer") or [] if isinstance(x, dict) and x.get("type") == 1]
            return t, {"status": "ok", "a": a[:8], "at": now.isoformat()}
        return t, {"status": "?", "a": [], "at": None}

    asked = [t for _, t in todo[:MAX_LOOKUPS]]
    out.update(dict(await asyncio.gather(*(one(t) for t in asked))))
    for _, t in todo[MAX_LOOKUPS:]:
        out[t] = {"status": "?", "a": [], "at": (cached.get(t) or {}).get("at")}
    return out


async def resolve(hosts) -> dict[str, list[str] | None]:
    """De adressen van de namen waar een tunnel heen gaat (zoals routes._npm_ip: 3 seconden per naam)."""
    loop = asyncio.get_running_loop()

    async def one(h: str) -> tuple[str, list[str] | None]:
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(h, None, family=socket.AF_UNSPEC), 3)
        except (OSError, TimeoutError, asyncio.TimeoutError, UnicodeError):
            return h, None
        return h, sorted({i[4][0] for i in infos}) or None

    return dict(await asyncio.gather(*(one(h) for h in sorted(set(hosts)))))


async def forwards(db: AsyncSession, prev: dict | None) -> dict | None:
    """De poortdoorverwijzingen uit de nieuwste kopie van elke OPNsense. Alleen ontsleuteld als er een nieuwe kopie
    is (meestal één keer per nacht); de XML verdwijnt meteen na het lezen. None: geen kopie."""
    tiles = (await db.execute(select(Service.id, Service.name).where(Service.type == "opnsense").order_by(Service.id))).all()
    newest = []
    for sid, name in tiles:
        row = (await db.execute(select(ConfigVersion.id, ConfigVersion.ts, ConfigVersion.size)
                                .where(ConfigVersion.item == f"opnsense:{sid}")
                                .order_by(ConfigVersion.ts.desc(), ConfigVersion.id.desc()).limit(1))).first()
        if row is not None:
            newest.append((name, row))
    if not newest:
        return None
    version = ",".join(str(r.id) for _, r in newest)
    if prev and prev.get("version") == version:
        return prev
    rules, status, why = [], "ok", None
    for name, r in newest:
        v = await db.get(ConfigVersion, r.id)
        try:
            text = decrypt(v.content) if v is not None else ""
        except Exception:  # noqa: BLE001 - een kopie die niet te ontsleutelen is: niet na te gaan
            text = ""
        got = wan_forwards(text, r.size) if text else {"status": "onbekend", "why": "kopie niet te lezen", "rules": []}
        del text
        rules += got["rules"]
        if got["status"] != "ok":
            status, why = "onbekend", got["why"]
    label = ", ".join(f"{name} · kopie van {_local(r.ts)}" for name, r in newest)
    return {"version": version, "label": label, "status": status, "why": why, "rules": rules if status == "ok" else []}


async def context(db: AsyncSession, npms: list[NpmData], resolved: dict, lookups: dict, fw: dict | None,
                  now: datetime | None = None) -> Ctx:
    now = now or _now()
    s = get_settings()
    st = await db.get(AppState, "public_ip")
    v = dict(st.value or {}) if st else {}
    ip = v.get("ip")
    ctx = Ctx(resolved=resolved, lookups=lookups, forwards=fw, dashboard_ip=s.syslog_target or None)
    if v.get("error"):
        ctx.ip_why = str(v["error"])[:200]
    elif not ip:
        ctx.ip_why = "nog niet gekend" if s.public_ip_check else "publiek-IP-check staat uit"
    else:
        ctx.ip_known, ctx.public_ip = True, ip
        for h in v.get("history") or []:
            until = routes._at(h.get("until"))
            if not h.get("ip") or h["ip"] == ip:
                continue
            if until and (now - until).total_seconds() < IP_GRACE:
                ctx.recent[h["ip"]] = until.isoformat()
            else:
                ctx.old_ips.add(h["ip"])
        ctx.home_ips = {ip, *ctx.recent}
        ctx.old_ips -= ctx.home_ips
    ctx.npm_lan = {x for x in [*(n.ip for n in npms), s.npm_ip] if x}
    for n in npms:
        ctx.npm_names |= n.names
        ctx.npm_ipv6 |= n.ipv6
    oidc = await db.get(AppState, "oidc")
    issuer = str((oidc.value or {}).get("issuer") or "") if oidc else ""
    if host := (urlsplit(issuer).hostname or "").lower():
        ctx.auth_hosts.add(host)
    return ctx


# --- de ronde -------------------------------------------------------------------------------------------------------

async def run_exposure(db: AsyncSession, http) -> bool:
    """Eén ronde: alles ophalen (zonder open transactie), analyseren en bewaren met commit_result. Gebruikt door de
    worker (elk uur) en de knop "vernieuwen". Geeft terug of de uitkomst bewaard is."""
    started = _now()
    cf_src = await sources(db, "cloudflared", http)
    npm_src = await sources(db, "npm", http)
    for key in (STATE_KEY, MARKS_KEY, SUMMARY_KEY):
        await ensure_state(db, key, {})
    prev = dict((await db.get(AppState, STATE_KEY)).value or {})
    # Geen transactie open tijdens de vragen aan Cloudflare, NPM en 1.1.1.1 (zoals domains.py).
    await db.commit()
    if not cf_src:
        return await commit_result(db, started, {"at": None, "rows": [], "sources": {"cloudflare": [], "npm": []}}, [])
    errors: list[str] = []

    async def fetch() -> tuple[list[CfData], list[NpmData], dict, dict, dict | None]:
        npms = list(await asyncio.gather(*(fetch_npm(label, integ) for label, integ in npm_src)))
        names = {routes._norm(n) for d in npms for h in d.proxy for n in h.get("domain_names") or []}
        cfs = list(await asyncio.gather(*(fetch_cf(label, integ, names) for label, integ in cf_src)))
        hosts = set()
        for cf in cfs:
            for cfg in cf.configs.values():
                for rule in (cfg or {}).get("ingress") or []:
                    try:
                        h = (urlsplit(rule.get("service") or "").hostname or "").lower()
                    except ValueError:
                        h = ""
                    if h and not _ip(h):
                        hosts.add(h)
        resolved = await resolve(hosts)
        zones = {z["name"] for cf in cfs for z in cf.zones}
        targets = {r["content"] for cf in cfs for r in cf.records if r["type"] == "CNAME"
                   and not r["content"].endswith(".cfargotunnel.com") and not _own(r["content"], zones)}
        looked = await lookup(http.get(False), targets, prev.get("lookups") or {})
        fw = await forwards(db, (prev.get("inbound") or {}).get("forwards"))
        return cfs, npms, resolved, looked, fw

    try:
        cfs, npms, resolved, looked, fw = await asyncio.wait_for(fetch(), RUN_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        await db.rollback()
        return await commit_result(db, started, None, [WHY["te_lang"]])
    errors += [d.error for d in [*cfs, *npms] if d.error]
    ctx = await context(db, npms, resolved, looked, fw)
    # Een NPM zonder één proxy host terwijl er records naar het thuis-IP of een tunnel wijzen: dan ziet de gebruiker
    # van het dashboard niet alles, en zou elke naam een wees lijken.
    served = any(r["type"] == "A" and r["content"] in ctx.home_ips
                 or r["type"] == "CNAME" and r["content"].endswith(".cfargotunnel.com") for cf in cfs for r in cf.records)
    errors += [f"{d.label}: {WHY['npm_leeg']}" for d in npms if not d.error and not d.proxy and served]
    if errors:
        return await commit_result(db, started, None, errors)
    result = analyse(cfs, npms, ctx)
    result["sources"] = {"cloudflare": [{"name": d.label, "zones": [z["name"] for z in d.zones], "records": len(d.records),
                                         "tunnels": len([t for t in d.tunnels if not t["deleted"]]), "error": d.error}
                                        for d in cfs],
                         "npm": [{"name": d.label, "hosts": len(d.proxy), "error": d.error} for d in npms]}
    result["lookups"] = {k: v for k, v in looked.items() if v.get("at")}
    return await commit_result(db, started, result, [])


async def _locked(db: AsyncSession, key: str) -> AppState:
    st = await db.get(AppState, key, with_for_update=True, populate_existing=True)
    return st if st is not None else await ensure_state(db, key, {})


async def commit_result(db: AsyncSession, started: datetime, result: dict | None, errors: list[str]) -> bool:
    """Bewaren in één transactie, met de rijen op slot in een vaste volgorde (exposure, exposure_intended,
    exposure_summary). Schreef een latere ronde intussen al (de worker en de knop tegelijk), dan schrijft deze niets en
    meldt ze niets. De meldingen vergelijken met wat er nu (vergrendeld) staat: zo komt er nooit een melding dubbel."""
    st = await _locked(db, STATE_KEY)
    prev = dict(st.value or {})
    last = routes._at(prev.get("checked_at"))
    if last and last > started:
        return False
    marks = ((await _locked(db, MARKS_KEY)).value or {}).get("items") or {}
    at = started.isoformat()
    if result is None:
        value = {**prev, "checked_at": at, "errors": errors}
    elif result.get("at", "") is None:
        # Geen Cloudflare (meer): niets te tonen, en geen "niet meer open" voor alles wat rood was. De volgende ronde
        # met Cloudflare telt weer als de eerste.
        value = {**result, "checked_at": at, "errors": []}
    else:
        value = {**result, "at": at, "checked_at": at, "errors": []}
        marked = apply_marks(value, marks)
        value["alarm"] = _notify(db, prev, marked, alarms(marked))
    st.value = value
    (await _locked(db, SUMMARY_KEY)).value = summary(apply_marks(value, marks), _now())
    return True


def _notify(db: AsyncSession, prev: dict, marked: dict, new: dict[str, dict]) -> dict:
    """Meldingen voor wat rood werd en wat niet meer rood is, en het alarm dat bewaard wordt."""
    rows = {r["name"]: r for r in marked.get("rows") or []}
    old = prev.get("alarm")
    if old is None:
        # De eerste ronde: één melding als er iets rood is, niet een per naam.
        if new:
            names = [k.removeprefix("pub:") for k in new]
            n = len(names)
            notify(db, f"Netwerk › publiek: {n} {'naam' if n == 1 else 'namen'} open van buitenaf", _list(names, 5),
                   level="warn", source="blootstelling", push=False)
        return dict(new)
    alarm = dict(new)
    for k, a in old.items():
        r = rows.get(k.removeprefix("pub:"))
        if k not in new and r is not None and r.get("undecided"):
            # Deze ronde niet na te gaan (publiek IP onbekend, Access niet leesbaar, geen antwoord van 1.1.1.1): het
            # alarm blijft staan, zonder herstel en zonder nieuwe melding.
            alarm[k] = a
    fresh = [k for k in new if k not in old]
    for k in fresh[:MAX_NOTIFY]:
        notify(db, new[k]["title"], new[k]["why"], level="err", source="blootstelling", key=k)
    if len(fresh) > MAX_NOTIFY:
        rest = [k.removeprefix("pub:") for k in fresh[MAX_NOTIFY:]]
        notify(db, f"Netwerk › publiek: nog {len(rest)} namen open van buitenaf", _list(rest, 5), level="err",
               source="blootstelling")
    gone = [k for k in old if k not in alarm and (rows.get(k.removeprefix("pub:")) or {}).get("state") != "bewust"]
    for k in gone[:MAX_NOTIFY]:
        notify(db, f"{k.removeprefix('pub:')} is niet meer open", None, level="ok", source="blootstelling", key=k,
               recovers="err")
    if len(gone) > MAX_NOTIFY:
        rest = [k.removeprefix("pub:") for k in gone[MAX_NOTIFY:]]
        notify(db, f"Netwerk › publiek: nog {len(rest)} namen niet meer open", _list(rest, 5), level="ok",
               source="blootstelling", push=False)
    return alarm


async def marks_of(db: AsyncSession) -> dict:
    st = await db.get(AppState, MARKS_KEY)
    return ((st.value or {}) if st else {}).get("items") or {}


async def view(db: AsyncSession, now: datetime | None = None) -> dict:
    """Wat het tabblad publiek toont: de uitkomst met de markeringen, zonder alarm en cache."""
    now = now or _now()
    st = await db.get(AppState, STATE_KEY)
    value = apply_marks(dict(st.value or {}) if st else {}, await marks_of(db))
    for k in ("alarm", "lookups"):
        value.pop(k, None)
    at = routes._at(value.get("at"))
    return {"at": None, "checked_at": None, "errors": [], "sources": {"cloudflare": [], "npm": []}, "rights": {},
            "inbound": None, **value,
            "stale": bool(at and (now - at).total_seconds() > STALE_AFTER), "every": EVERY,
            "configured": {"cloudflare": await has_source(db, "cloudflared"), "npm": await has_source(db, "npm")}}


async def write_summary(db: AsyncSession, marks: dict) -> None:
    """De samenvatting opnieuw na een (andere) markering. De aanroeper heeft exposure en exposure_intended al op slot."""
    st = await db.get(AppState, STATE_KEY)
    (await _locked(db, SUMMARY_KEY)).value = summary(apply_marks(dict(st.value or {}) if st else {}, marks), _now())


async def plan_calls(db: AsyncSession, clients) -> dict:
    """"welke calls?": elke vraag die een ronde stelt, als proef (er wordt niets verstuurd)."""
    cf = await sources(db, "cloudflared", clients)
    npm = await sources(db, "npm", clients)
    fw = (await db.execute(select(Service.id).where(Service.type == "opnsense"))).first() is not None
    steps = []
    for label, integ in cf:
        who = f"API-token uit {label}"
        acc = str(integ.config.get("account") or "<account-id>")
        m = "Cloudflare-API (api.cloudflare.com)"
        steps += [
            proef.step(m, "api", "GET /zones?status=active&per_page=50&page=1", who=who, note="zones van het token"),
            proef.step(m, "api", "GET /zones/{zone}/dns_records?per_page=500&page=1", who=who, when="per zone"),
            proef.step(m, "api", f"GET /accounts/{acc}/cfd_tunnel?per_page=100&page=1", who=who),
            proef.step(m, "api", f"GET /accounts/{acc}/cfd_tunnel/{{tunnel}}/configurations", who=who,
                       when="per tunnel die niet verwijderd is"),
            proef.step(m, "api", f"GET /accounts/{acc}/access/apps?per_page=100&page=1", who=who,
                       note="plus …/apps/{app}/policies voor een app zonder regels in de lijst"),
            proef.step(m, "api", "GET /zones/{zone}/access/apps?per_page=100&page=1", who=who, when="per zone"),
            proef.step(m, "api", "GET /zones/{zone}/settings/always_use_https", who=who, when="per zone"),
        ]
    for label, integ in npm:
        m, who = f"NPM ({integ.base})", f"NPM-gebruiker {integ.secrets.get('username') or '?'}"
        steps += [
            proef.step(m, "api", "POST /api/tokens", who=who, when="zonder geldige aanmelding van het laatste uur"),
            proef.step(m, "api", "GET /api/nginx/proxy-hosts", who=who),
            proef.step(m, "api", "GET /api/nginx/access-lists?expand=items,clients", who=who),
            proef.step(m, "api", "GET /api/nginx/redirection-hosts", who=who),
            proef.step(m, "api", "GET /api/nginx/dead-hosts", who=who),
        ]
    if cf:
        steps += [
            proef.step("1.1.1.1 (DNS over HTTPS)", "api", "GET https://1.1.1.1/dns-query?name={doel}&type=A",
                       when=f"voor CNAME's naar een naam buiten je zones: hoogstens {MAX_LOOKUPS} per ronde, een "
                            "antwoord blijft 24 uur geldig"),
            proef.step("DNS van de container (getaddrinfo)", "dashboard", "getaddrinfo({naam van de dienst})",
                       when="voor een tunnel naar een naam in plaats van een IP"),
            proef.step("database: kopie van OPNsense", "dashboard",
                       "nieuwste config.xml (opnsense:<tegel>) lezen, alleen de poortdoorverwijzingen",
                       when="alleen als er sinds de vorige ronde een nieuwe kopie is"),
        ]
    checks = [proef.check("Cloudflare-API ingesteld", bool(cf), None if cf else "Zet je token in API-beheer"),
              proef.check("NPM ingesteld", bool(npm)),
              proef.check("nachtelijke kopie van OPNsense", True if fw else None,
                          None if fw else "zonder kopie leidt het dashboard af uit de DNS-records")]
    return proef.plan("Netwerk › publiek: wat het dashboard opvraagt", steps, checks=checks,
                      after=["Niets verandert in Cloudflare, NPM of OPNsense: het dashboard leest alleen.",
                             "De uitkomst staat in Netwerk › publiek; een naam die nieuw rood is, geeft een melding."])
