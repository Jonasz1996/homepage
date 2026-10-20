"""Zabbix: hosts, beschikbaarheid, open problemen en de belangrijkste waarden (CPU, RAM, schijf, uptime, ping).

De API is JSON-RPC op /api_jsonrpc.php met een API-token (Zabbix 5.4 en nieuwer: Gebruikers → API-tokens).
Vanaf 6.4 gaat het token mee als Bearer-header; oudere versies willen het in het verzoek ("auth"): dat gebeurt
vanzelf als de header geweigerd wordt.
"""

import time
from typing import Any

from .base import Integration, IntegrationError, cell, field

# Ernst in Zabbix: 0 niet ingedeeld, 1 info, 2 waarschuwing, 3 gemiddeld, 4 hoog, 5 ramp.
SEVERITY = {0: "niet ingedeeld", 1: "info", 2: "waarschuwing", 3: "gemiddeld", 4: "hoog", 5: "ramp"}
# Vanaf deze ernst kleurt een host rood.
RED_FROM = 3
# Waarden die het mini dashboard toont, in deze volgorde: (label, sleutels in Zabbix, formaat).
METRICS = (
    ("cpu", ("system.cpu.util", "system.cpu.util[,,avg1]", "system.cpu.util[]"), "percent"),
    ("ram", ("vm.memory.utilization", "vm.memory.util"), "percent"),
    ("schijf /", ("vfs.fs.dependent.size[/,pused]", "vfs.fs.size[/,pused]"), "percent"),
    ("uptime", ("system.uptime", "system.net.uptime"), "uptime"),
    ("ping", ("icmppingsec",), "ms"),
    ("bereikbaar", ("icmpping", "agent.ping", "zabbix[host,agent,available]"), "bool"),
)
_auth_in_body: dict[str, bool] = {}


def level(severity: int | None) -> str | None:
    if severity is None:
        return None
    return "err" if severity >= RED_FROM else "warn" if severity >= 2 else None


class Zabbix(Integration):
    name = "zabbix"
    label = "Zabbix"
    config_help = {"url": "https://zabbix.jbogaert.be (de webinterface, zonder /api_jsonrpc.php)"}
    secret_help = {"token": "API-token (Gebruikers → API-tokens, met een gebruiker die alle hosts mag lezen)"}

    async def call_auth(self) -> dict:
        return {"headers": {"Authorization": f"Bearer {self.need('token')[0]}"}}

    async def rpc(self, method: str, params: Any) -> Any:
        token = self.need("token")[0]
        body: dict = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        old = _auth_in_body.get(self.base, False)
        if old:
            body["auth"] = token
        data = await self.request("POST", "/api_jsonrpc.php", json=body,
                                  headers={} if old else {"Authorization": f"Bearer {token}"})
        err = (data or {}).get("error") if isinstance(data, dict) else None
        if err and not old and "auth" in f"{err.get('message')} {err.get('data')}".lower():
            # Zabbix voor 6.4: het token hoort in het verzoek zelf. Lukt dat ook niet, dan was het de header niet.
            _auth_in_body[self.base] = True
            try:
                return await self.rpc(method, params)
            except IntegrationError:
                _auth_in_body.pop(self.base, None)
        if err:
            raise IntegrationError(f"Zabbix: {err.get('data') or err.get('message')}"[:200])
        if not isinstance(data, dict) or "result" not in data:
            raise IntegrationError("Geen antwoord van de Zabbix-API: klopt de url (zonder /api_jsonrpc.php)?")
        return data["result"]

    async def hosts(self) -> list[dict]:
        """Bewaakte hosts met hun adressen en of ze bereikbaar zijn."""
        rows = await self.rpc("host.get", {
            "output": ["hostid", "host", "name", "status", "available", "active_available"],
            "selectInterfaces": ["ip", "dns", "available", "type"],
            "filter": {"status": 0},
        })
        out = []
        for h in rows:
            ifs = h.get("interfaces") or []
            avail = [str(i.get("available")) for i in ifs] + [str(h.get("available") or ""), str(h.get("active_available") or "")]
            out.append({"id": str(h["hostid"]), "host": h.get("host") or "", "name": h.get("name") or h.get("host") or "",
                        "ips": sorted({i["ip"] for i in ifs if i.get("ip") and i["ip"] != "127.0.0.1"}),
                        "dns": sorted({i["dns"].lower() for i in ifs if i.get("dns")}),
                        # 1 = bereikbaar, 2 = onbereikbaar; alleen onbereikbaar als niets bereikbaar is.
                        "down": "2" in avail and "1" not in avail})
        return out

    async def problems(self, hostids: list[str] | None = None) -> list[dict]:
        """Triggers die nu in probleem staan (werkt op Zabbix 5 tot 7)."""
        params: dict = {"output": ["triggerid", "description", "priority", "lastchange"], "filter": {"value": 1},
                        "monitored": True, "skipDependent": True, "expandDescription": True,
                        "selectHosts": ["hostid", "name"], "sortfield": "priority", "sortorder": "DESC"}
        if hostids:
            params["hostids"] = hostids
        out = []
        for t in await self.rpc("trigger.get", params):
            for h in t.get("hosts") or []:
                out.append({"host_id": str(h["hostid"]), "host": h.get("name"), "name": t.get("description"),
                            "severity": int(t.get("priority") or 0), "since": int(t.get("lastchange") or 0)})
        return out

    async def metrics(self, hostids: list[str]) -> dict[str, list[dict]]:
        """Per host de bekende waarden uit METRICS, met een uurgemiddelde over 24 u voor CPU en RAM."""
        keys = [k for _, ks, _ in METRICS for k in ks]
        items = await self.rpc("item.get", {"output": ["itemid", "hostid", "key_", "lastvalue", "lastclock", "units"],
                                            "hostids": hostids, "filter": {"key_": keys}, "monitored": True})
        by_host: dict[str, dict[str, dict]] = {}
        for it in items:
            by_host.setdefault(str(it["hostid"]), {})[it["key_"]] = it
        out: dict[str, list[dict]] = {}
        trend_ids = []
        for hid in hostids:
            have = by_host.get(hid, {})
            rows = []
            for label, ks, fmt in METRICS:
                it = next((have[k] for k in ks if k in have), None)
                if it is None or it.get("lastclock") in (None, "0"):
                    continue
                try:
                    v = float(it["lastvalue"])
                except (TypeError, ValueError):
                    continue
                rows.append({"label": label, "value": v, "format": fmt, "item": str(it["itemid"]), "points": []})
                if label in ("cpu", "ram"):
                    trend_ids.append(str(it["itemid"]))
            out[hid] = rows
        if trend_ids:
            now = int(time.time())
            try:
                trends = await self.rpc("trend.get", {"output": ["itemid", "clock", "value_avg"], "itemids": trend_ids,
                                                      "time_from": now - 86400, "time_till": now})
            except IntegrationError:
                trends = []
            pts: dict[str, list] = {}
            for t in trends:
                pts.setdefault(str(t["itemid"]), []).append((int(t["clock"]), round(float(t["value_avg"]), 1)))
            for rows in out.values():
                for r in rows:
                    r["points"] = sorted(pts.get(r["item"], []))
        return out

    async def summary(self) -> list[dict]:
        hosts = await self.hosts()
        probs = await self.problems()
        red = sum(1 for p in probs if p["severity"] >= RED_FROM)
        down = sum(1 for h in hosts if h["down"])
        return [field("hosts", len(hosts)), field("problemen", len(probs), "err" if red else "warn" if probs else "ok"),
                field("onbereikbaar", down, "err" if down else "ok")]

    async def detail(self) -> dict:
        hosts = await self.hosts()
        probs = await self.problems()
        now = time.time()
        return {"sections": [
            {"kind": "kv", "title": "overzicht", "items": await self.summary()},
            {"kind": "table", "title": "open problemen", "columns": ["host", "probleem", "ernst", "sinds"],
             "rows": [[cell(p["host"]), cell(p["name"]), cell(SEVERITY.get(p["severity"], "?"), level(p["severity"])),
                       cell({"age": now - p["since"]})] for p in probs[:100]]},
            {"kind": "table", "title": "onbereikbare hosts", "columns": ["host", "adres"],
             "rows": [[cell(h["name"], "err"), cell(", ".join(h["ips"] + h["dns"]))] for h in hosts if h["down"]]},
        ]}
