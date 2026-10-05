"""OPNsense: status van de gateways (WAN online, latency, verlies) en firmware-updates."""

import re

import httpx

from .base import Integration, IntegrationError, cell, field

# "none" betekent bij OPNsense: geen probleem.
GW_OK = {"none", "online", ""}


def _num(text) -> float | None:
    m = re.search(r"[\d.]+", str(text or ""))
    return float(m.group()) if m else None


def gateway_level(status: str) -> str:
    s = (status or "").lower()
    if s in GW_OK:
        return "ok"
    return "err" if "down" in s else "warn"


class OPNsense(Integration):
    name = "opnsense"
    label = "OPNsense"
    config_help = {
        "url": "https://192.168.0.1 (of https://opnsense.jbogaert.be)",
        "gateway": "optioneel: naam van de WAN-gateway voor op de tegel (anders de eerste)",
        "insecure": "true bij een zelfondertekend certificaat",
    }
    secret_help = {
        "key": "API-key (System → Access → Users → API keys)",
        "secret": "API-secret",
    }
    call_prefix = "/api"

    async def call_auth(self) -> dict:
        return {"auth": self.auth()}

    def auth(self) -> httpx.BasicAuth:
        key, secret = self.need("key", "secret")
        return httpx.BasicAuth(key, secret)

    async def get(self, path: str):
        return await self.request("GET", "/api" + path, auth=self.auth())

    async def gateways(self) -> list[dict]:
        data = await self.get("/routes/gateway/status") or {}
        out = []
        for g in data.get("items") or []:
            status = str(g.get("status") or "")
            out.append({"name": g.get("name"), "address": g.get("address"), "monitor": g.get("monitor"),
                        "status": status, "label": g.get("status_translated") or status or "online",
                        "delay_ms": _num(g.get("delay")), "loss_pct": _num(g.get("loss")),
                        "level": gateway_level(status)})
        return out

    async def config_xml(self) -> str:
        """De volledige configuratie (recht: "Diagnostics: Configuration History" of "System: Configuration Backups")."""
        return await self.text("GET", "/api/core/backup/download/this", auth=self.auth())

    async def neighbours(self) -> list[dict]:
        """ARP-tabel plus DHCP-leases (ISC of Kea): mac, ip, fabrikant, hostnaam, interface."""
        out: dict[str, dict] = {}
        arp = await self.get("/diagnostics/interface/getArp") or []
        for a in arp if isinstance(arp, list) else arp.get("rows", []):
            mac = str(a.get("mac") or "").lower()
            if mac and mac != "(incomplete)":
                out[mac] = {"mac": mac, "ip": a.get("ip"), "vendor": a.get("manufacturer") or None,
                            "hostname": a.get("hostname") or None, "intf": a.get("intf_description") or a.get("intf")}
        for path, mac_key in (("/dhcpv4/leases/searchLease", "mac"), ("/kea/leases4/search", "hwaddr")):
            try:
                data = await self.get(path) or {}
            except IntegrationError:
                continue
            for row in data.get("rows", []) if isinstance(data, dict) else []:
                mac = str(row.get(mac_key) or "").lower()
                if not mac or str(row.get("state") or "").lower() in ("expired", "free", "backup", "released"):
                    continue
                d = out.setdefault(mac, {"mac": mac, "ip": row.get("address"), "vendor": None, "hostname": None,
                                         "intf": row.get("if_descr")})
                d["hostname"] = d["hostname"] or row.get("hostname") or None
                d["vendor"] = d["vendor"] or row.get("man") or None
                d["ip"] = d["ip"] or row.get("address")
        return list(out.values())

    async def firmware(self) -> dict:
        """Laatst gekende firmwarestatus. OPNsense controleert zelf; we starten geen nieuwe controle."""
        data = await self.get("/core/firmware/status") or {}
        pkgs = [{"n": p.get("name"), "from": p.get("current_version"), "to": p.get("new_version"), "sec": False}
                for p in (data.get("upgrade_packages") or []) if isinstance(p, dict)]
        pkgs += [{"n": p.get("name"), "from": None, "to": p.get("version"), "sec": False}
                 for p in (data.get("new_packages") or []) if isinstance(p, dict)]
        try:
            count = int(data.get("updates") or 0)
        except (TypeError, ValueError):
            count = 0
        product = data.get("product") or {}
        return {"status": data.get("status"), "message": data.get("status_msg"), "count": max(count, len(pkgs)),
                "packages": pkgs, "version": product.get("product_version") or data.get("product_version"),
                "latest": product.get("product_latest")}

    def main_gateway(self, gws: list[dict]) -> dict | None:
        want = str(self.config.get("gateway") or "").strip()
        return next((g for g in gws if g["name"] == want), None) if want else (gws[0] if gws else None)

    async def summary(self) -> list[dict]:
        gws = await self.gateways()
        g = self.main_gateway(gws)
        out = []
        if g:
            out.append(field("WAN", g["label"], g["level"]))
            if g["delay_ms"] is not None:
                out.append(field("ping", f"{g['delay_ms']:.0f} ms", "warn" if g["delay_ms"] > 100 else None))
            if g["loss_pct"]:
                out.append(field("verlies", f"{g['loss_pct']:.0f}%", "warn"))
        bad = [x for x in gws if x["level"] != "ok" and x is not g]
        if bad:
            out.append(field("gateways", f"{len(gws) - len(bad)}/{len(gws)}", "warn"))
        try:
            fw = await self.firmware()
            if fw["count"]:
                out.append(field("updates", fw["count"], "warn"))
        except Exception:  # firmware-API is optioneel (rechten)
            pass
        return out

    async def detail(self) -> dict:
        gws = await self.gateways()
        sections = [{"kind": "table", "title": "gateways", "columns": ["gateway", "status", "latency", "verlies", "monitor"],
                     "rows": [[cell(g["name"]), cell(g["label"], g["level"]),
                               cell(f"{g['delay_ms']:.1f} ms" if g["delay_ms"] is not None else "—"),
                               cell(f"{g['loss_pct']:.0f}%" if g["loss_pct"] is not None else "—",
                                    "warn" if g["loss_pct"] else None),
                               cell(g["monitor"] or "—")] for g in gws]}]
        try:
            fw = await self.firmware()
            sections.append({"kind": "kv", "title": "firmware", "items": [
                field("versie", fw["version"] or "—"),
                field("updates", fw["count"], "warn" if fw["count"] else "ok"),
                field("status", fw["message"] or fw["status"] or "—"),
            ]})
        except Exception:
            pass
        return {"sections": sections}
