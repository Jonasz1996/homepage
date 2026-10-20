"""Proxmox Backup Server: opslag per datastore, laatste back-up per VM/CT en mislukte taken."""

import time

from .base import Integration, ago, cell, field, level_for, pct

DAY = 86400


def backup_level(age: float | None) -> str:
    if age is None:
        return "err"
    return "ok" if age < 1.1 * DAY else "warn" if age < 3 * DAY else "err"


class ProxmoxBackupServer(Integration):
    name = "proxmoxbackupserver"
    label = "Proxmox Backup Server"
    config_help = {
        "url": "https://pbs.jbogaert.be (of https://192.168.0.60:8007)",
        "datastore": "optioneel: alleen deze datastore",
        "insecure": "true bij een zelfondertekend certificaat",
    }
    secret_help = {
        "username": "token-id, bv. homepage@pbs!dashboard (rechten: Datastore.Audit, Sys.Audit)",
        "password": "geheim van het token",
    }

    def headers(self) -> dict:
        user, secret = self.need("username", "password")
        return {"Authorization": f"PBSAPIToken={user}:{secret}"}

    async def get(self, path: str):
        data = await self.request("GET", "/api2/json" + path, headers=self.headers())
        return (data or {}).get("data") or []

    async def stores(self) -> list[dict]:
        stores = await self.get("/status/datastore-usage")
        only = self.config.get("datastore")
        return [s for s in stores if not only or s.get("store") == only]

    async def failed_tasks(self) -> list[dict]:
        since = int(time.time()) - DAY
        tasks = await self.get(f"/nodes/localhost/tasks?errors=1&since={since}&limit=50")
        return [t for t in tasks if t.get("status") not in (None, "OK") and not str(t.get("status")).startswith("WARNINGS")]

    async def groups(self, store: str) -> list[dict]:
        return await self.get(f"/admin/datastore/{store}/groups")

    async def summary(self) -> list[dict]:
        stores = await self.stores()
        used = sum(s.get("used", 0) for s in stores)
        total = sum(s.get("total", 0) for s in stores)
        p = pct(used, total)
        failed = await self.failed_tasks()
        oldest = None
        for s in stores:
            for g in await self.groups(s["store"]):
                age = ago(g.get("last-backup"))
                oldest = age if oldest is None or (age or 0) > oldest else oldest
        out = [
            field("opslag", f"{p:.0f}%" if p is not None else "—", level_for(p)),
            field("fouten 24u", len(failed), "err" if failed else "ok"),
        ]
        if oldest is not None:
            out.append(field("oudste", {"age": oldest}, backup_level(oldest)))
        return out

    async def detail(self) -> dict:
        stores = await self.stores()
        bars = []
        rows = []
        for s in stores:
            full = s.get("estimated-full-date")
            bars.append({"label": s.get("store"), "used": s.get("used"), "total": s.get("total"), "unit": "bytes",
                         "note": {"full_at": full} if full and full > 0 else None})
            for g in sorted(await self.groups(s["store"]), key=lambda g: (g.get("backup-type", ""), str(g.get("backup-id")))):
                age = ago(g.get("last-backup"))
                rows.append([
                    cell(s.get("store")),
                    cell(f"{g.get('backup-type')}/{g.get('backup-id')}"),
                    cell(g.get("comment") or "—"),
                    cell({"age": age} if age is not None else "nooit", backup_level(age)),
                    cell(g.get("backup-count")),
                ])
        failed = await self.failed_tasks()
        return {"sections": [
            {"kind": "bars", "title": "datastores", "items": bars},
            {"kind": "table", "title": "back-ups", "filter": True,
             "columns": ["datastore", "groep", "omschrijving", "laatste", "aantal"], "rows": rows},
            {"kind": "table", "title": "mislukte taken (24 u)", "columns": ["taak", "id", "start", "status"],
             "rows": [[cell(t.get("worker_type")), cell(t.get("worker_id") or "—"),
                       cell({"ts": t.get("starttime")}), cell(str(t.get("status"))[:120], "err")] for t in failed],
             "empty": "Geen mislukte taken."},
        ]}
