"""Proxmox Backup Server: opslag per datastore, laatste back-up per VM/CT en mislukte taken."""

import time

from .base import Integration, ago, cell, field, level_for, pct

DAY = 86400
# Dagelijkse back-ups: na 26 uur is er een gemist (oranje), na 3 dagen is het ernstig (rood).
LATE = 26 * 3600


def backup_level(age: float | None, failed: bool = False) -> str:
    if age is None or failed:
        return "err"
    return "ok" if age < LATE else "warn" if age < 3 * DAY else "err"


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

    async def snapshots(self, store: str) -> list[dict]:
        return await self.get(f"/admin/datastore/{store}/snapshots")

    async def backup_status(self) -> tuple[list[dict], list[dict], list[dict]]:
        """Per VM/CT: leeftijd van de laatste back-up, verify-status en of de laatste back-uptaak mislukte."""
        stores = await self.stores()
        failed = await self.failed_tasks()
        failed_ids = {str(t.get("worker_id")) for t in failed if t.get("worker_type") == "backup"}
        out = []
        for s in stores:
            store = s.get("store")
            verify: dict[tuple, tuple[int, str]] = {}
            for snap in await self.snapshots(store):
                state = (snap.get("verification") or {}).get("state")
                key = (snap.get("backup-type"), str(snap.get("backup-id")))
                t = snap.get("backup-time") or 0
                # Verify-status van de nieuwste snapshot die al geverifieerd is.
                if state and t >= verify.get(key, (-1, ""))[0]:
                    verify[key] = (t, state)
            for g in await self.groups(store):
                key = (g.get("backup-type"), str(g.get("backup-id")))
                age = ago(g.get("last-backup"))
                v = verify.get(key, (0, None))[1]
                task_failed = f"{store}:{key[0]}/{key[1]}" in failed_ids
                bad = task_failed or v == "failed"
                out.append({"store": store, "group": f"{key[0]}/{key[1]}", "comment": g.get("comment"),
                            "age": age, "count": g.get("backup-count"), "verify": v, "task_failed": task_failed,
                            "level": backup_level(age, bad)})
        out.sort(key=lambda r: (r["store"] or "", r["group"]))
        return stores, out, failed

    async def summary(self) -> list[dict]:
        stores, groups, failed = await self.backup_status()
        p = pct(sum(s.get("used", 0) for s in stores), sum(s.get("total", 0) for s in stores))
        out = [
            field("opslag", f"{p:.0f}%" if p is not None else "—", level_for(p)),
            field("fouten 24u", len(failed), "err" if failed else "ok"),
        ]
        ages = [g["age"] for g in groups if g["age"] is not None]
        if ages:
            out.append(field("oudste", {"age": max(ages)}, backup_level(max(ages))))
        bad_verify = sum(1 for g in groups if g["verify"] == "failed")
        if bad_verify:
            out.append(field("verify", f"{bad_verify} fout", "err"))
        return out

    async def detail(self) -> dict:
        stores, groups, failed = await self.backup_status()
        bars = []
        for s in stores:
            full = s.get("estimated-full-date")
            bars.append({"label": s.get("store"), "used": s.get("used"), "total": s.get("total"), "unit": "bytes",
                         "note": {"full_at": full} if full and full > 0 else None})
        verify_text = {"ok": ("ok", "ok"), "failed": ("mislukt", "err"), None: ("—", "muted")}
        rows = []
        for g in groups:
            vt, vl = verify_text.get(g["verify"], (g["verify"], None))
            last = cell({"age": g["age"]} if g["age"] is not None else "nooit", g["level"])
            rows.append([
                cell(g["store"]), cell(g["group"]), cell(g["comment"] or "—"),
                last if not g["task_failed"] else cell("laatste taak mislukt", "err"),
                cell(vt, vl), cell(g["count"]),
            ])
        return {"sections": [
            {"kind": "bars", "title": "datastores", "items": bars},
            {"kind": "table", "title": "back-ups", "filter": True,
             "columns": ["datastore", "groep", "omschrijving", "laatste", "verify", "aantal"], "rows": rows},
            {"kind": "table", "title": "mislukte taken (24 u)", "columns": ["taak", "id", "start", "status"],
             "rows": [[cell(t.get("worker_type")), cell(t.get("worker_id") or "—"),
                       cell({"ts": t.get("starttime")}), cell(str(t.get("status"))[:120], "err")] for t in failed],
             "empty": "Geen mislukte taken."},
        ]}
