"""Proxmox VE: nodes, VM's, containers en opslag via de API met een API-token."""

import re

from .base import Integration, IntegrationError, cell, field, level_for, pct

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class Proxmox(Integration):
    name = "proxmox"
    label = "Proxmox VE"
    config_help = {
        "url": "https://pve50.jbogaert.be (of https://192.168.0.50:8006)",
        "node": "optioneel: alleen deze node tonen",
        "insecure": "true bij een zelfondertekend certificaat",
    }
    secret_help = {
        "username": "token-id, bv. homepage@pve!dashboard",
        "password": "geheim van het token",
    }
    actions = {"start", "shutdown", "reboot", "stop"}

    def headers(self) -> dict:
        user, secret = self.need("username", "password")
        return {"Authorization": f"PVEAPIToken={user}={secret}"}

    async def get(self, path: str):
        data = await self.request("GET", "/api2/json" + path, headers=self.headers())
        return (data or {}).get("data") or []

    async def resources(self) -> list[dict]:
        res = await self.get("/cluster/resources")
        node = self.config.get("node")
        if node:
            res = [r for r in res if r.get("node") == node]
        return res

    async def summary(self) -> list[dict]:
        res = await self.resources()
        nodes = [r for r in res if r.get("type") == "node"]
        guests = [r for r in res if r.get("type") in ("qemu", "lxc") and not r.get("template")]
        vms = [g for g in guests if g["type"] == "qemu"]
        cts = [g for g in guests if g["type"] == "lxc"]
        run = lambda xs: sum(1 for x in xs if x.get("status") == "running")  # noqa: E731
        online = [n for n in nodes if n.get("status") == "online"]
        cpu = pct(sum(n.get("cpu", 0) * n.get("maxcpu", 0) for n in online), sum(n.get("maxcpu", 0) for n in online))
        mem = pct(sum(n.get("mem", 0) for n in online), sum(n.get("maxmem", 0) for n in online))
        out = [
            field("VM", f"{run(vms)}/{len(vms)}"),
            field("LXC", f"{run(cts)}/{len(cts)}"),
            field("CPU", f"{cpu:.0f}%" if cpu is not None else "—", level_for(cpu)),
            field("RAM", f"{mem:.0f}%" if mem is not None else "—", level_for(mem)),
        ]
        if len(online) < len(nodes):
            out.insert(0, field("nodes", f"{len(online)}/{len(nodes)}", "err"))
        return out

    async def detail(self) -> dict:
        res = await self.resources()
        nodes = sorted((r for r in res if r.get("type") == "node"), key=lambda r: r.get("node", ""))
        guests = sorted((r for r in res if r.get("type") in ("qemu", "lxc") and not r.get("template")),
                        key=lambda r: r.get("vmid", 0))
        storage = {}
        for s in res:
            if s.get("type") != "storage" or not s.get("maxdisk"):
                continue
            key = s.get("storage") if s.get("shared") else f"{s.get('node')}/{s.get('storage')}"
            storage[key] = s

        node_rows = []
        for n in nodes:
            cpu = round(n.get("cpu", 0) * 100, 1) if n.get("status") == "online" else None
            mem = pct(n.get("mem"), n.get("maxmem"))
            node_rows.append([
                cell(n.get("node")),
                cell(n.get("status"), "ok" if n.get("status") == "online" else "err"),
                cell(f"{cpu:.0f}%" if cpu is not None else "—", level_for(cpu)),
                cell(f"{mem:.0f}%" if mem is not None else "—", level_for(mem)),
                cell({"uptime": n.get("uptime")}),
            ])

        guest_rows = []
        for g in guests:
            running = g.get("status") == "running"
            mem = pct(g.get("mem"), g.get("maxmem")) if running else None
            params = {"node": g.get("node"), "type": g.get("type"), "vmid": g.get("vmid")}
            acts = ([{"id": "shutdown", "label": "afsluiten", "params": params, "confirm": True},
                     {"id": "reboot", "label": "herstart", "params": params, "confirm": True},
                     {"id": "stop", "label": "forceer stop", "params": params, "confirm": True, "danger": True}]
                    if running else
                    [{"id": "start", "label": "start", "params": params}])
            guest_rows.append({
                "cells": [
                    cell(g.get("vmid")),
                    cell(g.get("name") or "—"),
                    cell("VM" if g.get("type") == "qemu" else "LXC"),
                    cell(g.get("node")),
                    cell(g.get("status"), "ok" if running else "muted"),
                    cell(f"{g.get('cpu', 0) * 100:.0f}%" if running else "—"),
                    cell(f"{mem:.0f}%" if mem is not None else "—", level_for(mem)),
                    cell({"uptime": g.get("uptime")} if running else "—"),
                ],
                "actions": acts,
            })

        return {"sections": [
            {"kind": "table", "title": "nodes", "columns": ["node", "status", "cpu", "ram", "uptime"], "rows": node_rows},
            {"kind": "bars", "title": "opslag", "items": [
                {"label": k, "used": s.get("disk"), "total": s.get("maxdisk"), "unit": "bytes"}
                for k, s in sorted(storage.items())]},
            {"kind": "table", "title": "vm's en containers", "filter": True,
             "columns": ["id", "naam", "type", "node", "status", "cpu", "ram", "uptime"], "rows": guest_rows},
        ]}

    async def action(self, action: str, params: dict) -> str:
        if action not in self.actions:
            raise IntegrationError("Onbekende actie")
        node, kind, vmid = params.get("node"), params.get("type"), params.get("vmid")
        if not (isinstance(node, str) and NODE_RE.match(node)) or kind not in ("qemu", "lxc"):
            raise IntegrationError("Ongeldige node of type")
        try:
            vmid = int(vmid)
        except (TypeError, ValueError) as e:
            raise IntegrationError("Ongeldig vmid") from e
        await self.request("POST", f"/api2/json/nodes/{node}/{kind}/{vmid}/status/{action}", headers=self.headers())
        return f"{action} gestart voor {vmid} op {node}"
