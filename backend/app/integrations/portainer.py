"""Portainer: omgevingen, containers en stacks; containers starten, stoppen en herstarten."""

import re

from .base import Integration, IntegrationError, cell, field

CID_RE = re.compile(r"^[0-9a-f]{12,64}$")


class Portainer(Integration):
    name = "portainer"
    label = "Portainer"
    config_help = {
        "url": "https://portainer.jbogaert.be",
        "env": "optioneel: id van één omgeving (endpoint), anders alle",
        "insecure": "true bij een zelfondertekend certificaat",
        "logs": "false om de containerlogs niet in de logviewer op te halen",
    }
    secret_help = {"key": "API-sleutel (My account → Access tokens)"}
    actions = {"start", "stop", "restart"}

    def headers(self) -> dict:
        return {"X-API-Key": self.need("key")[0]}

    async def get(self, path: str):
        return await self.request("GET", "/api" + path, headers=self.headers())

    async def envs(self) -> list[dict]:
        envs = await self.get("/endpoints") or []
        only = str(self.config.get("env") or "").strip()
        return [e for e in envs if not only or str(e.get("Id")) == only]

    async def summary(self) -> list[dict]:
        envs = await self.envs()
        up = [e for e in envs if e.get("Status") == 1]
        running = stopped = 0
        for e in up:
            snap = (e.get("Snapshots") or [{}])[-1]
            running += snap.get("RunningContainerCount") or 0
            stopped += snap.get("StoppedContainerCount") or 0
        out = [field("draaiend", running, "ok" if running else None),
               field("gestopt", stopped, "warn" if stopped else None)]
        out.insert(0, field("omgevingen", f"{len(up)}/{len(envs)}", "err" if len(up) < len(envs) else None))
        return out

    async def containers(self, env_id: int) -> list[dict]:
        return await self.get(f"/endpoints/{env_id}/docker/containers/json?all=1") or []

    async def detail(self) -> dict:
        sections = [{"kind": "kv", "title": "overzicht", "items": await self.summary()}]
        for e in await self.envs():
            if e.get("Status") != 1:
                sections.append({"kind": "kv", "title": e.get("Name") or f"omgeving {e.get('Id')}",
                                 "items": [field("status", "offline", "err")]})
                continue
            rows = []
            for c in sorted(await self.containers(e["Id"]), key=lambda c: (c.get("Names") or ["/"])[0]):
                name = (c.get("Names") or ["/?"])[0].lstrip("/")
                running = c.get("State") == "running"
                params = {"env": e["Id"], "id": c.get("Id"), "name": name}
                acts = ([{"id": "restart", "label": "herstart", "params": params, "confirm": True},
                         {"id": "stop", "label": "stop", "params": params, "confirm": True, "danger": True}]
                        if running else [{"id": "start", "label": "start", "params": params}])
                rows.append({"cells": [
                    cell(name),
                    cell(c.get("Image")),
                    cell(c.get("State"), "ok" if running else "err" if c.get("State") in ("dead", "exited") else "muted"),
                    cell(c.get("Status")),
                ], "actions": acts})
            sections.append({"kind": "table", "title": e.get("Name") or f"omgeving {e['Id']}", "filter": True,
                             "columns": ["container", "image", "staat", "status"], "rows": rows})
        return {"sections": sections}

    async def action(self, action: str, params: dict) -> str:
        if action not in self.actions:
            raise IntegrationError("Onbekende actie")
        cid = str(params.get("id") or "")
        try:
            env = int(params.get("env"))
        except (TypeError, ValueError) as e:
            raise IntegrationError("Ongeldige omgeving") from e
        if not CID_RE.match(cid):
            raise IntegrationError("Ongeldig container-id")
        await self.request("POST", f"/api/endpoints/{env}/docker/containers/{cid}/{action}", headers=self.headers())
        verb = {"start": "gestart", "stop": "gestopt", "restart": "herstart"}[action]
        return f"{params.get('name') or cid[:12]} {verb}"
