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
        "logs": "true om de containerlogs in de logviewer op te halen (standaard uit: ze nemen veel schijf in)",
    }
    secret_help = {"key": "API-sleutel (My account → Access tokens)"}
    call_prefix = "/api"
    actions = {"start", "stop", "restart"}

    async def call_auth(self) -> dict:
        return {"headers": self.headers()}

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

    @staticmethod
    def target(params: dict) -> tuple[int, str]:
        """Omgeving en container-id uit de parameters van een actie, nagekeken."""
        cid = str(params.get("id") or "")
        try:
            env = int(params.get("env"))
        except (TypeError, ValueError) as e:
            raise IntegrationError("Ongeldige omgeving") from e
        if not CID_RE.match(cid):
            raise IntegrationError("Ongeldig container-id")
        return env, cid

    async def inspect(self, params: dict) -> dict:
        """De container zoals Docker hem nu kent (alleen lezen). Een container die opnieuw gemaakt is (update,
        compose) heeft een ander id: dan HTTP 404."""
        env, cid = self.target(params)
        return await self.get(f"/endpoints/{env}/docker/containers/{cid}/json") or {}

    def action_request(self, action: str, params: dict) -> tuple[str, str, dict | None]:
        """Methode, pad en inhoud van de call die action() stuurt: de proefmodus toont precies deze."""
        if action not in self.actions:
            raise IntegrationError("Onbekende actie")
        env, cid = self.target(params)
        return "POST", f"/api/endpoints/{env}/docker/containers/{cid}/{action}", None

    async def action(self, action: str, params: dict) -> str:
        method, path, _ = self.action_request(action, params)
        await self.request(method, path, headers=self.headers())
        verb = {"start": "gestart", "stop": "gestopt", "restart": "herstart"}[action]
        return f"{params.get('name') or self.target(params)[1][:12]} {verb}"
