"""Home Assistant: stroomverbruik per node uit slimme stekkers of energiemeters.

config: {"url": "http://192.168.0.30:8123", "price": 0.30,
         "nodes": {"pve50": {"power": "sensor.pve50_power", "energy": "sensor.pve50_energy"},
                   "pve51": "sensor.pve51_power"}}
"power" (W) is verplicht, "energy" (kWh, oplopend totaal) optioneel: zonder rekent het dashboard
het verbruik zelf uit zijn metingen om de 10 minuten.
"""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .base import Integration, IntegrationError, cell, field

ENTITY_RE = re.compile(r"^[a-z_]+\.[a-z0-9_]+$")


def month_start(now: datetime | None = None) -> datetime:
    local = (now or datetime.now(timezone.utc)).astimezone()
    return local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _float(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f else None  # NaN


def _kwh(value: float | None, unit: str | None) -> float | None:
    if value is None:
        return None
    u = (unit or "kWh").lower()
    return value / 1000 if u == "wh" else value * 1000 if u == "mwh" else value


def _watts(value: float | None, unit: str | None) -> float | None:
    if value is None:
        return None
    return value * 1000 if (unit or "W").lower() == "kw" else value


class HomeAssistant(Integration):
    name = "homeassistant"
    label = "Home Assistant (stroom)"
    config_help = {
        "url": "http://192.168.0.30:8123",
        "nodes": '{"pve50": {"power": "sensor.pve50_power", "energy": "sensor.pve50_energy"}, ...}; energy is optioneel',
        "price": "prijs per kWh in euro, bv. 0.30",
        "insecure": "true bij een zelfondertekend certificaat",
    }
    secret_help = {"token": "long-lived access token (profiel → Beveiliging, onderaan)"}
    call_prefix = "/api"

    async def call_auth(self) -> dict:
        return {"headers": self.headers()}

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.need('token')[0]}"}

    def mapping(self) -> list[tuple[str, str, str | None]]:
        nodes = self.config.get("nodes") or {}
        if not isinstance(nodes, dict) or not nodes:
            raise IntegrationError('Stel "nodes" in: {"pve50": {"power": "sensor...", "energy": "sensor..."}}')
        out = []
        for label, v in nodes.items():
            power, energy = (v.get("power"), v.get("energy")) if isinstance(v, dict) else (v, None)
            if not (isinstance(power, str) and ENTITY_RE.match(power)):
                raise IntegrationError(f"Ongeldige power-sensor bij {label}")
            if energy is not None and not (isinstance(energy, str) and ENTITY_RE.match(energy)):
                raise IntegrationError(f"Ongeldige energy-sensor bij {label}")
            out.append((str(label), power, energy))
        return out

    @property
    def price(self) -> float | None:
        return _float(self.config.get("price"))

    async def state(self, entity: str) -> tuple[float | None, str | None]:
        data = await self.request("GET", f"/api/states/{entity}", headers=self.headers()) or {}
        return _float(data.get("state")), (data.get("attributes") or {}).get("unit_of_measurement")

    async def value_at(self, entity: str, at: datetime) -> float | None:
        """Waarde van een sensor op een tijdstip (de eerste regel van de geschiedenis vanaf dat moment)."""
        start = quote(at.astimezone(timezone.utc).isoformat())
        end = quote((at + timedelta(hours=6)).astimezone(timezone.utc).isoformat())
        data = await self.request(
            "GET", f"/api/history/period/{start}?filter_entity_id={entity}&end_time={end}&minimal_response&no_attributes",
            headers=self.headers()) or []
        for row in (data[0] if data else []):
            v = _float(row.get("state"))
            if v is not None:
                return v
        return None

    async def readings(self) -> list[dict]:
        """Per node: watt nu, en kWh deze maand als er een energy-sensor is."""
        start = month_start()
        out = []
        for label, power, energy in self.mapping():
            w, unit = await self.state(power)
            row = {"name": label, "watts": _watts(w, unit), "month_kwh": None, "energy": bool(energy)}
            if energy:
                now_v, e_unit = await self.state(energy)
                then = await self.value_at(energy, start)
                if now_v is not None and then is not None:
                    # Teller teruggezet (nieuwe stekker): dan telt alles sinds de reset.
                    row["month_kwh"] = _kwh(now_v - then if now_v >= then else now_v, e_unit)
            out.append(row)
        return out

    async def summary(self) -> list[dict]:
        rows = await self.readings()
        total = sum(r["watts"] or 0 for r in rows)
        out = [field("nu", f"{total:.0f} W")]
        if rows and all(r["month_kwh"] is not None for r in rows):
            kwh = sum(r["month_kwh"] for r in rows)
            out.append(field("maand", f"{kwh:.1f} kWh"))
            if self.price is not None:
                out.append(field("kost", f"€ {kwh * self.price:.2f}"))
        return out

    async def detail(self) -> dict:
        rows = await self.readings()
        p = self.price
        table = [[cell(r["name"]), cell(f"{r['watts']:.0f} W" if r["watts"] is not None else "—"),
                  cell(f"{r['month_kwh']:.1f} kWh" if r["month_kwh"] is not None else "zie df"),
                  cell(f"€ {r['month_kwh'] * p:.2f}" if r["month_kwh"] is not None and p is not None else "—")]
                 for r in rows]
        return {"sections": [{"kind": "table", "title": "stroom per node", "columns": ["node", "nu", "deze maand", "kost"],
                              "rows": table}]}
