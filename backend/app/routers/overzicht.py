"""Overzicht: wat het hoofdscherm geregeld opvraagt, in één verzoek in plaats van negen endpoints op negen timers.

GET /api/overzicht?delen=status,widgets,zabbix,updates,net,cron,health,aandacht,meldingen,buiten (zonder delen: alles)
geeft {"tijd": nu in UTC, "delen": {deel: antwoord}, "fouten": {deel: korte reden}}. Elk deel is precies wat zijn eigen
endpoint geeft: dezelfde functie, met dezelfde neveneffecten (gezondheid bewaart de workercheck, aandacht vergeet wat
genegeerd was en opgelost is, buiten onthoudt een bezoek van buitenaf). Die endpoints blijven bestaan: andere vensters
gebruiken ze. meldingen is nieuw en klein: het aantal ongelezen en de nieuwste melding.

Vraag per keer alleen de delen die aan de beurt zijn (zoals de oude timers): elk deel doet bij elke vraag wat zijn
endpoint deed. buiten dus één keer bij het laden, anders telt elke vraag van buitenaf als een nieuw bezoek.

Een deel dat misloopt, breekt de rest niet: het komt met een korte reden in fouten (zonder details: die staan in de
log), en de sessie wordt teruggedraaid zodat de volgende delen verder kunnen (na een databasefout weigert PostgreSQL
anders alles tot het einde van de transactie, en half werk van het mislukte deel mag niet met een later deel mee
bewaard worden: op zijn eigen endpoint ging het ook verloren).
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db, get_maker, timed_out
from ..deps import current_user
from ..models import User
from . import attention, cron, health, integrations, monitoring, network, notifications, outside, timeline, zabbix

router = APIRouter(prefix="/api", tags=["overzicht"])
log = logging.getLogger("homepage.api")

# Zo lang wacht het overzicht op de tegels (de API's van de integraties). Daarna antwoordt het zonder, en rekent de
# berekening op de achtergrond verder: zo staat het resultaat in de cache van de tegels (SUMMARY_TTL) bij de volgende
# vraag.
WIDGETS_BUDGET = 8
TRAAG = "te traag, volgende keer"

DELEN = ("status", "widgets", "zabbix", "updates", "net", "cron", "health", "aandacht", "meldingen", "buiten")

# De delen op de sessie van het verzoek: na elkaar (een sessie doet één ding tegelijk), in deze volgorde. Geen van
# deze endpoints sluit zijn sessie; de tegels wel, daarom krijgen die hun eigen sessie (zie _tegels). meldingen komt na
# health, zodat een melding van de workercheck van deze ronde meetelt, zoals bij het eigen endpoint daarna. aandacht
# komt als laatste, na het wachten op de tegels: het neemt de laatste fout per tegel uit de cache die de tegels net
# vulden. De functies worden bij elke vraag opgezocht (lambda), niet hier vastgelegd.
_OP_SESSIE = {
    "status": lambda request, user, db: monitoring.all_status(user=user, db=db),
    "zabbix": lambda request, user, db: zabbix.zabbix_status(user=user, db=db),
    "updates": lambda request, user, db: timeline.updates(user=user, db=db),
    "net": lambda request, user, db: network.network(user=user, db=db),
    "cron": lambda request, user, db: cron.summary(user=user, db=db),
    "health": lambda request, user, db: health.summary(user=user, db=db),
    "meldingen": lambda request, user, db: notifications.badge(db),
    # Vraagt ook het verzoek zelf: van waar het komt (thuis of van buitenaf).
    "buiten": lambda request, user, db: outside.state(request=request, user=user, db=db),
    "aandacht": lambda request, user, db: attention.overview(user=user, db=db),
}
assert set(_OP_SESSIE) | {"widgets"} == set(DELEN)

# De berekening van de tegels die nu loopt (hoogstens één tegelijk, ook als het verzoek dat ze startte al antwoordde).
_tegels_taak: asyncio.Task | None = None


def _gevraagd(delen: str | None) -> set[str]:
    namen = {n.strip() for n in (delen or "").split(",")} - {""}
    if not namen:
        return set(DELEN)
    onbekend = sorted(namen - set(DELEN))
    if onbekend:
        wat = ", ".join(n[:40] for n in onbekend[:5])
        raise HTTPException(422, f"Onbekend deel: {wat} (kan: {', '.join(DELEN)})" if len(onbekend) == 1
                            else f"Onbekende delen: {wat} (kan: {', '.join(DELEN)})")
    return namen


def _reden(e: BaseException) -> str:
    """Korte reden voor in fouten: geen stacktrace, geen databasetekst (die kan waarden bevatten)."""
    if isinstance(e, HTTPException) and isinstance(e.detail, str):
        return e.detail[:200]  # bedoeld voor het scherm, zoals bij het eigen endpoint
    if isinstance(e, SQLAlchemyError):
        return "database te traag" if timed_out(e) else "databasefout"
    if isinstance(e, TimeoutError):
        return "duurde te lang"
    return "onverwachte fout"


async def _deel(naam: str, request: Request, user: User, db: AsyncSession, uit: dict, fouten: dict) -> None:
    try:
        uit[naam] = await _OP_SESSIE[naam](request, user, db)
    except Exception as e:
        fouten[naam] = _reden(e)
        if isinstance(e, HTTPException):
            log.warning("overzicht: deel %s geweigerd (%s): %s", naam, e.status_code, fouten[naam])
        else:
            log.exception("overzicht: deel %s mislukt", naam)
        try:
            await db.rollback()
        except Exception:
            log.exception("overzicht: terugdraaien na deel %s mislukt", naam)


@asynccontextmanager
async def _eigen_sessie(factory):
    """Een eigen sessie uit de pool (get_maker), of in de tests uit de get_db die ze in de plaats zetten."""
    if factory is None:
        async with get_maker()() as db:
            yield db
        return
    gen = factory()
    try:
        yield await anext(gen)
    finally:
        await gen.aclose()


async def _tegels_berekenen(factory, user: User) -> dict:
    async with _eigen_sessie(factory) as db:
        # Sluit de sessie zelf vóór de (soms trage) API's van de integraties.
        return await integrations.widgets(user=user, db=db)


def _tegels_klaar(t: asyncio.Task) -> None:
    # Ook als niemand meer wacht (het verzoek antwoordde al zonder): de fout in de log, niet "never retrieved".
    if not t.cancelled() and (e := t.exception()) is not None:
        log.error("overzicht: tegels laden mislukt", exc_info=e)


def _tegels(request: Request, user: User) -> asyncio.Task:
    """De berekening van de tegels: die nog loopt (van een vorige vraag), anders een nieuwe."""
    global _tegels_taak
    t = _tegels_taak
    # get_loop: een taak van een andere event loop (in de tests: een vorige test) kan nooit meer klaar raken.
    if t is None or t.done() or t.get_loop() is not asyncio.get_running_loop():
        t = asyncio.create_task(_tegels_berekenen(request.app.dependency_overrides.get(get_db), user))
        t.add_done_callback(_tegels_klaar)
        _tegels_taak = t
    return t


async def _wacht_op_tegels(taak: asyncio.Task, tot: float, uit: dict, fouten: dict) -> None:
    try:
        # shield: na de time-out (of als de bezoeker afhaakt) rekent de taak verder en vult ze de cache.
        uit["widgets"] = await asyncio.wait_for(asyncio.shield(taak), max(0.0, tot - asyncio.get_running_loop().time()))
    except asyncio.CancelledError:
        if not taak.cancelled() or asyncio.current_task().cancelling():
            raise  # dit verzoek zelf wordt afgebroken
        fouten["widgets"] = "afgebroken"
    except Exception as e:
        # De fout zelf staat al in de log (_tegels_klaar).
        fouten["widgets"] = TRAAG if isinstance(e, TimeoutError) and not taak.done() else _reden(e)


@router.get("/overzicht")
async def overzicht(request: Request, delen: str | None = None, user: User = Depends(current_user),
                    db: AsyncSession = Depends(get_db)):
    gevraagd = _gevraagd(delen)
    tijd = datetime.now(timezone.utc)
    uit: dict = {}
    fouten: dict[str, str] = {}
    tot = asyncio.get_running_loop().time() + WIDGETS_BUDGET
    # Eerst de tegels starten: die lopen in hun eigen sessie naast de rest.
    taak = _tegels(request, user) if "widgets" in gevraagd else None
    for naam in _OP_SESSIE:
        if naam in gevraagd and naam != "aandacht":
            await _deel(naam, request, user, db, uit, fouten)
    if taak is not None:
        await _wacht_op_tegels(taak, tot, uit, fouten)
    if "aandacht" in gevraagd:
        await _deel("aandacht", request, user, db, uit, fouten)
    return {"tijd": tijd.isoformat(), "delen": {k: uit[k] for k in DELEN if k in uit},
            "fouten": {k: fouten[k] for k in DELEN if k in fouten}}
