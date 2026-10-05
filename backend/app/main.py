import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request

from .config import get_settings
from .db import get_maker
from .deps import COOKIE, csrf_guard, secure_cookie
from .routers import (apis, attention, auth, backups, capacity, configs, cron, heal, health, hooks, importexport, integrations, layout, logs, monitoring, network, notifications,
                      netmap, oidc, outside, planning, restoretest, search, securitycheck, ssh, timeline, upgrade, versie, webpush, zabbix)

log = logging.getLogger("homepage.api")


async def _startup() -> None:
    """Manuele update-runs die liepen toen de API herstartte, als mislukt markeren (anders blijft dat doel geblokkeerd)."""
    from .monitoring.upgrade import mark_interrupted

    try:
        async with get_maker()() as db:
            n = await mark_interrupted(db, ("manueel",))
            await db.commit()
        if n:
            log.warning("%s update-run(s) onderbroken door herstart", n)
    except Exception:
        # Opstarten mag hier niet op vastlopen (bv. database nog niet bereikbaar of nog niet gemigreerd).
        log.exception("onderbroken update-runs opruimen mislukt")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await _startup()
    yield


app = FastAPI(
    title="homepage",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    dependencies=[Depends(csrf_guard)],
)

app.include_router(auth.router)
app.include_router(layout.router)
app.include_router(importexport.router)
app.include_router(notifications.router)
app.include_router(monitoring.router)
app.include_router(integrations.router)
app.include_router(ssh.router)
app.include_router(logs.router)
app.include_router(capacity.router)
app.include_router(timeline.router)
app.include_router(network.router)
app.include_router(oidc.router)
app.include_router(cron.router)
app.include_router(health.router)
app.include_router(upgrade.router)
app.include_router(heal.router)
app.include_router(configs.router)
app.include_router(hooks.router)
app.include_router(planning.router)
app.include_router(search.router)
app.include_router(restoretest.router)
app.include_router(netmap.router)
app.include_router(apis.router)
app.include_router(zabbix.router)
app.include_router(versie.router)
app.include_router(outside.router)
app.include_router(securitycheck.router)
app.include_router(attention.router)
app.include_router(backups.router)
app.include_router(webpush.router)


@app.middleware("http")
async def renew_session_cookie(request: Request, call_next):
    response = await call_next(request)
    renew = getattr(request.state, "renew_cookie", None)
    if renew:
        token, lifetime = renew
        response.set_cookie(COOKIE, token, max_age=int(lifetime.total_seconds()), httponly=True,
                            secure=secure_cookie(request), samesite="strict", path="/")
    return response


# Zonder inloggen: draait de API? (/api/health is het gezondheidsoverzicht in hw en vraagt een login.)
@app.get("/api/ping")
async def ping():
    return {"ok": True}
