from fastapi import Depends, FastAPI, Request

from .config import get_settings
from .deps import COOKIE, csrf_guard
from .routers import auth, importexport, integrations, layout, logs, monitoring, notifications, ssh

app = FastAPI(
    title="homepage",
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


@app.middleware("http")
async def renew_session_cookie(request: Request, call_next):
    response = await call_next(request)
    renew = getattr(request.state, "renew_cookie", None)
    if renew:
        token, lifetime = renew
        response.set_cookie(COOKIE, token, max_age=int(lifetime.total_seconds()), httponly=True,
                            secure=get_settings().cookie_secure, samesite="strict", path="/")
    return response


@app.get("/api/health")
async def health():
    return {"ok": True}
