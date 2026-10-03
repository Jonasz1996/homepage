from fastapi import Depends, FastAPI

from .deps import csrf_guard
from .routers import auth, importexport, layout, notifications

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


@app.get("/api/health")
async def health():
    return {"ok": True}
