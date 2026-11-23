"""Fabrieksreset (alles weg, terug naar de eerste start) en de eigen achtergrond (Instellingen → Weergave)."""

from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from sqlalchemy import func, select, update

from app.main import app
from app.db import get_db
from app.models import Achtergrond, AppState, AuditLog, LogRule, Page, Service, Session, User
from app.routers import fabrieksreset, weergave

from .conftest import SETUP_TOKEN, do_setup
from .test_buitenaf import CF

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\0" * 64


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _fill(authed) -> None:
    r = await authed.post("/api/import", json={"yaml": "- Infra:\n    - Proxmox:\n        href: http://192.168.0.10:8006\n"})
    assert r.status_code == 200, r.text
    r = await authed.post("/api/achtergrond/beeld", content=PNG, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text


async def test_reset_wist_alles_en_terug_naar_setup(authed):
    await _fill(authed)
    p = (await authed.get("/api/fabrieksreset")).json()
    assert p["thuis"] is True and p["zin"] == "WIS ALLES"
    assert p["telling"]["tegels"] == 1 and p["telling"]["paginas"] == 1

    # Zonder de zin: niets.
    r = await authed.post("/api/fabrieksreset", json={"zin": "ja"})
    assert r.status_code == 400
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(Service))).scalar_one() == 1
    await agen.aclose()

    r = await authed.post("/api/fabrieksreset", json={"zin": "wis alles"})
    assert r.status_code == 200, r.text
    assert r.json()["setup_code"] == SETUP_TOKEN

    agen, db = await _db()
    for model in (Service, Page, User, Session, Achtergrond):
        assert (await db.execute(select(func.count()).select_from(model))).scalar_one() == 0, model
    # Wat een verse installatie meekrijgt: de standaard logregel en het spoor van de reset zelf.
    assert [r.name for r in (await db.execute(select(LogRule))).scalars()] == ["Kritieke meldingen"]
    audit = (await db.execute(select(AuditLog))).scalars().all()
    assert [(a.action, a.detail.get("door"), a.user_id) for a in audit] == [("fabrieksreset", "jonas", None)]
    assert await db.get(AppState, fabrieksreset.LEGACY_KEY) is not None
    await agen.aclose()

    # De oude sessie is weg: het dashboard vraagt de eerste setup, en die werkt opnieuw.
    authed.cookies.clear()
    st = (await authed.get("/api/auth/state")).json()
    assert st["setup_required"] is True and st["user"] is None
    await do_setup(authed)
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"] is True
    assert (await authed.get("/api/achtergrond")).json()["beeld"] is None


async def test_reset_nooit_van_buitenaf(authed):
    await _fill(authed)
    p = (await authed.get("/api/fabrieksreset", headers=CF)).json()
    assert p["thuis"] is False
    r = await authed.post("/api/fabrieksreset", json={"zin": "WIS ALLES"}, headers=CF)
    assert r.status_code == 403 and "thuis" in r.json()["detail"]
    r = await authed.get("/api/fabrieksreset/backup", headers=CF)
    assert r.status_code == 403
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(Service))).scalar_one() == 1
    await agen.aclose()


async def test_reset_vraagt_verse_2fa_met_aanmelden_aan(authed):
    """In de tests staat aanmelden aan (conftest met_login): dan hoort er een recente 2FA bij."""
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()
    r = await authed.post("/api/fabrieksreset", json={"zin": "WIS ALLES"})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    r = await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 200
    r = await authed.post("/api/fabrieksreset", json={"zin": "WIS ALLES"})
    assert r.status_code == 200


async def test_reset_zonder_login(client):
    assert (await client.post("/api/fabrieksreset", json={"zin": "WIS ALLES"})).status_code == 401


def test_dump_command():
    args, env = fabrieksreset.dump_command("postgresql+asyncpg://homepage@/homepage", "/tmp/x.dump", ["_ti.c1"])
    assert args == ["pg_dump", "-Fc", "-f", "/tmp/x.dump", "-U", "homepage",
                    "--exclude-table-data=public.log_entries", "--exclude-table-data=_ti.c1", "homepage"]
    assert "PGPASSWORD" not in env or env["PGPASSWORD"] != "geheim"
    args, env = fabrieksreset.dump_command("postgresql+asyncpg://hp:geheim@db:5433/dash", "/o", [])
    assert args[4:10] == ["-h", "db", "-p", "5433", "-U", "hp"] and args[-1] == "dash" and env["PGPASSWORD"] == "geheim"


def test_reset_kent_alle_tabellen():
    """Een nieuwe tabel komt vanzelf mee: wipe() loopt over Base.metadata."""
    from app.models import Base
    assert "achtergrond" in Base.metadata.tables


# --- achtergrond ------------------------------------------------------------------------------------------------------

async def test_achtergrond_upload_en_instellingen(authed):
    r = (await authed.get("/api/achtergrond")).json()
    assert r == {"effecten": True, "dimmen": 35, "vervagen": 0, "beeld": None}

    r = await authed.post("/api/achtergrond/beeld", content=b"<svg onload=alert(1)>",
                          headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 415
    r = await authed.post("/api/achtergrond/beeld", content=JPG, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    b = r.json()["beeld"]
    assert b["mime"] == "image/jpeg" and b["url"].startswith("/api/achtergrond/beeld/")
    img = await authed.get(b["url"])
    assert img.status_code == 200 and img.content == JPG and img.headers["content-type"] == "image/jpeg"
    assert "immutable" in img.headers["cache-control"]
    assert (await authed.get("/api/achtergrond/beeld/" + "0" * 64)).status_code == 404

    r = await authed.put("/api/achtergrond", json={"effecten": False, "dimmen": 60, "vervagen": 4})
    assert r.status_code == 200 and r.json()["effecten"] is False and r.json()["dimmen"] == 60
    assert (await authed.put("/api/achtergrond", json={"effecten": True, "dimmen": 95, "vervagen": 0})).status_code == 422

    # Een nieuwe afbeelding vervangt de oude.
    r = await authed.post("/api/achtergrond/beeld", content=PNG, headers={"Content-Type": "application/octet-stream"})
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(Achtergrond))).scalar_one() == 1
    await agen.aclose()
    assert (await authed.get(b["url"])).status_code == 404

    r = await authed.delete("/api/achtergrond/beeld")
    assert r.json()["beeld"] is None and r.json()["dimmen"] == 60


async def test_achtergrond_te_groot(authed, monkeypatch):
    monkeypatch.setattr(weergave, "MAX_UPLOAD", 50)
    r = await authed.post("/api/achtergrond/beeld", content=PNG, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 413


async def test_achtergrond_van_adres(authed, monkeypatch):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/geen.png":
            return httpx.Response(200, content=b"<html>")
        return httpx.Response(200, content=PNG)

    real = httpx.AsyncClient

    def fake(*a, **kw):
        kw.pop("verify", None)
        return real(*a, transport=httpx.MockTransport(handler), **kw)
    monkeypatch.setattr(weergave.httpx, "AsyncClient", fake)

    r = await authed.post("/api/achtergrond/url", json={"url": "https://example.org/bg.png"})
    assert r.status_code == 200, r.text
    assert r.json()["beeld"]["bron"] == "https://example.org/bg.png" and r.json()["beeld"]["mime"] == "image/png"
    r = await authed.post("/api/achtergrond/url", json={"url": "https://example.org/geen.png"})
    assert r.status_code == 415
    for bad in ("file:///etc/passwd", "http://127.0.0.1:8000/api", "http://user:pw@x.org/a.png"):
        r = await authed.post("/api/achtergrond/url", json={"url": bad})
        assert r.status_code == 400, bad
    # Van buitenaf: hoort bij acties.
    r = await authed.post("/api/achtergrond/url", json={"url": "https://example.org/bg.png"}, headers=CF)
    assert r.status_code == 403 and r.json()["detail"] == "buiten:acties"
    assert len(seen) == 2


@pytest.mark.parametrize("data,mime", [(PNG, "image/png"), (JPG, "image/jpeg"), (b"GIF89a....", "image/gif"),
                                       (b"RIFF\0\0\0\0WEBPVP8 ", "image/webp"),
                                       (b"\0\0\0\x1cftypavif\0\0", "image/avif"), (b"<svg/>", None)])
def test_sniff(data, mime):
    assert weergave.sniff(data) == mime


async def test_backup_vooraf_met_postgres(authed, monkeypatch):
    """Een echte pg_dump (alleen tegen PostgreSQL, met pg_dump op het pad): een geldig archief, en daarna is het
    tijdelijke bestand weer weg."""
    import os
    import shutil

    from app.config import get_settings
    from .conftest import TEST_DB
    if not TEST_DB.startswith("postgresql") or not shutil.which("pg_dump"):
        if os.environ.get("HOMEPAGE_TEST_PG_CLIENT") == "verplicht" and TEST_DB.startswith("postgresql"):
            raise AssertionError("pg_dump ontbreekt")
        pytest.skip("alleen met PostgreSQL en pg_dump")
    await _fill(authed)
    monkeypatch.setattr(get_settings(), "database_url", TEST_DB)
    r = await authed.get("/api/fabrieksreset/backup")
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"PGDMP")
    assert "homepage-voor-reset-" in r.headers["content-disposition"]
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "fabrieksreset-backup"))).scalar_one() == 1
    await agen.aclose()
