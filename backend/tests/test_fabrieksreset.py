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


# --- commandoregel (homepage-beheer) -------------------------------------------------------------------------------

class _Maker:
    """get_maker()() zoals in app.beheer, op de database van de test."""

    def __call__(self):
        return self

    async def __aenter__(self):
        self.agen = app.dependency_overrides[get_db]()
        return await self.agen.__anext__()

    async def __aexit__(self, *exc):
        await self.agen.aclose()


async def test_cli_2fa_reset_en_wachtwoord(authed, monkeypatch, capsys):
    from app import beheer
    monkeypatch.setattr(beheer, "get_maker", lambda: _Maker())
    assert await beheer.gebruikers() == 0
    assert "jonas\t2FA aan" in capsys.readouterr().out

    assert await beheer.tfa_reset(None) == 0
    agen, db = await _db()
    u = (await db.execute(select(User))).scalar_one()
    assert u.totp_enabled is False and u.totp_secret is None
    assert (await db.execute(select(func.count()).select_from(Session))).scalar_one() == 0
    await agen.aclose()
    # De oude sessie werkt niet meer; inloggen met het wachtwoord en dan opnieuw 2FA instellen.
    authed.cookies.clear()
    st = (await authed.get("/api/auth/state")).json()
    assert st["setup_required"] is False and st["mfa_ok"] is False
    from .conftest import PASSWORD
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.status_code == 200, r.text
    assert (await authed.get("/api/auth/state")).json()["user"]["totp_enabled"] is False
    secret = (await authed.get("/api/auth/totp/enroll")).json()["secret"]
    r = await authed.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text

    pw = iter(["nieuw-wachtwoord-123", "nieuw-wachtwoord-123"])
    monkeypatch.setattr(beheer.getpass, "getpass", lambda *_: next(pw))
    assert await beheer.wachtwoord("jonas") == 0
    authed.cookies.clear()
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.status_code == 401
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": "nieuw-wachtwoord-123"})
    assert r.status_code == 200 and r.json().get("code_required")
    with pytest.raises(SystemExit):
        await beheer.tfa_reset("bestaat-niet")


async def test_cli_fabrieksreset(authed, monkeypatch, capsys):
    from app import beheer
    monkeypatch.setattr(beheer, "get_maker", lambda: _Maker())
    await _fill(authed)
    monkeypatch.setattr("builtins.input", lambda *_: "nee")
    assert await beheer.fabrieksreset(False) == 1
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(Service))).scalar_one() == 1
    await agen.aclose()
    monkeypatch.setattr("builtins.input", lambda *_: "wis alles")
    assert await beheer.fabrieksreset(False) == 0
    assert f"Setup-code: {SETUP_TOKEN}" in capsys.readouterr().out
    agen, db = await _db()
    for model in (Service, User, Achtergrond):
        assert (await db.execute(select(func.count()).select_from(model))).scalar_one() == 0
    await agen.aclose()
    assert (await authed.get("/api/auth/state")).json()["setup_required"] is True


async def test_cli_herstel_tijdelijk_wachtwoord(authed, monkeypatch, capsys):
    """homepage-beheer herstel: 2FA uit, sessies weg, tijdelijk wachtwoord dat na 1 uur vervalt; daarmee inloggen,
    eerst een eigen wachtwoord kiezen, dan 2FA opnieuw."""
    import re
    from datetime import datetime, timedelta, timezone

    from app import beheer
    from .conftest import PASSWORD
    monkeypatch.setattr(beheer, "get_maker", lambda: _Maker())
    assert await beheer.herstel("JONAS") == 0
    out = capsys.readouterr().out
    pw = re.search(r"Tijdelijk wachtwoord: (\S+)", out).group(1)
    assert len(pw) == 19
    agen, db = await _db()
    u = (await db.execute(select(User))).scalar_one()
    assert u.totp_enabled is False and u.totp_secret is None
    left = u.password_temp_until.replace(tzinfo=u.password_temp_until.tzinfo or timezone.utc) - datetime.now(timezone.utc)
    assert timedelta(minutes=55) < left <= timedelta(hours=1)
    assert (await db.execute(select(func.count()).select_from(Session))).scalar_one() == 0
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "herstel"))).scalars().first() is not None
    await agen.aclose()

    authed.cookies.clear()
    st = (await authed.get("/api/auth/state")).json()
    assert st["mfa_ok"] is False and st["herstel_commando"].endswith(("homepage-beheer", "beheer.sh"))
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.status_code == 401
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": pw})
    assert r.status_code == 200 and r.json()["nieuw_wachtwoord"] is True and r.json()["mfa_ok"] is False
    assert (await authed.get("/api/auth/state")).json()["user"]["nieuw_wachtwoord"] is True
    # Eerst een eigen wachtwoord: 2FA instellen of het dashboard openen kan nog niet.
    assert (await authed.get("/api/auth/totp/enroll")).status_code == 409
    assert (await authed.get("/api/layout")).status_code == 401
    r = await authed.post("/api/auth/password/nieuw", json={"new": pw})
    assert r.status_code == 400
    r = await authed.post("/api/auth/password/nieuw", json={"new": "mijn-nieuw-wachtwoord"})
    assert r.status_code == 200, r.text
    st = (await authed.get("/api/auth/state")).json()
    assert st["user"]["nieuw_wachtwoord"] is False and st["user"]["totp_enabled"] is False
    secret = (await authed.get("/api/auth/totp/enroll")).json()["secret"]
    r = await authed.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    assert (await authed.get("/api/layout")).status_code == 200
    # Nog eens: dan geldt het tijdelijke wachtwoord niet meer.
    assert (await authed.post("/api/auth/password/nieuw", json={"new": "nog-een-wachtwoord"})).status_code == 409


async def test_cli_herstel_verlopen(authed, monkeypatch, capsys):
    import re
    from datetime import datetime, timedelta, timezone

    from app import beheer
    monkeypatch.setattr(beheer, "get_maker", lambda: _Maker())
    assert await beheer.herstel(None) == 0
    pw = re.search(r"Tijdelijk wachtwoord: (\S+)", capsys.readouterr().out).group(1)
    agen, db = await _db()
    u = (await db.execute(select(User))).scalar_one()
    u.password_temp_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db.commit()
    await agen.aclose()
    authed.cookies.clear()
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": pw})
    assert r.status_code == 401 and "verlopen" in r.json()["detail"]
    assert (await authed.get("/api/auth/state")).json()["mfa_ok"] is False
