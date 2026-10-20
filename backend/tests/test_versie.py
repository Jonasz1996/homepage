from datetime import timedelta

from app.config import get_settings
from app.models import User, utcnow

from .test_meldingen_onderhoud import _db


async def test_versie_en_gezien(authed, tmp_path, monkeypatch):
    f = tmp_path / "versie"
    monkeypatch.setattr(get_settings(), "version_file", f)
    v = (await authed.get("/api/version")).json()
    assert v["versie"] == "dev" and v["gezien"] is None and v["nieuw_account"] is True

    f.write_text("versie=v1.2.0\ncommit=abc123\nkanaal=stabiel\ndatum=2026-10-05T14:00:00+02:00\nonzin\n")
    agen, db = await _db()
    user = (await db.execute(User.__table__.select())).first()
    u = await db.get(User, user.id)
    u.created_at = utcnow() - timedelta(days=3)
    await db.commit()
    v = (await authed.get("/api/version")).json()
    assert (v["versie"], v["commit"], v["kanaal"]) == ("v1.2.0", "abc123", "stabiel") and v["nieuw_account"] is False

    assert (await authed.post("/api/version/seen", json={"id": "2026-10-05-afronden"})).status_code == 200
    assert (await authed.get("/api/version")).json()["gezien"] == "2026-10-05-afronden"
    assert (await authed.post("/api/version/seen", json={"id": ""})).status_code == 422
    await agen.aclose()


async def test_ping_zonder_login(client):
    assert (await client.get("/api/ping")).json() == {"ok": True}
    assert (await client.get("/api/version")).status_code == 401
