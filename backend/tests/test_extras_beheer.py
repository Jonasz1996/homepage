from datetime import datetime, timedelta, timezone

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from app.db import get_db
from app.main import app
from app.models import Session

from .conftest import H, PASSWORD
from .test_integrations import _group, _svc, fake  # noqa: F401  (fixture)


async def _second_login(authed) -> AsyncClient:
    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test",
                        headers={**H, "User-Agent": "Firefox op gsm", "X-Country": "nl"})
    r = await other.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                                  "code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 200, r.text
    return other


async def test_sessions_list_and_revoke(authed):
    other = await _second_login(authed)
    sessions = (await authed.get("/api/auth/sessions")).json()
    assert len(sessions) == 2 and sessions[0]["current"]
    phone = sessions[1]
    assert phone["country"] == "NL" and phone["user_agent"] == "Firefox op gsm"
    assert len(phone["id"]) == 16

    # Eigen sessie kan hier niet, die meld je af met afmelden.
    assert (await authed.delete(f"/api/auth/sessions/{sessions[0]['id']}")).status_code == 400
    assert (await authed.delete(f"/api/auth/sessions/{phone['id']}")).status_code == 200
    assert (await other.get("/api/layout")).status_code == 401
    assert len((await authed.get("/api/auth/sessions")).json()) == 1
    audit = (await authed.get("/api/auth/audit")).json()["items"]
    assert audit[0]["action"] == "session_revoked" and audit[0]["user"] == "jonas"
    await other.aclose()


async def test_revoke_others_needs_recent_2fa(authed):
    other = await _second_login(authed)
    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    r = await authed.post("/api/auth/sessions/revoke-others")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    r = await authed.post("/api/auth/sessions/revoke-others")
    assert r.json() == {"ok": True, "count": 1}
    assert (await other.get("/api/layout")).status_code == 401
    await other.aclose()


async def test_audit_paging_and_filter(authed):
    for _ in range(3):
        await authed.post("/api/auth/reauth", json={"password": "fout-wachtwoord-x"})
    first = (await authed.get("/api/auth/audit?limit=2")).json()
    assert len(first["items"]) == 2 and first["more"]
    rest = (await authed.get(f"/api/auth/audit?before_id={first['items'][-1]['id']}")).json()
    assert all(i["id"] < first["items"][-1]["id"] for i in rest["items"])
    failed = (await authed.get("/api/auth/audit?action=reauth_failed")).json()["items"]
    assert len(failed) == 3


async def test_country_header_is_validated(authed):
    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test",
                        headers={**H, "X-Country": "<script>"})
    await other.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                              "code": pyotp.TOTP(authed.totp_secret).now()})
    sessions = (await authed.get("/api/auth/sessions")).json()
    assert all(s["country"] is None for s in sessions)
    await other.aclose()


async def test_notes_kept_on_form_save_and_exported(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://jellyfin.jbogaert.be", name="Jellyfin")
    r = await authed.put(f"/api/services/{sid}/notes", json={"notes": "## Herstel\nPoort **8096**  "})
    assert r.json()["notes"] == "## Herstel\nPoort **8096**"
    # Het formulier stuurt geen notities mee: die blijven staan.
    await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "Jellyfin 2"})
    svc = (await authed.get(f"/api/services/{sid}")).json()
    assert svc["notes"] == "## Herstel\nPoort **8096**" and svc["name"] == "Jellyfin 2"
    assert "Herstel" in (await authed.get("/api/export")).text
    await authed.put(f"/api/services/{sid}/notes", json={"notes": "  "})
    assert (await authed.get(f"/api/services/{sid}")).json()["notes"] is None


async def test_portainer_and_quick_actions(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "portainer", "https://portainer.jbogaert.be", secrets={"key": "ptr_geheim"},
                     name="Portainer")
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    await _svc(authed, g, "json", "https://x.jbogaert.be/status.json", name="Sensor")

    w = {f["label"]: f for f in (await authed.get("/api/widgets")).json()[str(sid)]["fields"]}
    assert w["omgevingen"]["value"] == "1/2" and w["omgevingen"]["level"] == "err"
    assert w["draaiend"]["value"] == 1 and w["gestopt"]["value"] == 1

    acts = (await authed.get("/api/actions")).json()
    mine = [(a["service"], a["id"], a["target"]) for a in acts]
    assert ("Portainer", "restart", "vaultwarden vw:latest") in mine
    assert ("Portainer", "start", "immich immich:v1") in mine
    assert ("PVE", "start", "101 homepage") in mine
    assert not any(a["service"] == "Sensor" for a in acts)

    start = next(a for a in acts if a["service"] == "Portainer" and a["id"] == "start")
    r = await authed.post(f"/api/services/{sid}/integration/action", json={"action": "start", "params": start["params"]})
    assert r.status_code == 200 and r.json()["message"] == "immich gestart"
    assert fake.calls[-1].url.path == f"/api/endpoints/2/docker/containers/{'b' * 64}/start"
    bad = await authed.post(f"/api/services/{sid}/integration/action",
                            json={"action": "stop", "params": {"env": 2, "id": "../../x"}})
    assert bad.status_code == 502
    assert pve
