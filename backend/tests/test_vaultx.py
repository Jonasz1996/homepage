"""VaultX: tegel, mini dashboard en check, tegen een nagebootste lees-API met de velden zoals VaultX ze geeft
(backend/app/services/stats.py en api/v1/stats.py, health.py in Jonasz1996/vaultx)."""

import httpx
import pytest

from app.models import Service
from app.monitoring import integrationchecks as ic
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

KEY = "vxk_abcdefghijklmnopqrstuvwxyz012345"
USER_KEY = "vxk_gewonegebruiker0000000000000000"
BASE = "http://192.168.0.50"


def _stats(scope="instance"):
    s = {
        "scope": scope, "version": "0.7.0", "generated_at": "2026-11-16T21:50:00Z",
        "sessions": {"active": 2, "users": 1},
        "vault": {
            "accounts": 1, "with_two_factor": 1, "last_change_at": "2026-11-16T20:12:03Z",
            "items": {"total": 412, "logins": 380, "notes": 20, "cards": 4, "identities": 3, "ssh_keys": 5, "other": 0,
                      "favorites": 12, "archived": 0, "in_trash": 7},
            "folders": 14, "attachments": {"count": 6, "bytes": 1048576},
            "devices": {"total": 3, "active_last_30_days": 2, "by_type": {"Edge-extensie": 1, "Android": 1, "Edge": 1},
                        "last_seen_at": "2026-11-16T21:40:00Z"},
        },
        "notes": {"total": 25, "in_trash": 1, "last_change_at": "2026-11-15T09:00:00Z"},
        "links": {"total": 950, "pinned": 10, "last_added_at": "2026-11-16T18:00:00Z", "collections": 22, "tags": 60},
        "catalog": {
            "applications": 18, "by_status": {"protected": 12, "restricted": 3, "unprotected": 2, "offline": 1},
            "auto_login": 5, "hosts": 21, "hosts_online": 20, "hosts_with_ssl": 21,
            "npm_connections": [{"name": "NPM", "enabled": True, "npm_version": "2.16.0",
                                 "last_sync_at": "2026-11-16T21:45:00Z", "last_sync_status": "ok"}],
        },
        "activity_last_24h": {"events": 140, "logins": 3, "failed_logins": 0, "vault_logins": 4, "failed_vault_logins": 1},
    }
    if scope == "instance":
        s["users"] = {"total": 3, "active": 3, "admins": 1, "with_authentik": 2, "with_password": 2,
                      "logged_in_last_24h": 1, "locked": 0}
    return s


class FakeVaultX:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.db_up = True
        self.expired = False
        self.stats = _stats()

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        assert req.method == "GET" and req.url.host == "192.168.0.50"
        if req.url.path == "/health/ready":
            if not self.db_up:
                return httpx.Response(503, json={"status": "unavailable", "database": "down"})
            return httpx.Response(200, json={"status": "ok", "database": "up"})
        if req.url.path != "/api/v1/stats":
            return httpx.Response(404, json={"error": "not_found", "detail": "Not Found"})
        tok = (req.headers.get("authorization") or "").removeprefix("Bearer ")
        if self.expired and tok == KEY:
            return httpx.Response(401, json={"error": "authentication_failed", "detail": "API-sleutel verlopen"},
                                  headers={"WWW-Authenticate": "Bearer"})
        if tok == KEY:
            return httpx.Response(200, json=self.stats)
        if tok == USER_KEY:
            return httpx.Response(200, json=_stats("user"))
        return httpx.Response(401, json={"error": "authentication_failed", "detail": "Ongeldige of ingetrokken API-sleutel"})


@pytest.fixture
def vx(monkeypatch):
    fake = FakeVaultX()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(router, "clients", http)
    router._cache.clear()
    return fake, http


async def _api(authed, key=KEY, config=None) -> int:
    r = await authed.post("/api/apis", json={"name": "VaultX", "category": "Overig", "kind": "vaultx",
                                             "url": BASE, "config": config or {}, "secrets": {"token": key}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _tile(authed, g, api, name="VaultX") -> int:
    sid = await _svc(authed, g, "link", "https://vaultx.jbogaert.be", name=name)
    assert (await authed.post(f"/api/apis/{api}/tiles", json={"service_ids": [sid]})).json()["changed"] == 1
    return sid


def _fields(w):
    return {f["label"]: f for f in w["fields"]}


async def test_tile_and_mini_dashboard(authed, vx):
    fake, _ = vx
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed, config={"link": "https://vaultx.jbogaert.be"}))

    f = _fields((await authed.get("/api/widgets")).json()[str(sid)])
    assert f["kluisitems"]["value"] == 412
    assert f["toestellen"]["value"] == "3 (2 actief)"
    assert f["sessies"]["value"] == 2
    assert f["logins 24u"] == {"label": "logins 24u", "value": "7 (1 mislukt)", "level": "warn"}
    assert f["apps"]["value"] == "18 (3 onbeschermd/offline)" and f["apps"]["level"] == "warn"
    assert "NPM" not in f
    # Op IP, met de sleutel als Bearer, alleen op de lees-API.
    assert {r.url.path for r in fake.requests} == {"/api/v1/stats"}
    assert fake.requests[0].headers["authorization"] == f"Bearer {KEY}"

    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    secs = {s["title"]: s for s in d["sections"]}
    assert secs["overzicht"]["href"] == "https://vaultx.jbogaert.be"
    ov = {i["label"]: i for i in secs["overzicht"]["items"]}
    assert ov["versie"]["value"] == "0.7.0" and ov["cijfers van"]["value"] == "heel VaultX (beheerder)"
    kluis = {i["label"]: i for i in secs["kluis"]["items"]}
    assert kluis["logins"]["value"] == 380 and kluis["SSH-sleutels"]["value"] == 5 and "andere" not in kluis
    assert kluis["bijlagen samen"]["value"] == {"bytes": 1048576}
    assert kluis["met tweestaps"] == {"label": "met tweestaps", "value": "1/1", "level": "ok"}
    assert "age" in kluis["laatste wijziging"]["value"]
    assert [r[0]["v"] for r in secs["toestellen"]["rows"]] == ["Edge-extensie", "Android", "Edge"]
    assert {i["label"]: i["value"] for i in secs["gebruikers"]["items"]}["beheerders"] == 1
    cat = {i["label"]: i for i in secs["appcatalogus"]["items"]}
    assert cat["onbeschermd"] == {"label": "onbeschermd", "value": 2, "level": "warn"}
    assert cat["hosts online"]["value"] == "20/21" and cat["hosts online"]["level"] == "warn"
    npm = secs["NPM-koppelingen"]["rows"][0]
    assert npm[0]["v"] == "NPM" and npm[4] == {"v": "ok", "level": "ok"}
    assert {i["label"]: i["value"] for i in secs["notities en links"]["items"]}["links"] == 950
    assert KEY not in str(d)


async def test_check_red_on_database_npm_and_expired_key(authed, vx):
    fake, http = vx
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed))

    agen, db = await _db()
    out = await ic.check_api(db, await db.get(Service, sid), {"type": "api"}, http)
    assert out.ok
    # /health/ready gaat zonder sleutel.
    ready = [r for r in fake.requests if r.url.path == "/health/ready"]
    assert ready and "authorization" not in ready[0].headers

    fake.db_up = False
    out = await ic.check_api(db, await db.get(Service, sid), {"type": "api"}, http)
    assert not out.ok and "database onbereikbaar" in out.error
    fake.db_up = True

    fake.stats["catalog"]["npm_connections"][0]["last_sync_status"] = "error"
    out = await ic.check_api(db, await db.get(Service, sid), {"type": "api"}, http)
    assert not out.ok and "NPM-sync NPM mislukt" in out.error
    fake.stats["catalog"]["npm_connections"][0]["enabled"] = False  # uitgezet: geen melding meer
    assert (await ic.check_api(db, await db.get(Service, sid), {"type": "api"}, http)).ok

    fake.expired = True
    out = await ic.check_api(db, await db.get(Service, sid), {"type": "api"}, http)
    assert not out.ok and "API-sleutel verlopen" in out.error and KEY not in out.error
    await db.close()


async def test_npm_sync_error_on_tile(authed, vx):
    fake, _ = vx
    fake.stats["catalog"]["npm_connections"][0]["last_sync_status"] = "error"
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed))
    f = _fields((await authed.get("/api/widgets")).json()[str(sid)])
    assert f["NPM"] == {"label": "NPM", "value": "sync mislukt", "level": "err"}
    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    npm = {s["title"]: s for s in d["sections"]}["NPM-koppelingen"]["rows"][0]
    assert npm[4] == {"v": "error", "level": "err"}


async def test_user_key_shows_own_numbers(authed, vx):
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed, USER_KEY))
    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    secs = {s["title"]: s for s in d["sections"]}
    assert "gebruikers" not in secs
    assert {i["label"]: i["value"] for i in secs["overzicht"]["items"]}["cijfers van"] == "enkel jouw account"


async def test_wrong_key_says_why(authed, vx):
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed, "vxk_fout"))
    w = (await authed.get("/api/widgets")).json()[str(sid)]
    assert "ingetrokken API-sleutel" in w["error"] and "401" in w["error"] and "vxk_fout" not in str(w)


async def test_template_is_known(authed, vx):
    r = (await authed.get("/api/integrations")).json()
    kinds = {i["name"] if isinstance(i, dict) else i for i in (r if isinstance(r, list) else r.get("integrations", []))}
    assert "vaultx" in kinds or "vaultx" in str(r)
