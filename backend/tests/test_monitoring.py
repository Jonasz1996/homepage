import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from app.db import get_db
from app.main import app
from app.models import Service
from app.monitoring import checks
from app.monitoring.checks import Outcome, check_http, check_tcp, target_for
from app.monitoring.engine import DOWN_AFTER, record


def test_target_for():
    assert target_for({"type": "http"}, "https://a.be/x") == "https://a.be/x"
    assert target_for({"type": "tcp"}, "https://a.be") == "a.be:443"
    assert target_for({"type": "tcp"}, "http://a.be:8080") == "a.be:8080"
    assert target_for({"type": "ping"}, "https://a.be") == "a.be"
    assert target_for({"type": "ping", "target": "10.0.0.1"}, "https://a.be") == "10.0.0.1"
    assert target_for({"type": "http"}, None) is None


async def test_check_http_status_rules():
    def handler(request):
        return httpx.Response(503 if request.url.path == "/down" else 200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        assert (await check_http("http://x/up", {}, c)).ok
        bad = await check_http("http://x/down", {}, c)
        assert not bad.ok and bad.status_code == 503 and bad.error == "HTTP 503"
        assert (await check_http("http://x/down", {"expect_status": 503}, c)).ok


async def test_check_tcp_real_socket():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert (await check_tcp(f"127.0.0.1:{port}")).ok
    assert not (await check_tcp("127.0.0.1:1")).ok
    assert not (await check_tcp("geen-poort")).ok


async def test_ping_rejects_option_injection():
    out = await checks.check_ping("-f")
    assert not out.ok and out.error == "Ongeldig doel"


async def _service(authed, **check):
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    group = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    return (await authed.post("/api/services", json={
        "group_id": group, "name": "AdGuard", "url": "https://adguard.jbogaert.be", "check": check,
    })).json()["id"]


async def _record(sid, outcomes, start):
    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    service = await db.get(Service, sid)
    for i, o in enumerate(outcomes):
        await record(db, service, o, now=start + timedelta(minutes=i))
    await db.commit()
    await agen.aclose()


async def test_down_after_three_failures_and_recovery(authed):
    sid = await _service(authed, type="http", interval=60)
    start = datetime.now(timezone.utc) - timedelta(minutes=30)
    fails = [Outcome(False, error="Time-out")] * DOWN_AFTER
    await _record(sid, [Outcome(True, 12.0)] + fails[:-1], start)
    st = (await authed.get("/api/status")).json()[str(sid)]
    assert st["status"] == "up"  # twee fouten: nog niet down

    await _record(sid, [fails[-1]], start + timedelta(minutes=5))
    st = (await authed.get("/api/status")).json()[str(sid)]
    assert st["status"] == "down" and st["last_error"] == "Time-out"

    await _record(sid, [Outcome(True, 15.0)], start + timedelta(minutes=10))
    st = (await authed.get("/api/status")).json()[str(sid)]
    assert st["status"] == "up"
    assert st["spark"][-1] == 15.0
    assert 0 < st["uptime_24h"] < 1

    titles = [n["title"] for n in (await authed.get("/api/notifications")).json()["items"]]
    assert "AdGuard is down" in titles and "AdGuard is weer bereikbaar" in titles


async def test_history_buckets_and_outages(authed):
    sid = await _service(authed, type="http")
    start = datetime.now(timezone.utc) - timedelta(minutes=50)
    outcomes = [Outcome(True, 10.0 + i) for i in range(20)] + [Outcome(False, error="x")] * 5 \
        + [Outcome(True, 30.0)] * 10
    await _record(sid, outcomes, start)
    h = (await authed.get(f"/api/services/{sid}/history?range=1h")).json()
    assert h["checks"] == 35
    assert abs(h["uptime"] - 30 / 35) < 1e-9
    assert len(h["points"]) == 35  # 1 check per minuut, tijdvak van 60 s
    assert len(h["outages"]) == 1
    assert h["state"]["status"] == "up"
    h24 = (await authed.get(f"/api/services/{sid}/history?range=24h")).json()
    assert sum(1 for p in h24["points"]) <= 12
    assert (await authed.get(f"/api/services/{sid}/history?range=2d")).status_code == 422


async def test_restore_keeps_history(authed):
    sid = await _service(authed, type="http")
    await _record(sid, [Outcome(True, 5.0)], datetime.now(timezone.utc) - timedelta(minutes=1))
    rev = (await authed.get("/api/revisions")).json()[0]["id"]
    await authed.post("/api/pages", json={"name": "Extra"})
    await authed.post(f"/api/revisions/{rev}/restore")
    h = (await authed.get(f"/api/services/{sid}/history?range=1h")).json()
    assert h["checks"] == 1


async def test_housekeeping_removes_old_rows(authed):
    from sqlalchemy import func, select

    from app.models import Notification
    from app.monitoring.engine import housekeeping

    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    old = datetime.now(timezone.utc) - timedelta(days=40)
    db.add(Notification(title="oud", ts=old, read_at=old))
    db.add(Notification(title="oud maar ongelezen", ts=old))
    await db.commit()
    await housekeeping(db)
    await db.commit()
    titles = (await db.execute(select(Notification.title))).scalars().all()
    assert "oud" not in titles and "oud maar ongelezen" in titles
    await agen.aclose()
