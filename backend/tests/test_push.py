"""Push-monitors: het geheime adres (Kuma-compatibel), het beheer ervan en de beoordeling door de worker."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select, update

from app.db import get_db
from app.main import app
from app.models import AuditLog, CheckResult, PushMonitor, Service, ServiceState, Session
from app.monitoring import push as evaluator
from app.monitoring.engine import _aware
from app.routers import push as pushroute

NO_CSRF = {"X-Requested-With": ""}
CF = {"X-Homepage-Via-Cf": "1"}


@pytest.fixture(autouse=True)
def _limits():
    pushroute._recent.clear()
    pushroute._misses._fails.clear()
    yield
    pushroute._recent.clear()
    pushroute._misses._fails.clear()


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _service(authed, **check) -> int:
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    group = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    sid = (await authed.post("/api/services", json={"group_id": group, "name": "Back-up VPS"})).json()["id"]
    # Rechtstreeks in de database: zo hangt deze test niet af van de validatie van het formulier.
    agen, db = await _db()
    s = await db.get(Service, sid)
    s.check = {"type": "push", "interval": 60, "down_after": 1, **check}
    await db.commit()
    await agen.aclose()
    return sid


async def _monitor(authed, sid) -> str:
    r = await authed.post(f"/api/services/{sid}/push")
    assert r.status_code == 200, r.text
    return r.json()["path"]


async def _row(sid) -> PushMonitor:
    agen, db = await _db()
    m = await db.get(PushMonitor, sid)
    await agen.aclose()
    return m


async def _evaluate(now):
    agen, db = await _db()
    done = await evaluator.evaluate(db, now)
    await db.commit()
    await agen.aclose()
    return done


async def _results(sid):
    agen, db = await _db()
    rows = (await db.execute(select(CheckResult).where(CheckResult.service_id == sid)
                             .order_by(CheckResult.ts))).scalars().all()
    await agen.aclose()
    return [(r.ok, r.error) for r in rows]


async def _stale():
    """Herbevestiging verlopen laten (zoals een uur later)."""
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()


# --- het adres ---------------------------------------------------------------------------------------------

async def test_adres_maken_en_slagen(authed):
    sid = await _service(authed)
    r = (await authed.get(f"/api/services/{sid}/push")).json()
    assert r == {"path": None, "outside": False, "last_at": None, "last_ok": None, "last_msg": None,
                 "last_ping": None, "count": 0}
    path = await _monitor(authed, sid)
    assert path.startswith("/api/push/") and len(path) - len("/api/push/") >= 40
    # Nog eens aanmaken geeft hetzelfde adres; het blijft te zien voor wie ingelogd is.
    assert await _monitor(authed, sid) == path
    assert (await authed.get(f"/api/services/{sid}/push")).json()["path"] == path
    assert (await authed.get("/api/services/9999/push")).status_code == 404

    # Zoals Kuma: GET met query, zonder login en zonder CSRF-header.
    r = await authed.get(f"{path}?status=up&msg=OK&ping=12.5", headers=NO_CSRF)
    assert r.status_code == 200 and r.json() == {"ok": True}
    m = await _row(sid)
    assert (m.last_ok, m.last_msg, m.last_ping, m.count) == (True, "OK", 12.5, 1)
    assert m.last_down_at is None

    # POST met JSON of een formulier, ook zonder CSRF-header.
    r = await authed.post(path, headers=NO_CSRF, json={"status": "down", "msg": "schijf vol", "ping": 7})
    assert r.status_code == 200 and r.json() == {"ok": True}
    m = await _row(sid)
    assert (m.last_ok, m.last_msg, m.last_ping, m.last_down_msg) == (False, "schijf vol", 7.0, "schijf vol")
    assert m.last_down_at is not None
    r = await authed.post(path, headers=NO_CSRF, data={"status": "up", "msg": "weer goed"})
    assert r.status_code == 200
    m = await _row(sid)
    assert (m.last_ok, m.last_msg, m.last_ping, m.count) == (True, "weer goed", None, 3)
    # De query telt boven de body.
    await authed.post(f"{path}?status=down", headers=NO_CSRF, json={"status": "up"})
    assert (await _row(sid)).last_ok is False
    # Alles behalve "up" is down (zoals Kuma), lege status is up.
    await authed.get(f"{path}?status=ok")
    assert (await _row(sid)).last_ok is False
    await authed.get(f"{path}?status=&msg=")
    m = await _row(sid)
    assert m.last_ok is True and m.last_msg is None

    r = (await authed.get(f"/api/services/{sid}/push")).json()
    assert r["count"] == 6 and r["last_ok"] is True and r["last_at"]


async def test_onbekend_adres(authed):
    for token in ("x" * 43, "kort", "x" * 101):
        r = await authed.get(f"/api/push/{token}")
        assert r.status_code == 404 and r.json() == {"detail": "Onbekend adres"}
    r = await authed.post("/api/push/" + "y" * 43, headers=NO_CSRF, json={})
    assert r.status_code == 404 and r.json() == {"detail": "Onbekend adres"}


async def test_bericht_en_ping_opgekuist(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    await authed.post(path, headers=NO_CSRF, json={"msg": "a\nb\x1b[31mc\x00d\t e  " + "x" * 400, "ping": "-5"})
    m = await _row(sid)
    assert m.last_msg.startswith("a b[31mcd e x") and len(m.last_msg) == 300
    assert m.last_ping is None
    for ping in ("700000", "abc", "nan", "inf", ""):
        await authed.get(f"{path}?ping={ping}")
        assert (await _row(sid)).last_ping is None, ping
    await authed.get(f"{path}?ping=600000")
    assert (await _row(sid)).last_ping == 600000


async def test_van_buitenaf_alleen_als_het_aanstaat(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    r = await authed.get(path, headers=CF)
    assert r.status_code == 404 and r.json() == {"detail": "Onbekend adres"}
    assert (await _row(sid)).count == 0
    assert (await authed.get(path)).status_code == 200  # thuis wel

    r = await authed.patch(f"/api/services/{sid}/push", json={"outside": True})
    assert r.status_code == 200 and r.json()["outside"] is True
    assert (await authed.get(path, headers=CF)).status_code == 200
    assert (await authed.post(path, headers={**CF, **NO_CSRF})).status_code == 200
    assert (await _row(sid)).count == 3


async def test_nieuw_adres(authed):
    sid = await _service(authed)
    old = await _monitor(authed, sid)
    r = await authed.post(f"/api/services/{sid}/push/rotate")
    assert r.status_code == 200
    new = r.json()["path"]
    assert new != old
    assert (await authed.get(old)).status_code == 404
    assert (await authed.get(new)).status_code == 200
    assert (await authed.post("/api/services/9999/push/rotate")).status_code == 404
    other = await _service(authed)
    assert (await authed.post(f"/api/services/{other}/push/rotate")).status_code == 404
    assert (await authed.patch(f"/api/services/{other}/push", json={"outside": True})).status_code == 404
    await authed.patch(f"/api/services/{sid}/push", json={"outside": True})

    agen, db = await _db()
    acts = [a.action for a in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
    await agen.aclose()
    assert [a for a in acts if a.startswith("push_")] == ["push_created", "push_rotated", "push_changed"]


async def test_beheer_vraagt_recente_bevestiging(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    await _stale()
    assert (await authed.get(f"/api/services/{sid}/push")).status_code == 200
    for method, url, body in (("post", f"/api/services/{sid}/push", None),
                              ("post", f"/api/services/{sid}/push/rotate", None),
                              ("patch", f"/api/services/{sid}/push", {"outside": True})):
        r = await getattr(authed, method)(url, json=body)
        assert r.status_code == 403 and r.json()["detail"] == "reauth_required", url
    assert (await authed.get(path)).status_code == 200  # het adres zelf werkt gewoon
    # Zonder login: geen beheer, wel het adres.
    authed.cookies.clear()
    assert (await authed.get(f"/api/services/{sid}/push")).status_code == 401
    assert (await authed.get(path)).status_code == 200


async def test_te_veel_per_adres(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    for _ in range(pushroute.PER_MINUTE):
        assert (await authed.get(path)).status_code == 200
    r = await authed.get(path)
    assert r.status_code == 429
    assert (await _row(sid)).count == pushroute.PER_MINUTE


async def test_te_veel_missers_per_ip(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    for i in range(pushroute.MAX_MISSES):
        assert (await authed.get(f"/api/push/{'z' * 40}{i:03d}")).status_code == 404
    assert (await authed.get(f"/api/push/{'z' * 43}")).status_code == 429
    # Ook een goed adres: de database wordt niet meer geraadpleegd voor dit IP.
    assert (await authed.get(path)).status_code == 429
    pushroute._misses._fails.clear()
    assert (await authed.get(path)).status_code == 200


# --- de worker ---------------------------------------------------------------------------------------------

async def test_slag_wordt_up(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    await authed.get(f"{path}?msg=OK&ping=3")
    m = await _row(sid)
    beat = _aware(m.last_at)
    assert await _evaluate(beat + timedelta(seconds=2)) == [sid]
    assert await _results(sid) == [(True, None)]
    agen, db = await _db()
    st = await db.get(ServiceState, sid)
    assert st.status == "up" and st.latency_ms == 3
    await agen.aclose()
    assert _aware((await _row(sid)).seen_at) == beat
    # Niets nieuws: niets weg te schrijven.
    assert await _evaluate(beat + timedelta(seconds=7)) == []
    assert len(await _results(sid)) == 1


async def test_geen_signaal(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    await authed.get(path)
    beat = _aware((await _row(sid)).last_at)
    await _evaluate(beat + timedelta(seconds=1))
    # Interval 60 s plus 30 s speling.
    assert await _evaluate(beat + timedelta(seconds=89)) == []
    assert await _evaluate(beat + timedelta(seconds=91)) == [sid]
    since = beat.astimezone(ZoneInfo("Europe/Brussels")).strftime("%d/%m %H:%M")
    assert await _results(sid) == [(True, None), (False, f"Geen signaal sinds {since}")]
    # Hoogstens één keer per interval, ook na een herstart van de worker (missed_at staat in de database).
    for s in (96, 120, 150):
        assert await _evaluate(beat + timedelta(seconds=s)) == []
    assert await _evaluate(beat + timedelta(seconds=152)) == [sid]
    assert [ok for ok, _ in await _results(sid)] == [True, False, False]
    agen, db = await _db()
    assert (await db.get(ServiceState, sid)).fail_count == 2
    await agen.aclose()

    # Een nieuwe slag: weer up.
    await authed.get(path)
    beat2 = _aware((await _row(sid)).last_at)
    assert await _evaluate(beat2 + timedelta(seconds=1)) == [sid]
    assert sorted(ok for ok, _ in await _results(sid)) == [False, False, True, True]
    agen, db = await _db()
    assert (await db.get(ServiceState, sid)).fail_count == 0
    await agen.aclose()


async def test_nog_nooit_een_slag(authed):
    sid = await _service(authed, interval=120)
    await _monitor(authed, sid)
    created = _aware((await _row(sid)).created_at)
    assert await _evaluate(created + timedelta(seconds=149)) == []
    assert await _evaluate(created + timedelta(seconds=151)) == [sid]
    since = created.astimezone(ZoneInfo("Europe/Brussels")).strftime("%d/%m %H:%M")
    assert await _results(sid) == [(False, f"Geen signaal sinds {since}")]


async def test_down_en_dan_up_in_een_ronde(authed):
    sid = await _service(authed)
    path = await _monitor(authed, sid)
    await authed.get(f"{path}?status=down&msg=back-up mislukt&ping=4")
    await authed.get(f"{path}?status=up&msg=OK&ping=5")
    m = await _row(sid)
    assert await _evaluate(_aware(m.last_at) + timedelta(seconds=1)) == [sid]
    # Allebei, in de volgorde waarin ze binnenkwamen.
    assert await _results(sid) == [(False, "back-up mislukt"), (True, None)]
    agen, db = await _db()
    st = await db.get(ServiceState, sid)
    assert st.status == "up" and st.fail_count == 0
    await agen.aclose()

    # Alleen down, zonder bericht.
    await authed.get(f"{path}?status=down")
    m = await _row(sid)
    assert await _evaluate(_aware(m.last_at) + timedelta(seconds=1)) == [sid]
    assert (await _results(sid))[-1] == (False, "status=down")
    assert len(await _results(sid)) == 3


async def test_gepauzeerd(authed):
    sid = await _service(authed, paused=True)
    path = await _monitor(authed, sid)
    await authed.get(f"{path}?status=down&msg=fout")
    assert (await authed.get(path)).status_code == 200  # het adres aanvaardt de slag
    m = await _row(sid)
    beat = _aware(m.last_at)
    assert m.count == 2
    assert await _evaluate(beat + timedelta(seconds=1)) == []
    assert await _evaluate(beat + timedelta(hours=2)) == []
    assert await _results(sid) == []
    # Weer aan: de slagen van tijdens de pauze tellen niet achteraf, en het interval begint opnieuw.
    agen, db = await _db()
    s = await db.get(Service, sid)
    s.check = {**s.check, "paused": False}
    await db.commit()
    await agen.aclose()
    assert await _evaluate(datetime.now(timezone.utc) + timedelta(seconds=1)) == []
    assert await _results(sid) == []


async def test_geen_push_adres(authed):
    sid = await _service(authed)
    agen, db = await _db()
    changed = _aware((await db.get(Service, sid)).updated_at)
    await agen.aclose()
    # Net aangemaakt: eerst een interval de tijd om het adres te maken.
    assert await _evaluate(changed + timedelta(seconds=30)) == []
    assert await _evaluate(changed + timedelta(seconds=61)) == [sid]
    assert await _results(sid) == [(False, "Geen push-adres: maak er een aan")]
    # Niet elke 5 s opnieuw, wel elk interval.
    assert await _evaluate(changed + timedelta(seconds=66)) == []
    assert await _evaluate(changed + timedelta(seconds=122)) == [sid]
    assert len(await _results(sid)) == 2


async def test_andere_checks_niet(authed):
    sid = await _service(authed)
    agen, db = await _db()
    s = await db.get(Service, sid)
    s.check = {"type": "http", "interval": 60}
    await db.commit()
    await agen.aclose()
    assert await _evaluate(datetime.now(timezone.utc) + timedelta(days=1)) == []
