"""Het dashboard vervangt Uptime Kuma: strengere checks, meldingen per check, herinneringen, pauzeren en de bewaking
van het dashboard zelf."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select, update

from app.db import get_db
from app.main import app
from app.models import (AppState, AuditLog, CheckResult, CronJob, Event, Notification, Service, ServiceState,
                        Session)
from app.monitoring import checks, engine, watchdog
from app.monitoring.checks import Outcome, check_http
from app.monitoring.engine import mass_check, record
from app.schemas import clean_check

from .test_beveiliging import _reauth

NOW = datetime.now(timezone.utc)
FAIL = Outcome(False, error="Time-out")
OK = Outcome(True, 10.0, 200)


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _group(c) -> int:
    page = (await c.post("/api/pages", json={"name": "P"})).json()["id"]
    return (await c.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]


async def _svc(c, g, name, check=None, **extra) -> int:
    r = await c.post("/api/services", json={"group_id": g, "name": name, "url": f"https://{name}.lan",
                                            "check": check or {}, **extra})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _record(db, sid, outcomes, start, step=timedelta(minutes=1)):
    service = await db.get(Service, sid)
    state = None
    for i, o in enumerate(outcomes):
        state = await record(db, service, o, now=start + i * step)
    await db.commit()
    return state


async def _titles(db) -> list[str]:
    return [n.title for n in (await db.execute(select(Notification).order_by(Notification.id))).scalars()]


# --- controle van de check ---------------------------------------------------------------------------------------

def test_check_wordt_gecontroleerd():
    assert clean_check(None) == {} and clean_check({"interval": 30}) == {}
    assert clean_check({"type": "http", "expect_status": 204}) == {"type": "http", "interval": 60, "accept": "204"}
    assert clean_check({"type": "http", "json_value": True, "json_path": "ok"})["json_value"] == "true"
    # Sneller herproberen dan het gewone interval heeft geen zin bij een trager interval.
    assert "retry_interval" not in clean_check({"type": "ping", "interval": 60, "retry_interval": 120})
    for bad, msg in (({"type": "smtp"}, "check type"), ({"type": "http", "interval": 5}, "interval"),
                     ({"type": "http", "accept": "2xx"}, "Statuscodes"),
                     ({"type": "http", "accept": "200-100"}, "klopt niet"),
                     ({"type": "http", "headers": {"Authorization": "Bearer x"}}, "lijkt geheim"),
                     ({"type": "http", "headers": {"X-Test": "a\r\nb"}}, "regeleinde"),
                     ({"type": "http", "target": "ftp://x"}, "http://"),
                     ({"type": "tcp", "target": "host"}, "host:poort"),
                     ({"type": "ping", "target": "-f host"}, "hostnaam"),
                     ({"type": "dns", "dns_server": "adguard.lan"}, "IP-adres"),
                     ({"type": "container", "portainer_id": 1}, "container"),
                     ({"type": "api", "path": "http://x/y"}, "Pad"),
                     ({"type": "http", "onbekend": 1}, "onbekend"),
                     ({"type": "http", "method": "HEAD", "keyword": "Jellyfin"}, "HEAD"),
                     ({"type": "http", "method": "HEAD", "json_path": "ok"}, "HEAD"),
                     ({"type": "push", "interval": 30}, "60 s")):
        with pytest.raises(ValueError) as e:
            clean_check(bad)
        assert msg in str(e.value), (bad, str(e.value))


async def test_foute_check_geweigerd_en_import_slaat_hem_over(authed):
    g = await _group(authed)
    r = await authed.post("/api/services", json={"group_id": g, "name": "x", "check": {"type": "tcp", "target": "x"}})
    assert r.status_code == 422 and "host:poort" in r.text
    r = await authed.post("/api/services", json={"group_id": g, "name": "x", "check": "http"})
    assert r.status_code == 422
    yaml = "- G:\n    - Goed:\n        href: https://a.lan\n    - Fout:\n        href: https://b.lan\n"
    r = await authed.post("/api/import", json={"yaml": yaml})
    assert r.status_code == 200 and "checks_skipped" not in r.json()


# --- HTTP-opties ---------------------------------------------------------------------------------------------------

async def test_http_opties():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(method=req.method, body=req.content, ctype=req.headers.get("content-type"),
                    extra=req.headers.get("x-test"))
        if req.url.host == "app.lan" and req.url.path == "/login":
            return httpx.Response(302, headers={"Location": "https://auth.lan/flow"})
        if req.url.host == "auth.lan":
            return httpx.Response(200, text="login")
        if req.url.path == "/geheim":
            return httpx.Response(401)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as c:
        out = await check_http("https://app.lan/api", {"method": "POST", "body": '{"a":1}', "headers": {"X-Test": "ja"}},
                               c)
        assert out.ok and seen == {"method": "POST", "body": b'{"a":1}', "ctype": "application/json", "extra": "ja"}
        assert not (await check_http("https://app.lan/geheim", {}, c)).ok
        out = await check_http("https://app.lan/geheim", {"accept": "200-299,401"}, c)
        assert out.ok and out.status_code == 401
        out = await check_http("https://app.lan/geheim", {"accept": "200"}, c)
        assert out.error == "HTTP 401 (verwacht 200)"
        # Doorverwezen naar de loginpagina: onthouden, en down als je dat vraagt.
        out = await check_http("https://app.lan/login", {}, c)
        assert out.ok and out.redirected_to == "auth.lan"
        out = await check_http("https://app.lan/login", {"same_host": True}, c)
        assert not out.ok and out.error == "Doorverwezen naar auth.lan (loginpagina?)"
        # Niet volgen: een 302 telt als bereikbaar (zoals altijd: alles onder 400), tenzij je de codes kiest.
        out = await check_http("https://app.lan/login", {"follow_redirects": False}, c)
        assert out.ok and out.status_code == 302 and out.redirected_to == "auth.lan"
        assert not (await check_http("https://app.lan/login", {"follow_redirects": False, "accept": "200-299"}, c)).ok
        assert not (await check_http("https://app.lan/login", {"follow_redirects": False, "same_host": True}, c)).ok


async def test_check_die_crasht_is_een_mislukte_check(monkeypatch):
    async def boom(*_a, **_k):
        raise RuntimeError("stuk")
    monkeypatch.setattr(checks, "check_tcp", boom)
    out = await checks.run_check({"type": "tcp", "target": "x:1"}, None)
    assert not out.ok and out.error == "Interne fout in de check: RuntimeError"
    out = await checks.run_check({"type": "push"}, None)
    assert not out.ok and "worker" in out.error


# --- meldingen per check ------------------------------------------------------------------------------------------

async def test_down_na_herinneren_en_meldwijze(authed):
    g = await _group(authed)
    snel = await _svc(authed, g, "snel", {"type": "http", "down_after": 1, "remind_hours": 1})
    hier = await _svc(authed, g, "hier", {"type": "http", "down_after": 1, "notify": "centrum"})
    stil = await _svc(authed, g, "stil", {"type": "http", "down_after": 1, "notify": "uit"})
    agen, db = await _db()
    start = NOW - timedelta(hours=3)
    st = await _record(db, snel, [FAIL], start)
    assert st.status == "down"
    # Een uur later: één herinnering, daarna pas weer na een uur.
    await _record(db, snel, [FAIL] * 3, start + timedelta(minutes=61), step=timedelta(minutes=10))
    await _record(db, snel, [FAIL], start + timedelta(minutes=125))
    await _record(db, hier, [FAIL], start)
    await _record(db, stil, [FAIL, OK], start)
    titles = await _titles(db)
    assert titles.count("snel is nog altijd down") == 2 and "snel is down" in titles
    assert "stil is down" not in titles and "stil is weer bereikbaar" not in titles
    events = [e.title for e in (await db.execute(select(Event))).scalars()]
    assert "stil is down" in events and "stil is weer bereikbaar" in events
    pushed = {n.title: n.pushed_at for n in (await db.execute(select(Notification))).scalars()}
    assert pushed["hier is down"] is not None and pushed["snel is down"] is None
    await agen.aclose()


async def test_kind_meldt_zich_als_de_ouder_terug_is(authed):
    g = await _group(authed)
    node = await _svc(authed, g, "node", {"type": "ping"})
    ct = await _svc(authed, g, "ct", {"type": "http"}, parent_id=node)
    agen, db = await _db()
    start = NOW - timedelta(minutes=30)
    await _record(db, node, [FAIL] * 3, start)
    await _record(db, ct, [FAIL] * 3, start)
    assert (await db.get(ServiceState, ct)).quiet
    await _record(db, node, [OK], start + timedelta(minutes=5))
    await _record(db, ct, [FAIL], start + timedelta(minutes=6))
    titles = await _titles(db)
    assert "node is down (1 services getroffen)" in titles and "ct is down" not in titles
    assert "ct is nog down" in titles
    await agen.aclose()


async def test_massastoring_een_melding(authed):
    g = await _group(authed)
    ids = [await _svc(authed, g, f"s{i}", {"type": "http"}) for i in range(6)]
    agen, db = await _db()
    start = NOW - timedelta(minutes=30)
    # Zoals bij een echte storing van het netwerk: vier checks falen in dezelfde rondes.
    for rnd in range(3):
        for sid in ids[:4]:
            await _record(db, sid, [FAIL], start + timedelta(minutes=rnd))
    titles = await _titles(db)
    assert titles.count("Het dashboard bereikt bijna niets") == 1
    assert not [t for t in titles if t.endswith("is down")]
    items = {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}
    assert items["massastoring"]["level"] == "err"
    for sid in ids[:3]:
        await _record(db, sid, [OK], start + timedelta(minutes=10))
    await mass_check(db)
    await db.commit()
    assert not (await db.get(AppState, engine.MASS_KEY)).value
    await _record(db, ids[3], [FAIL], start + timedelta(minutes=11))
    assert "s3 is nog down" in await _titles(db)
    await agen.aclose()


async def test_massastoring_telt_gemelde_storingen_niet(authed):
    """Een pc die meestal uit staat, is al apart gemeld: die mag geen massastoring starten of laten duren."""
    g = await _group(authed)
    ids = [await _svc(authed, g, f"s{i}", {"type": "http"}) for i in range(8)]
    agen, db = await _db()
    start = NOW - timedelta(hours=2)
    for sid in ids[:2]:
        await _record(db, sid, [FAIL] * 3, start)
    # Eén echte storing erbij: 3 van de 8 falen, maar dat is gewoon "s2 is down".
    await _record(db, ids[2], [FAIL] * 3, start + timedelta(minutes=10))
    titles = await _titles(db)
    assert "s2 is down" in titles and "Het dashboard bereikt bijna niets" not in titles
    await _record(db, ids[2], [OK], start + timedelta(minutes=20))
    # Nu wel alles tegelijk (de zes die nog liepen): massastoring.
    for rnd in range(3):
        for sid in ids[2:]:
            await _record(db, sid, [FAIL], start + timedelta(minutes=30 + rnd))
    assert (await _titles(db)).count("Het dashboard bereikt bijna niets") == 1
    # Ze herstellen; de twee oude blijven down. Toch voorbij, en een nieuwe storing wordt weer gemeld.
    for sid in ids[2:]:
        await _record(db, sid, [OK], start + timedelta(minutes=40))
    await mass_check(db)
    await db.commit()
    assert not (await db.get(AppState, engine.MASS_KEY)).value
    await _record(db, ids[7], [FAIL] * 3, start + timedelta(minutes=50))
    assert "s7 is down" in await _titles(db)
    await agen.aclose()


async def test_massastoring_tegelijk_een_melding(authed):
    """Checks uit dezelfde ronde falen tegelijk, elk in een eigen sessie: toch maar één melding."""
    g = await _group(authed)
    ids = [await _svc(authed, g, f"s{i}", {"type": "http"}) for i in range(8)]
    agen, db = await _db()
    if db.bind.dialect.name == "sqlite":
        await agen.aclose()
        pytest.skip("SQLite heeft één verbinding: tegelijk schrijven kan daar niet")
    start = NOW - timedelta(minutes=10)
    for sid in ids:
        await _record(db, sid, [FAIL, FAIL], start)

    async def fail(sid):
        a, s = await _db()
        try:
            await record(s, await s.get(Service, sid), FAIL, start + timedelta(minutes=3))
            await s.commit()
        finally:
            await a.aclose()
    await asyncio.gather(*(fail(sid) for sid in ids))
    assert (await _titles(db)).count("Het dashboard bereikt bijna niets") == 1
    await agen.aclose()


async def test_ouder_met_meldingen_uit_houdt_het_kind_niet_stil(authed):
    g = await _group(authed)
    node = await _svc(authed, g, "node", {"type": "ping", "notify": "uit"})
    plex = await _svc(authed, g, "plex", {"type": "http"}, parent_id=node)
    agen, db = await _db()
    start = NOW - timedelta(minutes=10)
    await _record(db, node, [FAIL] * 3, start)
    await _record(db, plex, [FAIL] * 3, start)
    titles = await _titles(db)
    assert "plex is down" in titles and "node is down" not in titles
    await agen.aclose()


async def test_lange_doorverwijzing_past_in_de_database(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "wiki", {"type": "http"})
    agen, db = await _db()
    host = ".".join(["a" * 60] * 5)
    st = await _record(db, sid, [Outcome(False, 5.0, 302, f"Doorverwezen naar {host} (loginpagina?)", None, host)],
                       NOW)
    assert len(st.redirected_to) == 255 and len(st.last_error) == 300
    await agen.aclose()


# --- pauzeren, stilzetten en oude status ----------------------------------------------------------------------------

async def test_pauzeren_vraagt_2fa_en_wist_de_status(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "wiki", {"type": "http"})
    agen, db = await _db()
    await _record(db, sid, [FAIL] * 3, NOW - timedelta(minutes=10))
    await db.execute(update(Session).values(auth_at=NOW - timedelta(hours=1)))
    await db.commit()
    r = await authed.post(f"/api/services/{sid}/pause", json={"paused": True})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    base = {"group_id": g, "name": "wiki", "url": "https://wiki.lan"}
    r = await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "http", "paused": True}})
    assert r.status_code == 403
    r = await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "http", "notify": "uit"}})
    assert r.status_code == 403
    await _reauth(authed)
    assert (await authed.post(f"/api/services/{sid}/pause", json={"paused": True})).status_code == 200
    st = (await authed.get("/api/status")).json()[str(sid)]
    assert st["status"] is None and st["paused"] is True
    assert await db.get(ServiceState, sid) is None
    assert "Check gepauzeerd: wiki" in await _titles(db)
    # Hervatten mag zonder 2FA.
    await db.execute(update(Session).values(auth_at=NOW - timedelta(hours=1)))
    await db.commit()
    assert (await authed.post(f"/api/services/{sid}/pause", json={"paused": False})).status_code == 200
    actions = [a.action for a in (await db.execute(select(AuditLog))).scalars()]
    assert "check_paused" in actions and "check_resumed" in actions
    await agen.aclose()


async def test_ander_doel_begint_met_een_schone_status(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "nas", {"type": "http"})
    agen, db = await _db()
    await _record(db, sid, [FAIL] * 3, NOW - timedelta(minutes=10))
    base = {"group_id": g, "name": "nas", "url": "https://nas.lan"}
    # Alleen het interval: status blijft.
    assert (await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "http", "interval": 120}})
            ).status_code == 200
    db.expire_all()
    assert (await db.get(ServiceState, sid)).status == "down"
    assert (await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "ping"}})).status_code == 200
    db.expire_all()
    assert await db.get(ServiceState, sid) is None
    await agen.aclose()


async def test_uptime_per_periode_en_twijfel(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "git", {"type": "http", "down_after": 4})
    agen, db = await _db()
    await _record(db, sid, [OK] * 3 + [FAIL], NOW - timedelta(minutes=5))
    st = (await authed.get("/api/status")).json()[str(sid)]
    assert st["status"] == "up" and st["fail_count"] == 1 and st["down_after"] == 4
    h = (await authed.get(f"/api/services/{sid}/history?hours=24")).json()
    assert set(h["uptime_all"]) == {"24h", "7d", "30d", "1y"} and h["uptime_all"]["24h"] == pytest.approx(0.75)
    await agen.aclose()


# --- bewaking van het dashboard zelf ------------------------------------------------------------------------------

async def test_vastgelopen_checks(authed):
    g = await _group(authed)
    a = await _svc(authed, g, "a", {"type": "http"})
    b = await _svc(authed, g, "b", {"type": "http", "interval": 3600})
    agen, db = await _db()
    await _record(db, a, [OK], NOW - timedelta(minutes=20))
    await _record(db, b, [OK], NOW - timedelta(minutes=20))
    assert await watchdog.stale_checks(db, NOW) == ["a"]
    await db.commit()
    st = (await authed.get("/api/status")).json()[str(a)]
    assert st["stale"] is True and st["status"] == "up"
    assert "De check van a loopt niet meer" in await _titles(db)
    # Nog eens: geen tweede melding. Een nieuw resultaat maakt hem weer gewoon.
    assert await watchdog.stale_checks(db, NOW) == []
    await _record(db, a, [OK], NOW)
    assert not (await db.get(ServiceState, a)).stale
    await agen.aclose()


async def test_healthz(authed, monkeypatch):
    monkeypatch.setattr(watchdog, "_healthz", None)
    monkeypatch.setattr(watchdog, "_seen_saved", 0.0)
    r = await authed.get("/api/healthz")
    assert r.status_code == 503 and r.json() == {"ok": False}
    agen, db = await _db()
    db.add(AppState(key="worker", value={"at": datetime.now(timezone.utc).isoformat()}))
    await db.commit()
    monkeypatch.setattr(watchdog, "_healthz", None)
    assert (await authed.get("/api/healthz")).status_code == 200
    # Een check zonder resultaat in de laatste 5 minuten: niet gezond.
    g = await _group(authed)
    sid = await _svc(authed, g, "x", {"type": "http"})
    db.add(CheckResult(service_id=sid, ts=datetime.now(timezone.utc) - timedelta(minutes=10), ok=True))
    await db.commit()
    monkeypatch.setattr(watchdog, "_healthz", None)
    assert (await authed.get("/api/healthz")).status_code == 503
    # Van buitenaf bestaat hij niet, en zonder login.
    assert (await authed.get("/api/healthz", headers={"X-Homepage-Via-Cf": "1"})).status_code == 404
    seen = await db.get(AppState, watchdog.SEEN_KEY)
    assert seen and seen.value["at"]
    rows = {r["key"]: r for grp in (await authed.get("/api/attention/setup")).json()["groups"] for r in grp["rows"]}
    assert rows["wachter"]["state"] == "ok"
    await agen.aclose()


async def test_stilte_na_herstart(authed):
    agen, db = await _db()
    db.add(AppState(key="worker", value={"at": (NOW - timedelta(hours=2)).isoformat()}))
    await db.commit()
    await watchdog.report_gap(db, NOW)
    await watchdog.report_gap(db, NOW - timedelta(hours=2) + timedelta(minutes=1))
    titles = [t for t in await _titles(db) if "stil" in t]
    assert titles == ["Het dashboard was 2 u 0 min stil"]
    await agen.aclose()


async def test_api_antwoordt_niet(authed, monkeypatch):
    monkeypatch.setattr(watchdog, "_api_fails", 0)
    up = [False]

    def handler(_req):
        return httpx.Response(200 if up[0] else 502)
    agen, db = await _db()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        for _ in range(4):
            await watchdog.check_api(db, c)
        up[0] = True
        await watchdog.check_api(db, c)
    await db.commit()
    assert (await _titles(db)).count("De API van de homepage antwoordt niet") == 1
    assert "De API van de homepage antwoordt weer" in [e.title for e in (await db.execute(select(Event))).scalars()]
    await agen.aclose()


async def test_checklist_dekking(authed):
    g = await _group(authed)
    await _svc(authed, g, "zonder")
    sid = await _svc(authed, g, "met", {"type": "http"})
    await _svc(authed, g, "backup", {"type": "push"})
    agen, db = await _db()
    await _record(db, sid, [Outcome(True, 5.0, 200, redirected_to="auth.lan")], NOW)
    db.add(CronJob(key="k1", target="ssh:1", target_name="pve2", kind="crontab", name="rsync",
                   command="rsync -a /data /mnt && curl -fsS https://kuma.lan/api/push/AbCdEf0123456789xyz?status=up"))
    await db.commit()
    rows = {r["key"]: r for grp in (await authed.get("/api/attention/setup")).json()["groups"] for r in grp["rows"]}
    row = rows["monitoring:dekking"]
    todo = " | ".join(row["todo"])
    assert row["state"] == "half" and "zonder" in row["todo"][0] and "auth.lan" in todo
    assert "backup: push-check zonder adres" in todo and "Cronjob rsync op pve2" in todo
    assert rows["wachter"]["state"] == "none" and rows["webpush"]["state"] == "none"
    assert rows["webpush"]["fix"] == {"window": "webpush"}
    await agen.aclose()


# --- na het nalezen ------------------------------------------------------------------------------------------------

async def test_vastgelopen_check_houdt_zijn_status(authed):
    """Een check die even niets meldt (herstart van de worker), verliest zijn down niet: daarna volgt nog altijd
    "weer bereikbaar", en geen tweede "is down"."""
    g = await _group(authed)
    a = await _svc(authed, g, "nas", {"type": "http"})
    b = await _svc(authed, g, "wiki", {"type": "http"})
    agen, db = await _db()
    start = NOW - timedelta(minutes=40)
    await _record(db, a, [FAIL] * 3, start)
    await _record(db, b, [FAIL] * 3, start)
    assert sorted(await watchdog.stale_checks(db, NOW)) == ["nas", "wiki"]
    await db.commit()
    assert (await db.get(ServiceState, a)).status == "down"
    await _record(db, a, [OK], NOW)
    await _record(db, b, [FAIL], NOW)
    titles = await _titles(db)
    assert "nas is weer bereikbaar" in titles and titles.count("wiki is down") == 1
    # Wat de worker nu uitvoert, is niet vastgelopen (na een herstart duurt de eerste ronde even).
    assert await watchdog.stale_checks(db, NOW + timedelta(hours=1), running={a, b}) == []
    await agen.aclose()


async def test_healthz_met_trage_checks(authed):
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    db.add(AppState(key="worker", value={"at": now.isoformat()}))
    g = await _group(authed)
    sid = await _svc(authed, g, "x", {"type": "http", "interval": 900})
    db.add(CheckResult(service_id=sid, ts=now - timedelta(minutes=10), ok=True))
    await db.commit()
    # Elk kwartier een check: 10 minuten zonder resultaat is normaal, 50 niet.
    assert await watchdog.healthy(db, now)
    assert not await watchdog.healthy(db, now + timedelta(minutes=40))
    await agen.aclose()


async def test_check_weghalen_vraagt_2fa(authed):
    """Zonder check of zonder tegel bewaakt het dashboard niets meer: dat is net zo stil als pauzeren."""
    g = await _group(authed)
    wiki = await _svc(authed, g, "wiki", {"type": "http"})
    link = await _svc(authed, g, "link")
    agen, db = await _db()

    async def stale():
        await db.execute(update(Session).values(auth_at=NOW - timedelta(hours=1)))
        await db.commit()
    await stale()
    base = {"group_id": g, "name": "wiki", "url": "https://wiki.lan"}
    r = await authed.patch(f"/api/services/{wiki}", json={**base, "check": {}})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    r = await authed.delete(f"/api/services/{wiki}")
    assert r.status_code == 403
    assert (await authed.delete(f"/api/groups/{g}")).status_code == 403
    # Een tegel zonder check mag gewoon weg.
    assert (await authed.delete(f"/api/services/{link}")).status_code == 200
    await _reauth(authed)
    assert (await authed.patch(f"/api/services/{wiki}", json={**base, "check": {}})).status_code == 200
    assert "Check verwijderd: wiki" in await _titles(db)
    # Een oude versie terugzetten die de tegel weghaalt: ook stil.
    await authed.patch(f"/api/services/{wiki}", json={**base, "check": {"type": "http"}})
    before = next(r["id"] for r in (await authed.get("/api/revisions")).json() if r["summary"] == "Groep 'G' toegevoegd")
    await stale()
    r = await authed.post(f"/api/revisions/{before}/restore")
    assert r.status_code == 403
    await _reauth(authed)
    assert (await authed.delete(f"/api/services/{wiki}")).status_code == 200
    actions = [a.action for a in (await db.execute(select(AuditLog))).scalars()]
    assert actions.count("check_silenced") == 2
    await agen.aclose()


async def test_resultaat_van_een_oude_check_telt_niet(authed, monkeypatch):
    """De check liep nog toen het doel veranderde: dat resultaat hoort niet bij de nieuwe check."""
    from contextlib import asynccontextmanager

    from app.monitoring import worker as worker_mod

    g = await _group(authed)
    sid = await _svc(authed, g, "nas", {"type": "http", "down_after": 1})

    @asynccontextmanager
    async def maker():
        a, s = await _db()
        try:
            yield s
        finally:
            await a.aclose()

    async def moved(*_args):
        r = await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "nas", "url": "https://nas2.lan",
                                                              "check": {"type": "http", "down_after": 1}})
        assert r.status_code == 200
        return FAIL
    monkeypatch.setattr(worker_mod, "check_service", moved)
    w = worker_mod.Worker(maker)
    await w.run_one(sid, {"type": "http", "down_after": 1}, "https://nas.lan")
    agen, db = await _db()
    assert await db.get(ServiceState, sid) is None
    assert "nas is down" not in await _titles(db)
    await agen.aclose()
