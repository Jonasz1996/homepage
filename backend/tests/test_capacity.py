from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, select

from app.db import get_db
from app.main import app
from app.models import Metric, Notification
from app.monitoring.capacity import check_forecasts, forecast, sample
from app.monitoring.checks import HttpClients
from app.monitoring.watchers import watch_pbs

from .test_integrations import Fake, _group, _svc

GB = 1_000_000_000


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()  # agen meegeven zodat de sessie open blijft


def test_forecast():
    day = 86400
    pts = [(i * day / 4, 500 * GB + i * 2.5 * GB) for i in range(12)]  # 10 GB per dag
    rate, days = forecast(pts, 1000 * GB)
    assert round(rate / GB) == 10
    assert round(days) == 47  # nu 527.5 GB, nog 472.5 GB
    assert forecast(pts[:3], 1000 * GB) == (None, None)  # te weinig punten
    flat = [(i * day / 4, 500 * GB - i * GB) for i in range(12)]
    assert forecast(flat, 1000 * GB)[1] is None  # krimpt: nooit vol


async def test_sample_and_capacity_api(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    agen, db = await _db()
    n = await sample(db, HttpClients(httpx.MockTransport(Fake())))
    await db.commit()
    # 1 online node (offline telt niet), 2 guests (template niet), 1 opslag
    assert n == 4
    data = (await authed.get("/api/capacity")).json()
    assert [x["name"] for x in data["nodes"]] == ["pve50"]
    guests = {x["name"]: x for x in data["guests"]}
    assert guests["pve50/100"]["label"] == "VM 100 opnsense" and guests["pve50/100"]["mem"] == 1e9
    assert guests["pve50/101"]["cpu"] is None  # gestopt
    assert data["nodes"][0]["service"] == "PVE" and data["sampled_at"]
    # Opslag staat er meteen, een voorspelling pas na genoeg metingen.
    assert [(x["name"], x["days_left"]) for x in data["storage"]] == [("pve50/local-lvm", None)]
    assert sid


async def test_disk_full_forecast_notifies_once_per_level(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", name="PVE")
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    # 3 dagen lang elke 2 uur meten, 20 GB per dag erbij, 100 GB schijf: nu 80 GB → vol over ~1 dag
    for i in range(37):
        ts = now - timedelta(hours=72 - 2 * i)
        used = 20 * GB + i * (20 * GB / 12)
        db.add(Metric(service_id=sid, kind="storage", name="pve50/local-lvm", ts=ts, disk=int(used), disk_total=100 * GB))
    # Stabiele opslag: geen melding
    for i in range(37):
        db.add(Metric(service_id=sid, kind="storage", name="pve50/local", ts=now - timedelta(hours=72 - 2 * i),
                      disk=10 * GB, disk_total=100 * GB))
    await db.commit()
    await check_forecasts(db)
    await db.commit()
    await check_forecasts(db)
    await db.commit()
    notes = (await db.execute(select(Notification).where(Notification.source == "capaciteit"))).scalars().all()
    assert len(notes) == 1
    assert notes[0].title == "pve50/local-lvm vol over 1 dag" and notes[0].level == "err"
    assert "20.0 GB per dag" in notes[0].body

    # Opkuis: grote daling. Daarna telt alleen de trend van na de opkuis (nog te kort om te voorspellen).
    for i in range(3):
        db.add(Metric(service_id=sid, kind="storage", name="pve50/local-lvm", ts=now + timedelta(minutes=10 + i),
                      disk=30 * GB, disk_total=100 * GB))
    await db.commit()
    after = (await authed.get("/api/capacity")).json()["storage"]
    assert next(x for x in after if x["name"] == "pve50/local-lvm")["days_left"] is None
    await db.execute(delete(Metric).where(Metric.ts > now))
    await db.commit()

    cap = (await authed.get("/api/capacity")).json()["storage"]
    assert cap[0]["name"] == "pve50/local-lvm" and round(cap[0]["days_left"]) == 1
    assert cap[1]["days_left"] is None and len(cap[0]["series"]) > 10
    assert agen


async def test_pbs_watch(authed):
    g = await _group(authed)
    await _svc(authed, g, "proxmoxbackupserver", "https://pbs.jbogaert.be",
               secrets={"username": "homepage@pbs!dash", "password": "geheim"}, name="PBS")
    agen, db = await _db()
    clients = HttpClients(httpx.MockTransport(Fake()))
    await watch_pbs(db, clients)
    await db.commit()
    await watch_pbs(db, clients)
    await db.commit()
    notes = (await db.execute(select(Notification).where(Notification.source == "backup"))).scalars().all()
    assert len(notes) == 1
    assert notes[0].title == "PBS: 3 back-ups met een probleem" and notes[0].level == "err"
    assert "hdd:ct/101: laatste back-up mislukt" in notes[0].body
    assert "hdd:vm/100: verify mislukt" in notes[0].body
    assert "hdd:vm/102: geen back-up in meer dan 26 uur" in notes[0].body
    assert agen
