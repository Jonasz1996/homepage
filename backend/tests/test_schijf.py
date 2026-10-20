"""De kleine schijf van de container: logregels sneller comprimeren, oude logregels weg als de schijf vol raakt,
oranje vanaf 75% en rood vanaf 90%, containerlogs alleen als je ze aanzet, en een klok die een uur verkeerd staat."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.config import get_settings
from app.health import diskguard as dg, selfcheck as sc
from app.models import ApiConnection, AppState, LogEntry, Notification, Service
from app.monitoring.containerlogs import logs_on
from app.syslog.parse import parse

from .conftest import MIGRATED, alembic
from .test_meldingen_onderhoud import _db

GB = 2**30


def _usage(pct: float, path="/") -> dict:
    total = 32 * GB
    used = int(total * pct / 100)
    return {"path": str(path), "total": total, "used": used, "free": total - used, "pct": pct}


def _disk(monkeypatch, *pcts: float) -> None:
    """Zo vol is de schijf bij elke meting van de bewaker; de laatste waarde blijft."""
    left = list(pcts)
    monkeypatch.setattr(dg, "fullest", lambda: _usage(left.pop(0) if len(left) > 1 else left[0]))


def _rows(db, now: datetime, days: int = 10, per_day: int = 3) -> None:
    # Elke dag om 12 uur UTC: zo ver van middernacht dat de daggrens (en de chunk) altijd duidelijk is.
    noon = dg._day(now) + timedelta(hours=12)
    for d in range(days):
        for i in range(per_day):
            db.add(LogEntry(ts=noon - timedelta(days=d, minutes=i), host="pve50", app="sshd", severity=6,
                            msg=f"dag {d} regel {i}"))


async def _days_left(db) -> set[int]:
    return {int(m.split()[1]) for m in (await db.execute(select(LogEntry.msg))).scalars()}


async def _notes(db) -> list[Notification]:
    stmt = select(Notification).where(Notification.title.like("Schijf%")).order_by(Notification.id)
    return list((await db.execute(stmt)).scalars())


async def _chunks(db) -> int:
    return (await db.execute(text(
        "SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'log_entries'"))).scalar()


async def _timescale(db) -> bool:
    if db.bind.dialect.name != "postgresql":
        return False
    return bool((await db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar())


# --- compressie na 1 dag ----------------------------------------------------------------------------------------

async def _compress_after(db) -> list[str]:
    return list((await db.execute(text(
        "SELECT config->>'compress_after' FROM timescaledb_information.jobs "
        "WHERE hypertable_name = 'log_entries' AND proc_name = 'policy_compression'"))).scalars())


@pytest.mark.skipif(not MIGRATED, reason="alleen met HOMEPAGE_TEST_SCHEMA=migraties op PostgreSQL")
async def test_logs_gecomprimeerd_na_een_dag(authed):
    agen, db = await _db()
    if not await _timescale(db):
        pytest.skip("TimescaleDB niet beschikbaar")
    assert await _compress_after(db) == ["1 day"]
    await agen.aclose()
    try:
        alembic("downgrade", "0021")
        agen, db = await _db()
        assert await _compress_after(db) == ["3 days"]
        await agen.aclose()
    finally:
        alembic("upgrade", "head")
    agen, db = await _db()
    assert await _compress_after(db) == ["1 day"]
    await agen.aclose()


# --- schijfbewaker ----------------------------------------------------------------------------------------------

async def test_schijfbewaker_ruimt_dag_per_dag_op(authed, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    monkeypatch.setattr(dg, "BATCH", 2)  # zonder TimescaleDB: in stukken verwijderen
    agen, db = await _db()
    _rows(db, datetime.now(timezone.utc))
    await db.commit()
    hyper = await dg._hypertable(db)
    assert hyper == (MIGRATED and await _timescale(db))
    if hyper:  # oude chunks gecomprimeerd, zoals het beleid na 1 dag doet
        await db.execute(text(
            "SELECT compress_chunk(c) FROM show_chunks('log_entries', older_than => INTERVAL '2 days') c"))
        await db.commit()
        assert await _chunks(db) == 10

    # Onder 75%: niets.
    _disk(monkeypatch, 74.9)
    v = await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == set(range(10)) and not v.get("since") and not await _notes(db)

    # 80%: de oudste dag weg (79%), nog een dag (74%), dan stoppen.
    _disk(monkeypatch, 80, 79, 74)
    v = await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == set(range(8))
    if hyper:  # hele chunks weg, niet alleen de rijen
        assert await _chunks(db) == 8
    notes = await _notes(db)
    assert [(n.title, n.level) for n in notes] == [
        ("Schijf van de homepage was 80% vol: oude logregels opgeruimd", "warn")]
    assert "Logregels van voor " in notes[0].body and "was 80% vol, nu 74%" in notes[0].body
    assert v["since"] and v["noted"] and not v.get("warned") and v["removed"]

    # Zelfde keer: weer net boven 75%, nog een dag weg, maar geen tweede melding.
    _disk(monkeypatch, 76, 74)
    await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == set(range(7)) and len(await _notes(db)) == 1
    # 72% is nog niet voorbij (pas onder 70%); 60% wel.
    _disk(monkeypatch, 72)
    assert (await dg.run_diskguard(db))["since"]
    _disk(monkeypatch, 60)
    v = await dg.run_diskguard(db)
    await db.commit()
    assert not v.get("since") and not v.get("noted")

    # Een nieuwe keer: weer een melding.
    _disk(monkeypatch, 81, 73)
    await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == set(range(6)) and len(await _notes(db)) == 2
    await agen.aclose()


async def test_schijfbewaker_laat_drie_dagen_staan_en_zegt_wat_de_schijf_vult(authed, monkeypatch, tmp_path):
    (tmp_path / "homepage-2026-10-10.dump").write_bytes(b"x" * 3 * 2**20)
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    agen, db = await _db()
    _rows(db, datetime.now(timezone.utc))
    await db.commit()

    # De logregels zijn het niet: alles tot de laatste 3 dagen weg, en een melding met wat de schijf wel vult.
    _disk(monkeypatch, 85)
    v = await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == {0, 1, 2, 3}
    notes = await _notes(db)
    assert [(n.title, n.level) for n in notes] == [("Schijf van de homepage is 85% vol", "warn")]
    body = notes[0].body
    assert "Logregels van voor " in body and "helpt niet genoeg" in body and f"back-ups in {tmp_path} 3 MB" in body
    if db.bind.dialect.name == "postgresql":
        assert "grootste tabellen: " in body
    assert v["noted"] and v["warned"]

    # Volgende ronde: niets meer weg te halen en geen nieuwe melding.
    await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == {0, 1, 2, 3} and len(await _notes(db)) == 1

    # De zelfcontrole meldt 85% niet nog eens (de bewaker deed het al), 92% wel, in het rood.
    monkeypatch.setattr(sc, "disk", lambda p: _usage(85, p))
    v = await sc.run_selfcheck(db, offsite_on=False)
    await db.commit()
    assert v["alerts"]["disk"] == "warn" and len(await _notes(db)) == 1
    monkeypatch.setattr(sc, "disk", lambda p: _usage(92, p))
    await sc.run_selfcheck(db, offsite_on=False)
    await db.commit()
    assert [(n.title, n.level) for n in await _notes(db)][1:] == [("Schijf van de homepage is 92% vol", "err")]
    await agen.aclose()


async def test_schijfbewaker_wacht_op_de_eerste_back_up_na_de_update(authed, monkeypatch, tmp_path):
    # Net na de update: nog 14 volledige dumps van de oude back-up (met alle logregels); de nieuwe houdt er 5.
    for day in range(1, 15):
        (tmp_path / f"homepage-2026-09-{day:02d}.dump").write_bytes(b"x")
    (tmp_path / "voor-update-2026-09-30.dump").write_bytes(b"x")
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    agen, db = await _db()
    _rows(db, datetime.now(timezone.utc))
    await db.commit()

    # Oranje op de schijf met de back-ups: de logregels blijven, één melding over de dumps.
    monkeypatch.setattr(dg, "fullest", lambda: _usage(80, tmp_path))
    for _ in range(2):
        v = await dg.run_diskguard(db)
        await db.commit()
    assert await _days_left(db) == set(range(10)) and v["waited"] and not v.get("removed") and not v.get("warned")
    notes = await _notes(db)
    assert [(n.title, n.level) for n in notes] == [("Schijf van de homepage is 80% vol", "warn")]
    assert "staan 14 dagelijkse dumps" in notes[0].body and "systemctl start homepage-backup" in notes[0].body
    assert f"back-ups in {tmp_path}" in notes[0].body and "helpt niet genoeg" not in notes[0].body

    # Een andere schijf is vol (de dumps staan niet op die schijf): niet wachten.
    _disk(monkeypatch, 80, 79, 74)
    await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == set(range(8))

    # Rood: niet langer wachten, ook niet op de schijf met de back-ups.
    monkeypatch.setattr(dg, "fullest", lambda: _usage(92, tmp_path))
    v = await dg.run_diskguard(db)
    await db.commit()
    assert await _days_left(db) == {0, 1, 2, 3} and v["removed"] and v["warned"]

    # Na de eerste nieuwe back-up (5 dumps) ruimt de bewaker op zoals altijd.
    for day in range(1, 10):
        (tmp_path / f"homepage-2026-09-{day:02d}.dump").unlink()
    assert dg._extra_dumps(_usage(80, tmp_path)) == 0
    await agen.aclose()


async def test_schijfbewaker_zonder_logregels(authed, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    agen, db = await _db()
    _disk(monkeypatch, 77)
    v = await dg.run_diskguard(db)
    await db.commit()
    assert v["warned"] and not v.get("noted") and not v.get("removed")
    assert [n.title for n in await _notes(db)] == ["Schijf van de homepage is 77% vol"]
    # Meten lukt niet: niets doen.
    monkeypatch.setattr(dg, "fullest", lambda: None)
    assert (await dg.run_diskguard(db))["pct"] == 77
    await agen.aclose()


# --- oranje en rood ---------------------------------------------------------------------------------------------

async def test_zelfcontrole_oranje_vanaf_75_en_rood_vanaf_90(authed, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    agen, db = await _db()

    async def at(pct):
        monkeypatch.setattr(sc, "disk", lambda p: _usage(pct, p))
        v = await sc.run_selfcheck(db, offsite_on=False)
        await db.commit()
        return v

    async def selfdisk():
        items = (await authed.get("/api/attention")).json()["items"]
        return [(i["level"], i["title"]) for i in items if i["key"] == "selfdisk"]

    assert (await at(60))["alerts"]["disk"] is None and not await _notes(db) and not await selfdisk()

    assert (await at(80))["alerts"]["disk"] == "warn"
    assert [(n.title, n.level) for n in await _notes(db)] == [("Schijf van de homepage is 80% vol", "warn")]
    assert await selfdisk() == [("warn", "De schijf van de container is 80% vol")]
    summ = (await authed.get("/api/health/summary")).json()
    assert "schijf bijna vol" not in summ["problems"] and summ["warn"] >= 1
    await at(85)
    assert len(await _notes(db)) == 1  # één melding per keer

    assert (await at(92))["alerts"]["disk"] == "err"
    assert [(n.title, n.level) for n in await _notes(db)][1:] == [("Schijf van de homepage is 92% vol", "err")]
    # Op ext4 is 5% voor root: PostgreSQL stopt dan al rond 95%, niet bij 100%.
    assert "rond 95%" in (await _notes(db))[1].body and "100%" not in (await _notes(db))[1].body
    assert await selfdisk() == [("err", "De schijf van de container is 92% vol")]
    assert "schijf bijna vol" in (await authed.get("/api/health/summary")).json()["problems"]
    assert "schijf bijna vol" in (await authed.get("/api/health")).json()["summary"]["problems"]

    await at(80)  # terug naar oranje: geen nieuwe melding
    await at(50)
    assert len(await _notes(db)) == 2 and not await selfdisk()
    await at(80)  # een nieuwe keer
    assert len(await _notes(db)) == 3

    # Toestand van voor deze versie: True betekende vanaf 90%. Telt als rood, dus geen nieuwe melding bij 92%.
    st = await db.get(AppState, sc.STATE_KEY)
    st.value = {**st.value, "alerts": {**st.value["alerts"], "disk": True}}
    await db.commit()
    await at(92)
    assert len(await _notes(db)) == 3
    await agen.aclose()


# --- containerlogs en klokken -----------------------------------------------------------------------------------

def test_containerlogs_alleen_als_ze_aan_staan():
    for on in ("true", "1", "ja", "aan", "yes", " Ja ", True, 1):
        assert logs_on(Service(config={"logs": on})), on
    for off in (None, "", "false", "0", "nee", "uit", "no", "misschien", False, 0):
        assert not logs_on(Service(config={} if off is None else {"logs": off})), off
    assert not logs_on(Service(config=None))
    # Tegel aan een API uit API-beheer: logs = true in de instellingen van de API geldt voor al zijn tegels, de tegel
    # zelf kan het weer uitzetten.
    api = ApiConnection(kind="portainer", url="https://portainer", config={"logs": True})
    assert logs_on(Service(type="portainer", api_id=1, api=api, config={}))
    assert logs_on(Service(type="portainer", api_id=1, api=api, config=None))
    assert not logs_on(Service(type="portainer", api_id=1, api=api, config={"logs": "uit"}))
    assert logs_on(Service(type="portainer", api_id=1, config={"logs": "ja"},
                           api=ApiConnection(kind="portainer", url="https://portainer", config=None)))


def test_klok_van_de_bron_meer_dan_een_uur_voor_of_achter_een_dag_als_rsyslog_hem_vasthield():
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    def at(stamp: str, held: bool = False) -> datetime:
        return parse(f"<14>1 {stamp} h a - - - m".encode(), None, now, held).ts

    assert at("2026-10-11T11:30:00Z") == now - timedelta(minutes=30)  # binnen het uur: tijd van de bron
    assert at("2026-10-11T12:50:00Z") == now + timedelta(minutes=50)
    assert at("2026-10-11T14:00:00Z") == now  # twee uur in de toekomst: klok van de bron verkeerd
    # Uren achter: een klok die achterloopt. Met zijn eigen tijd stond de regel uren in het verleden, en ontbrak hij
    # bij live meekijken en in het laatste uur.
    assert at("2026-10-11T10:30:00Z") == now
    assert at("2026-10-10T12:30:00Z") == now
    # Tenzij rsyslog de regel vastgehouden kan hebben terwijl de ontvanger niet las (held, zie server.py): dan zijn
    # eigen tijd, tot een dag oud.
    assert at("2026-10-11T10:30:00Z", held=True) == now - timedelta(hours=1, minutes=30)
    assert at("2026-10-10T12:30:00Z", held=True) == now - timedelta(hours=23, minutes=30)
    assert at("2026-10-11T11:30:00Z", held=True) == now - timedelta(minutes=30)
    assert at("2026-10-11T14:00:00Z", held=True) == now
    # Met de tijdzone van de machine, zoals rsyslog hem meestuurt: in UTC, zoals de ontvangsttijd.
    local = at("2026-10-11T09:00:00.123456+02:00", held=True)
    assert local == now - timedelta(hours=5, microseconds=-123456) and local.utcoffset() == timedelta(0)
    # Meer dan een dag oud: niet in een gecomprimeerde chunk.
    assert at("2026-10-10T11:30:00Z", held=True) == now
    assert at("2026-10-08T12:00:00Z", held=True) == now
    for held in (False, True):  # niet in UTC te zetten
        assert at("0001-01-01T00:00:00+05:00", held) == at("9999-12-31T23:59:59-05:00", held) == now
