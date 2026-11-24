"""Agenda uit een ICS-feed: lezen, herhalingen, tijdzones, cache en de tegel."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
import pytest

from app.integrations import REGISTRY, IntegrationError
from app.integrations import ics
from app.integrations.ics import IcsAgenda, expand, parse, when

BXL = ZoneInfo("Europe/Brussels")


def window(text, start, days=30):
    s = datetime(*start, tzinfo=BXL)
    return expand(parse(text), s, s + timedelta(days=days), BXL)


def cal(*events: str) -> str:
    body = "\r\n".join(f"BEGIN:VEVENT\r\n{e.strip()}\r\nEND:VEVENT" for e in events)
    return f"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//NL\r\n{body}\r\nEND:VCALENDAR\r\n"


def test_eenvoudige_afspraak_met_tijdzone_escape_en_vouwen():
    text = cal("UID:1\r\nSUMMARY:Tandarts\\, controle\r\nLOCATION:Gent\r\n"
               "DESCRIPTION:lijn 1\\nlijn\r\n  2\r\nDTSTART;TZID=Europe/Brussels:20261124T100000\r\n"
               "DTEND;TZID=Europe/Brussels:20261124T110000\r\nBEGIN:VALARM\r\nSUMMARY:niet ik\r\nEND:VALARM")
    [o] = window(text, (2026, 11, 23))
    assert o.summary == "Tandarts, controle"
    assert o.description == "lijn 1\nlijn 2"
    assert o.location == "Gent"
    assert o.start == datetime(2026, 11, 24, 10, tzinfo=BXL)
    assert o.end - o.start == timedelta(hours=1)
    now = datetime(2026, 11, 23, 20, tzinfo=BXL)
    assert when(o, now, BXL) == "morgen 10:00–11:00"


def test_utc_hele_dag_en_meerdaags():
    text = cal("UID:a\r\nSUMMARY:UTC\r\nDTSTART:20261125T090000Z\r\nDURATION:PT30M",
               "UID:b\r\nSUMMARY:Verlof\r\nDTSTART;VALUE=DATE:20261126\r\nDTEND;VALUE=DATE:20261129",
               "UID:c\r\nSUMMARY:Verjaardag\r\nDTSTART;VALUE=DATE:20261127")
    occ = window(text, (2026, 11, 23))
    assert [o.summary for o in occ] == ["UTC", "Verlof", "Verjaardag"]
    assert occ[0].start.astimezone(BXL).hour == 10  # 09:00 UTC = 10:00 in Brussel (wintertijd)
    now = datetime(2026, 11, 23, 12, tzinfo=BXL)
    assert when(occ[1], now, BXL) == "do 26/11 t/m za 28/11"
    assert when(occ[2], now, BXL) == "vr 27/11 (hele dag)"


def test_wekelijks_met_exdate_en_verplaatste_keer():
    text = cal("UID:sport\r\nSUMMARY:Sport\r\nDTSTART;TZID=Europe/Brussels:20261102T190000\r\n"
               "DTEND;TZID=Europe/Brussels:20261102T200000\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,TH\r\n"
               "EXDATE;TZID=Europe/Brussels:20261126T190000",
               "UID:sport\r\nRECURRENCE-ID;TZID=Europe/Brussels:20261130T190000\r\nSUMMARY:Sport (later)\r\n"
               "DTSTART;TZID=Europe/Brussels:20261130T210000\r\nDTEND;TZID=Europe/Brussels:20261130T220000")
    occ = window(text, (2026, 11, 23), days=11)
    got = [(o.start.strftime("%a %d %H"), o.summary) for o in occ]
    assert got == [("Mon 23 19", "Sport"), ("Mon 30 21", "Sport (later)"), ("Thu 03 19", "Sport")]


def test_count_until_interval_en_maandelijks():
    text = cal("UID:x\r\nSUMMARY:Drie keer\r\nDTSTART:20261123T080000Z\r\nRRULE:FREQ=DAILY;COUNT=3",
               "UID:y\r\nSUMMARY:Om de 2 dagen\r\nDTSTART;VALUE=DATE:20261123\r\nRRULE:FREQ=DAILY;INTERVAL=2;UNTIL=20261127",
               "UID:z\r\nSUMMARY:Laatste vrijdag\r\nDTSTART;VALUE=DATE:20261030\r\nRRULE:FREQ=MONTHLY;BYDAY=-1FR",
               "UID:w\r\nSUMMARY:Jaarlijks\r\nDTSTART;VALUE=DATE:20201201\r\nRRULE:FREQ=YEARLY")
    occ = window(text, (2026, 11, 23), days=40)
    days = {}
    for o in occ:
        days.setdefault(o.summary, []).append(o.start.strftime("%m-%d"))
    assert days["Drie keer"] == ["11-23", "11-24", "11-25"]
    assert days["Om de 2 dagen"] == ["11-23", "11-25", "11-27"]
    assert days["Laatste vrijdag"] == ["11-27", "12-25"]
    assert days["Jaarlijks"] == ["12-01"]


def test_geannuleerd_en_kapotte_regels():
    text = cal("UID:1\r\nSUMMARY:Weg\r\nSTATUS:CANCELLED\r\nDTSTART:20261124T100000Z",
               "UID:2\r\nSUMMARY:Kapot\r\nDTSTART:morgen",
               "UID:3\r\nSUMMARY:Onmogelijk\r\nDTSTART;VALUE=DATE:20261123\r\nRRULE:FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=31",
               "UID:4\r\nDTSTART:20261124T100000Z")
    occ = window(text, (2026, 11, 23))
    assert [o.summary for o in occ] == ["Onmogelijk", "(zonder titel)"]  # begin telt altijd


def test_lopende_afspraak_blijft_staan():
    text = cal("UID:1\r\nSUMMARY:Bezig\r\nDTSTART:20261123T090000Z\r\nDTEND:20261123T120000Z")
    s = datetime(2026, 11, 23, 11, tzinfo=timezone.utc)
    assert [o.summary for o in expand(parse(text), s, s + timedelta(days=1), BXL)] == ["Bezig"]
    s = datetime(2026, 11, 23, 13, tzinfo=timezone.utc)
    assert expand(parse(text), s, s + timedelta(days=1), BXL) == []


def _feed_now() -> str:
    now = datetime.now(BXL).replace(minute=0, second=0, microsecond=0)
    fmt = "%Y%m%dT%H%M%S"
    return cal(f"UID:1\r\nSUMMARY:Overleg\r\nDTSTART;TZID=Europe/Brussels:{(now + timedelta(hours=2)):{fmt}}\r\nDURATION:PT1H",
               f"UID:2\r\nSUMMARY:Nu bezig\r\nDTSTART;TZID=Europe/Brussels:{(now - timedelta(hours=1)):{fmt}}\r\n"
               f"DTEND;TZID=Europe/Brussels:{(now + timedelta(hours=1, minutes=59)):{fmt}}\r\nLOCATION:Thuis")


@pytest.fixture(autouse=True)
def _leeg():
    ics._FEEDS.clear()
    yield
    ics._FEEDS.clear()


async def test_tegel_haalt_af_en_toe_op_en_houdt_query():
    seen = []
    state = {"ok": True}

    def handler(req: httpx.Request):
        seen.append(req)
        if not state["ok"]:
            return httpx.Response(502)
        return httpx.Response(200, text=_feed_now(), headers={"content-type": "text/calendar"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        i = IcsAgenda("webcal://agenda.example/ics?token=abc", {}, {}, c)
        fields = {f["label"]: f for f in await i.summary()}
        assert str(seen[0].url) == "https://agenda.example/ics?token=abc"
        assert fields["nu"]["value"] == "Nu bezig"
        assert "Overleg" in fields["volgende"]["value"]
        detail = await i.detail()
        rows = detail["sections"][0]["rows"]
        assert [r[1]["v"] for r in rows] == ["Nu bezig", "Overleg"]
        assert rows[0][2]["v"] == "Thuis"
        assert len(seen) == 1  # tweede keer uit de cache

        # Feed even weg: de oude kopie blijft, met een waarschuwing.
        state["ok"] = False
        key, (mono, at, text) = next(iter(ics._FEEDS.items()))
        ics._FEEDS[key] = (mono - 16 * 60, at - 16 * 60, text)  # ouder dan refresh (15 min)
        fields = {f["label"]: f for f in await i.summary()}
        assert fields["feed"]["level"] == "warn"
        with pytest.raises(IntegrationError):
            await i.health()


async def test_geen_ics_en_aanmelding():
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        return httpx.Response(200, text="<html><title>Login</title></html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        i = IcsAgenda("https://agenda.example/ics", {"days": "7"}, {"token": "geheim"}, c)
        with pytest.raises(IntegrationError, match="Geen ICS-agenda"):
            await i.summary()
        assert seen[0].headers["authorization"] == "Bearer geheim"
        assert i.days == 7


def test_geregistreerd():
    assert REGISTRY["ics"] is IcsAgenda
