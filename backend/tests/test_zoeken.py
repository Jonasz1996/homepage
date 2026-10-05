import json
import struct
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.models import ConfigVersion, CronJob, Device, LogEntry, Notification, SshHost
from app.monitoring import containerlogs
from app.monitoring.checks import HttpClients
from app.security import encrypt

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db


def _mux(*parts: tuple[int, str]) -> bytes:
    return b"".join(bytes([s, 0, 0, 0]) + struct.pack(">I", len(t.encode())) + t.encode() for s, t in parts)


def _ts(offset: float) -> str:
    return datetime.fromtimestamp(time.time() + offset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


class Portainer:
    def __init__(self):
        self.lines = {"aaa": [], "bbb": []}
        self.calls = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api/endpoints":
            return httpx.Response(200, json=[{"Id": 2, "Name": "docker01", "Status": 1}])
        if p == "/api/endpoints/2/docker/containers/json":
            return httpx.Response(200, json=[
                {"Id": "aaa" + "0" * 61, "Names": ["/plex"], "State": "running"},
                {"Id": "bbb" + "0" * 61, "Names": ["/radarr"], "State": "running"},
                {"Id": "ccc" + "0" * 61, "Names": ["/oud"], "State": "exited"}])
        if p.endswith("/logs"):
            cid = p.split("/")[-2][:3]
            self.calls.append(cid)
            since = float(req.url.params["since"])
            lines = [x for x in self.lines[cid] if x[2] > since]
            if cid == "aaa":  # zonder TTY: gemultiplexed
                return httpx.Response(200, content=_mux(*[(s, f"{t} {m}\n") for s, m, _, t in lines]))
            return httpx.Response(200, content="".join(f"{t} {m}\r\n" for _, m, _, t in lines).encode())
        return httpx.Response(404)

    def add(self, cid, stream, msg, offset=0.0):
        ts = time.time() + offset
        self.lines[cid].append((stream, msg, ts, datetime.fromtimestamp(ts, timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%S.%f000Z")))


async def test_container_logs_into_log_viewer(authed):
    world = Portainer()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "portainer", "https://portainer.jbogaert.be", secrets={"key": "k"}, name="portainer")
    await authed.post("/api/logs/rules", json={"name": "transcoder faalt", "pattern": "transcode.*failed", "level": "err",
                                               "cooldown_minutes": 0})
    world.add("aaa", 1, "Plex Media Server started", -20)
    world.add("aaa", 2, "ERROR: transcode session failed", -10)
    world.add("bbb", 1, "[WRN] indexer traag", -5)
    world.add("bbb", 1, "oude regel", -3600)  # van voor de eerste keer: niet ophalen
    agen, db = await _db()
    v = await containerlogs.run_containerlogs(db, http)
    await db.commit()
    assert v["lines"] == 3 and not v["errors"] and "ccc" not in world.calls
    rows = {(e.host, e.app, e.severity, e.msg) for e in (await db.execute(select(LogEntry))).scalars()}
    assert rows == {("plex", "docker", 6, "Plex Media Server started"), ("plex", "docker", 3, "ERROR: transcode session failed"),
                    ("radarr", "docker", 4, "[WRN] indexer traag")}
    notes = [(n.title, n.level) for n in (await db.execute(select(Notification).where(Notification.source == "syslog"))).scalars()]
    assert notes == [("plex: transcoder faalt", "err")]

    # Volgende ronde: alleen wat nieuw is, niets dubbel.
    world.add("aaa", 1, "nieuw", 0)
    v = await containerlogs.run_containerlogs(db, http)
    await db.commit()
    assert v["lines"] == 1
    assert len((await db.execute(select(LogEntry))).scalars().all()) == 4

    hosts = {h["host"]: h for h in (await authed.get("/api/logs/hosts")).json()}
    assert hosts["plex"]["docker"] and hosts["plex"]["errors"] == 1
    found = (await authed.get("/api/logs?q=transcode")).json()["items"]
    assert [i["host"] for i in found] == ["plex"]

    # Uit te zetten per tegel.
    await _svc(authed, g, "portainer", "https://p2.jbogaert.be", config={"logs": "false"}, secrets={"key": "k"}, name="p2")
    world.calls.clear()
    await containerlogs.run_containerlogs(db, http)
    assert len(world.calls) == 2


def test_frames_split_streams_and_lines():
    raw = _mux((1, "a\nb"), (2, "fout\n"), (1, "c\n"))
    assert containerlogs.frames(raw) == [(False, "a"), (True, "fout"), (False, "bc")]
    assert containerlogs.frames(b"x\r\ny\n\n") == [(False, "x"), (False, "y")]
    ts, msg = containerlogs.stamp("2026-10-05T10:00:00.123456789Z hallo wereld")
    assert msg == "hallo wereld" and abs(ts - datetime(2026, 10, 5, 10, tzinfo=timezone.utc).timestamp() - 0.123456789) < 1e-6
    assert containerlogs.severity("level=error msg=x", False) == 3
    assert containerlogs.severity("gewoon", True) == 5


async def test_search_everywhere(authed):
    g = await _group(authed)
    plex = await _svc(authed, g, "", "http://192.168.0.60:32400", name="plex")
    await authed.put(f"/api/services/{plex}/notes", json={"notes": "# Plex\nNFS-share remount: mount -a\nPoort 32400"})
    agen, db = await _db()
    h = SshHost(name="mediaserver", host="192.168.0.60", username="root", folder="pve50")
    db.add(h)
    db.add(Device(mac="aa:bb:cc:dd:ee:ff", name="mediaserver", ip="192.168.0.60", vendor="Intel"))
    db.add(Device(mac="11:22:33:44:55:66", hostname="printer", ip="192.168.0.99"))
    await db.flush()
    db.add(CronJob(key="k1", target=f"ssh:{h.id}", target_name="mediaserver", host_id=h.id, kind="cron",
                   schedule="0 3 * * *", command="/usr/local/bin/backup-plex.sh", name="backup-plex.sh"))
    npm = {"proxy-hosts": [{"id": 4, "domain_names": ["plex.jbogaert.be"], "forward_host": "192.168.0.60",
                            "forward_port": 32400}]}
    db.add(ConfigVersion(item="npm:1", name="NPM-hosts", kind="npm", sha="x", size=1,
                         content=encrypt(json.dumps(npm, indent=1))))
    db.add(ConfigVersion(item="opnsense:2", name="OPNsense config.xml", kind="opnsense", sha="y", size=1,
                         content=encrypt("<opnsense>\n<hostname>fw</hostname>\n<password>geheimwachtwoord</password>\n"
                                         "<descr>regel voor plex van buiten</descr>\n</opnsense>")))
    db.add(ConfigVersion(item="file:1:/etc/plex.env", name="/etc/plex.env op mediaserver", kind="file", sha="z", size=1,
                         content=encrypt("PLEX_CLAIM=plex-secret")))
    db.add(LogEntry(host="mediaserver", app="plexmediaserver", severity=3, msg="plex: database locked"))
    await db.commit()

    r = (await authed.get("/api/search?q=plex")).json()
    by = {x["kind"]: x for x in r["groups"]}
    assert by["note"]["items"][0]["sub"] == "Plex"  # alleen de titel bevat "plex"
    assert by["cron"]["items"][0]["title"] == "backup-plex.sh"
    assert {i["title"] for i in by["config"]["items"]} == {"NPM-hosts", "OPNsense config.xml", "/etc/plex.env op mediaserver"}
    opn = next(i for i in by["config"]["items"] if i["title"].startswith("OPNsense"))
    assert "regel voor plex" in opn["sub"]
    assert by["log"]["items"][0]["title"] == "plex: database locked"

    # Een wachtwoord in een config wordt niet gevonden (gemaskeerd), een eigen bestand alleen op naam.
    r = (await authed.get("/api/search?q=geheimwachtwoord")).json()
    assert not any(x["kind"] == "config" for x in r["groups"])
    assert not any(x["kind"] == "config" for x in (await authed.get("/api/search?q=plex-secret")).json()["groups"])

    # Een IP: apparaat, SSH-host, NPM-host, service en cronjobs van die machine.
    r = (await authed.get("/api/search?q=192.168.0.60")).json()
    assert r["service_ids"] == [plex]
    look = next(x for x in r["groups"] if x["kind"] == "lookup")
    assert [i["kind"] for i in look["items"]] == ["device", "host", "npm"]
    assert look["items"][2]["title"] == "plex.jbogaert.be" and look["items"][2]["url"] == "https://plex.jbogaert.be"
    assert next(x for x in r["groups"] if x["kind"] == "cron")["items"][0]["title"] == "backup-plex.sh"

    # Een MAC (ook met streepjes): hetzelfde, via het IP van het apparaat.
    r = (await authed.get("/api/search?q=AA-BB-CC-DD-EE-FF")).json()
    look = next(x for x in r["groups"] if x["kind"] == "lookup")
    assert look["label"] == "wat is 192.168.0.60" and len(look["items"]) == 3

    r = (await authed.get("/api/search?q=printer")).json()
    assert [i["mac"] for i in next(x for x in r["groups"] if x["kind"] == "device")["items"]] == ["11:22:33:44:55:66"]
    assert (await authed.get("/api/search?q=x")).status_code == 422
