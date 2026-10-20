import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from sqlalchemy import select, update

from app.cron import links, probe, wrap
from app.cron.schedule import describe, next_after, occurrences, parse_calendar, parse_cron, tz_of
from app.db import get_db
from app.main import app
from app.models import CronJob, CronRun, Event, Notification, SshHost

from .test_ssh import WS, _cookie

BXL = tz_of("Europe/Brussels")


def test_schedules_in_plain_dutch():
    assert describe(parse_cron("30 3 * * 1-5")) == "ma–vr om 03:30"
    assert describe(parse_cron("*/15 * * * *")) == "elke 15 minuten"
    assert describe(parse_cron("0 4 1 * *")) == "op de 1e van de maand om 04:00"
    assert describe(parse_cron("0 */6 * * *")) == "elke 6 uur om :00"
    assert describe(parse_calendar("sun 01:00")) == "zo om 01:00"
    assert describe(parse_calendar("*/15")) == "elke 15 minuten"
    assert describe(parse_calendar("mon..fri 02:30")) == "ma–vr om 02:30"
    assert describe(parse_calendar("*-*-* 06,18:00:00")) == "elke dag om 06:00 en 18:00"
    # Cron: dag van de maand én weekdag vast = één van de twee volstaat.
    s = parse_cron("0 0 1 * 1")
    t = datetime(2026, 10, 5, tzinfo=timezone.utc)  # maandag 5 oktober
    assert s.day_ok(t.replace(tzinfo=None)) and s.day_ok(datetime(2026, 10, 1))


def test_occurrences_follow_local_time_and_dst():
    start = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    got = occurrences(parse_cron("0 3 * * *"), start, start + timedelta(days=2), BXL)
    # Zomertijd tot 25 oktober 03:00: eerst 01:00 UTC, daarna 02:00 UTC.
    assert [g.hour for g in got] == [1, 2]
    assert next_after(parse_calendar("sat 01:00"), start, BXL) == datetime(2026, 10, 23, 23, tzinfo=timezone.utc)


def test_targets_from_commands():
    t = links.from_text('rsync -az -e "ssh -p 2222" /srv/ backup@192.168.0.60:/volume1/pve/')
    assert t == [{"type": "host", "ref": "192.168.0.60", "label": "192.168.0.60:/volume1/pve/", "via": "rsync", "dir": "out"}]
    assert links.from_text("curl -fsS https://hc-ping.com/abc")[0]["type"] == "ping"
    assert links.from_text("scp nas:/etc/x.conf /root/")[0]["dir"] == "in"
    assert links.from_text("PBS_REPOSITORY=root@pam@pbs.lan:main proxmox-backup-client backup r.pxar:/")[0] == {
        "type": "pbs", "ref": "pbs.lan", "label": "pbs.lan/main", "via": "proxmox-backup-client", "datastore": "main"}
    assert links.from_text("echo hallo") == []


def test_wrap_round_trip_and_refusals():
    content = "SHELL=/bin/sh\n30 3 * * *  root  /root/backup.sh --full >/dev/null 2>&1\n"
    line = probe.cron_lines(content, True)[0]
    new, new_line, cmd = wrap.rewrite(content, line["raw"], line["command"], "abc1234567", True)
    assert cmd == "/usr/local/bin/hp-cron abc1234567 '/root/backup.sh --full >/dev/null 2>&1'"
    assert probe.unwrap(cmd) == ("/root/backup.sh --full >/dev/null 2>&1", "abc1234567")
    back, _, _ = wrap.rewrite(new, new_line, cmd, "abc1234567", False)
    assert back == content
    with pytest.raises(wrap.WrapError):
        wrap.rewrite(content.replace("--full", "--quick"), line["raw"], line["command"], "x" * 10, True)
    pct = "0 1 * * * root mail -s x me@x %body\n"
    with pytest.raises(wrap.WrapError):
        wrap.rewrite(pct, pct.rstrip(), probe.cron_lines(pct, True)[0]["command"], "abc1234567", True)
    assert "it'\\''s" in probe.wrap("echo it's", "abc1234567")


# --- Een gesimuleerde Proxmox-node en PBS -------------------------------------------------------

def node_output(now: int, cronlog: bool = True, wrapped_rc: int = 1, sync_time: str = "0 4 * * *") -> str:
    ago = lambda s: now - s  # noqa: E731
    pve = {
        "backup": [{"id": "backup-nacht", "schedule": "01:00", "storage": "pbs-pi", "all": 1, "mode": "snapshot",
                    "enabled": 1}],
        "replication": [{"id": "105-0", "guest": 105, "target": "pve100", "schedule": "*/30"}],
        "storage": [{"storage": "pbs-pi", "type": "pbs", "server": "pbs-pi.lan", "datastore": "main"},
                    {"storage": "local", "type": "dir", "path": "/var/lib/vz"}],
        "status": [{"type": "cluster", "name": "thuis", "nodes": 2},
                   {"type": "node", "name": "pve50", "ip": "127.0.0.1", "online": 1},
                   {"type": "node", "name": "pve100", "ip": "192.168.0.100", "online": 1}],
        "resources": [{"vmid": 105, "name": "plex", "node": "pve50", "type": "lxc"}],
        "repstatus": [{"id": "105-0", "guest": 105, "target": "pve100", "last_sync": ago(600), "next_sync": now + 1200,
                       "duration": 4.2, "fail_count": 0}],
        "tasks": [],
    }
    log_lines = ""
    if cronlog:
        log_lines = f"{ago(4000)}.0 pve50 CRON[123]: (root) CMD (/root/sync.sh)\n"
    run = {"id": "1a2b3c4d5e", "start": ago(120), "end": ago(100), "rc": wrapped_rc,
           "out": base64.b64encode(b"verbinding met nas mislukt\n").decode()}
    j = lambda o: json.dumps(o)  # noqa: E731
    return f"""@@HOST
@@META pve50 Europe/Brussels {now}
@@FILE /etc/crontab
SHELL=/bin/sh
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
@@FILE /etc/cron.d/backup-nas
30 2 * * * root rsync -a /srv/ backup@192.168.0.60:/volume1/pve/
@@USER root /var/spool/cron/crontabs/root
# mijn jobs
*/5 * * * * /usr/local/bin/hp-cron 1a2b3c4d5e '/root/check.sh'
{sync_time} /root/sync.sh
@@PERIODIC /etc/cron.hourly zfs-check
@@TIMER backup-db.timer backup-db.service
Description=Database dump
TimersCalendar={{ OnCalendar=*-*-* 03:15:00 ; next_elapse=@{now + 3600} }}
TimersMonotonic=
NextElapseUSecRealtime=@{now + 3600}
LastTriggerUSec=@{ago(80000)}
ActiveState=active
UnitFileState=enabled
U.ExecStart={{ path=/usr/bin/pg_dump ; argv[]=/usr/bin/pg_dump -f /mnt/backup/db.sql app ; ignore_errors=no }}
U.Result=success
U.ExecMainStatus=0
U.ExecMainStartTimestamp=@{ago(80000)}
U.ExecMainExitTimestamp=@{ago(79940)}
U.User=
U.InvocationID=abc
U.FragmentPath=/etc/systemd/system/backup-db.service
@@OUT backup-db.service
dump klaar
@@TIMER apt-daily.timer apt-daily.service
TimersCalendar={{ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=@{now + 100} }}
NextElapseUSecRealtime=@{now + 100}
LastTriggerUSec=@{ago(100)}
ActiveState=active
UnitFileState=enabled
U.ExecStart={{ path=/usr/lib/apt/apt.systemd.daily ; argv[]=/usr/lib/apt/apt.systemd.daily update ; }}
U.Result=success
U.ExecMainStatus=0
@@CRONLOG
{log_lines}@@WRAPLOG
@@RUN {j(run)}
@@PVE pve50
@@J backup
{j(pve['backup'])}
@@J replication
{j(pve['replication'])}
@@J storage
{j(pve['storage'])}
@@J status
{j(pve['status'])}
@@J resources
{j(pve['resources'])}
@@J repstatus
{j(pve['repstatus'])}
@@J tasks
{j(pve['tasks'])}
@@CT 105 plex
@@META plex Europe/Brussels {now}
@@USER root /var/spool/cron/crontabs/root
0 5 * * * curl -fsS https://hc-ping.com/plex-backup
@@CRONLOG
@@WRAPLOG
"""


def pbs_output(now: int) -> str:
    j = json.dumps
    tasks = [{"upid": "x", "worker_type": "syncjob", "worker_id": "offsite:main:main:s-1", "starttime": now - 7000,
              "endtime": now - 6000, "status": "OK"},
             {"upid": "y", "worker_type": "garbage_collection", "worker_id": "main", "starttime": now - 5000,
              "endtime": now - 4000, "status": "TASK ERROR: disk full"}]
    return f"""@@HOST
@@META pbs-pi Europe/Brussels {now}
@@PBS pbs-pi
@@J pbs-sync-job
{j([{"id": "s-1", "store": "main", "remote": "offsite", "remote-store": "main", "schedule": "daily"}])}
@@J pbs-verify-job
{j([{"id": "v-1", "store": "main", "schedule": "sat 05:00"}])}
@@J pbs-prune-job
[]
@@J pbs-datastore
{j([{"name": "main", "path": "/mnt/main", "gc-schedule": "01:30"}])}
@@J pbs-remote
{j([{"name": "offsite", "host": "10.0.0.9"}])}
@@J pbs-tasks
{j(tasks)}
"""


def test_parse_node_output():
    now = int(time.time())
    machines = probe.split_machines(node_output(now))
    assert [(k, n) for k, n, _ in machines] == [("host", None), ("ct", "105 plex")]
    p = probe.parse(machines[0][2], "ssh:1")
    by = {j["name"]: j for j in p["jobs"]}
    assert by["cron.hourly (1 scripts)"]["system"]
    assert by["rsync"]["targets"][0]["ref"] == "192.168.0.60"
    assert by["check.sh"]["monitored"] and by["check.sh"]["wid"] == "1a2b3c4d5e" and by["check.sh"]["command"] == "/root/check.sh"
    db = by["backup-db"]
    assert db["kind"] == "timer" and db["schedule"] == "*-*-* 03:15:00" and db["last_status"] == "ok"
    assert db["last_duration"] == 60 and db["extra"]["output"] == "dump klaar"
    assert db["targets"] == [{"type": "path", "ref": "/mnt/backup", "label": "/mnt/backup", "via": "pg_dump", "dir": "out"}]
    assert by["apt-daily"]["system"]
    b = by["back-up naar pbs-pi"]
    assert b["key"] == "pve:thuis:backup:backup-nacht" and b["targets"][0]["ref"] == "pbs-pi.lan"
    assert p["runs"][0]["exit_code"] == 1 and p["runs"][0]["output"] == "verbinding met nas mislukt\n"
    assert p["log_ok"] and len(p["cronlog"]) == 1
    q = probe.parse(pbs_output(now), "ssh:2")
    names = sorted(j["name"] for j in q["jobs"])
    assert names == ["garbage collection main", "sync van offsite:main → main", "verify main"]
    sync = next(j for j in q["jobs"] if j["kind"] == "pbs-sync")
    assert sync["targets"][0]["dir"] == "in" and len(sync["pbs_tasks"]) == 1


# --- Via SSH, opslaan, meldingen en de API ----------------------------------------------------

class Fake:
    def __init__(self, output):
        self.output = output
        self.commands: list[str] = []
        self.files: dict[str, str] = {}
        self.key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(self, proc):
        cmd = proc.command or ""
        self.commands.append(cmd)
        if "@@HOST" in cmd:
            proc.stdout.write(self.output())
        elif "@@SCRIPT" in cmd:
            proc.stdout.write("@@SCRIPT /root/sync.sh\n#!/bin/sh\nrclone sync /data gdrive:backup\n")
        elif "hp-cron.new" in cmd:
            proc.stdout.write("@@OK\n")
        elif "crontab -l -u root" in cmd and "base64 -d" not in cmd:
            proc.stdout.write(self.files.get("root", "") + "@@END\n")
        elif "crontab -u root -" in cmd:
            b = cmd.split("echo ", 1)[1].split(" ", 1)[0]
            self.files["root"] = base64.b64decode(b).decode()
            proc.stdout.write("@@OK\n")
        elif "exec sh -c" in cmd:
            proc.stdout.write("bezig met sync\nklaar\n")
            proc.exit(0)
            return
        proc.exit(0)

    async def start(self):
        class S(asyncssh.SSHServer):
            def begin_auth(self, u):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, u, p):
                return p == "pw"

        self.server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[self.key],
                                                   process_factory=self.handle)
        return self.server.sockets[0].getsockname()[1]


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _host(authed, name, port, key):
    hid = (await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                     "password": "pw"})).json()["id"]
    agen, db = await _db()
    h = await db.get(SshHost, hid)
    h.host_key = key.export_public_key().decode()
    await db.commit()
    return hid


async def _scan(authed):
    from app.cron.scan import run_scan
    agen, db = await _db()
    v = await run_scan(db)
    await db.commit()
    return v


async def test_scan_store_alerts_and_api(authed):
    now = {"t": int(time.time()), "rc": 1, "log": True, "sync": "0 4 * * *"}
    node = Fake(lambda: node_output(now["t"], now["log"], now["rc"], now["sync"]))
    pbs = Fake(lambda: pbs_output(now["t"]))
    hid = await _host(authed, "pve50", await node.start(), node.key)
    await _host(authed, "pbs-pi", await pbs.start(), pbs.key)
    # Een host zonder bevestigde sleutel staat apart, de container 105 als host ook niet dubbel.
    await authed.post("/api/ssh/hosts", json={"name": "nieuw", "host": "10.9.9.9", "password": "pw"})

    state = await _scan(authed)
    assert [t["key"] for t in state["targets"]] == [f"ssh:{hid}", f"ssh:{hid}:ct:105", f"ssh:{hid + 1}"]
    assert state["pending"][0]["name"] == "nieuw"

    r = (await authed.get("/api/cron")).json()
    jobs = {j["name"]: j for j in r["jobs"]}
    assert jobs["check.sh"]["last_status"] == "fout" and jobs["check.sh"]["monitored"]
    assert jobs["sync.sh"]["last_status"] == "gestart" and jobs["sync.sh"]["when"] == "elke dag om 04:00"
    # Het script dat de job aanroept is gelezen: het doel staat erin.
    assert jobs["sync.sh"]["targets"][0]["ref"] == "gdrive" and jobs["sync.sh"]["script_path"] == "/root/sync.sh"
    assert jobs["back-up naar pbs-pi"]["target"] == "pve:thuis"
    assert jobs["garbage collection main"]["last_status"] == "fout"
    assert r["summary"]["fout"] == 2
    notes = (await authed.get("/api/notifications")).json()
    titles = [n["title"] for n in (notes["items"] if isinstance(notes, dict) else notes)]
    assert any("Cronjob mislukt: check.sh" in t for t in titles)
    assert not any("apt-daily" in t for t in titles)

    # Detail met runs en de volgende keren.
    d = (await authed.get(f"/api/cron/jobs/{jobs['check.sh']['id']}")).json()
    assert d["runs"][0]["status"] == "fout" and "nas mislukt" in d["runs"][0]["output"] and len(d["next"]) == 5

    # Verbanden: back-up van de cluster naar de PBS, rsync naar een onbekende NAS, sync van offsite naar de PBS.
    g = (await authed.get("/api/cron/graph")).json()
    pairs = {(e["from"], e["to"], e["via"]) for e in g["edges"]}
    # De PBS-opslag "pbs-pi.lan" is de gescande machine pbs-pi.
    assert ("pve:thuis", f"ssh:{hid + 1}", "vzdump") in pairs
    assert (f"ssh:{hid}", "ext:host:192.168.0.60", "rsync") in pairs
    assert ("ext:pbs:10.0.0.9", f"ssh:{hid + 1}", "pbs-sync") in pairs
    assert any(e["via"] == "replicatie" and e["to"] == "pvenode:pve100" for e in g["edges"])
    assert any(b["name"] == "verify main" for b in g["badges"][f"ssh:{hid + 1}"])

    a = (await authed.get("/api/cron/agenda?hours=48")).json()
    assert any(row["dense"] for row in a["rows"])  # check.sh elke 5 minuten
    assert all(it["name"] != "apt-daily" for row in a["rows"] for it in row["items"])

    # Tweede scan: wrapper meldt nu exitcode 0, sync.sh heeft een ander schema, de cronlog mist de laatste keer.
    agen, db = await _db()
    await db.execute(update(CronJob).values(first_seen=datetime.now(timezone.utc) - timedelta(days=3)))
    await db.commit()
    now.update(rc=0, sync="0 3 * * *")
    await _scan(authed)
    agen, db = await _db()
    evs = [e.title for e in (await db.execute(select(Event).where(Event.kind == "cron"))).scalars()]
    assert any("schema van sync.sh gewijzigd" in e for e in evs)
    assert any("check.sh op pve50 loopt weer goed" in e for e in evs)
    st = {j.name: j for j in (await db.execute(select(CronJob).where(CronJob.removed_at.is_(None)))).scalars()}
    assert st["check.sh"].last_status == "ok"
    rows = (await db.execute(select(CronRun).where(CronRun.job_id == st["check.sh"].id))).scalars().all()
    assert len(rows) == 1  # dezelfde run, bijgewerkt
    node.server.close()
    pbs.server.close()


async def test_missed_run_is_reported(authed):
    now = {"t": int(time.time())}
    # De cronlog werkt (er staat een andere regel in), maar de geplande keer van sync.sh van vannacht ontbreekt.
    hh = datetime.fromtimestamp(now["t"] - 7200, BXL)
    sched = f"{hh.minute} {hh.hour} * * *"
    node = Fake(lambda: node_output(now["t"], True, 0, sched).replace("CMD (/root/sync.sh)", "CMD (/root/iets-anders.sh)"))
    await _host(authed, "pve50", await node.start(), node.key)
    await _scan(authed)
    agen, db = await _db()
    await db.execute(update(CronJob).values(first_seen=datetime.now(timezone.utc) - timedelta(days=3)))
    await db.commit()
    await _scan(authed)
    agen, db = await _db()
    job = (await db.execute(select(CronJob).where(CronJob.name == "sync.sh"))).scalar_one()
    assert job.last_status == "gemist"
    n = (await db.execute(select(Notification).where(Notification.title.like("%niet gelopen%")))).scalars().all()
    assert [x.title for x in n if "sync.sh" in x.title] == ["Cronjob niet gelopen: sync.sh op pve50"]
    node.server.close()


async def test_monitor_run_now_and_patch(authed):
    now = {"t": int(time.time())}
    node = Fake(lambda: node_output(now["t"]))
    node.files["root"] = "# mijn jobs\n*/5 * * * * /usr/local/bin/hp-cron 1a2b3c4d5e '/root/check.sh'\n0 4 * * * /root/sync.sh\n"
    await _host(authed, "pve50", await node.start(), node.key)
    await _scan(authed)
    jobs = {j["name"]: j for j in (await authed.get("/api/cron")).json()["jobs"]}
    jid = jobs["sync.sh"]["id"]

    r = await authed.post(f"/api/cron/jobs/{jid}/monitor", json={"on": True})
    assert r.status_code == 200, r.text
    assert r.json()["monitored"]
    assert "/usr/local/bin/hp-cron " in node.files["root"] and "'/root/sync.sh'" in node.files["root"]
    r = await authed.post(f"/api/cron/jobs/{jid}/monitor", json={"on": False})
    assert r.status_code == 200, r.text
    assert node.files["root"].endswith("0 4 * * * /root/sync.sh\n")
    assert (await authed.post(f"/api/cron/jobs/{jobs['back-up naar pbs-pi']['id']}/monitor",
                              json={"on": True})).status_code == 400

    r = await authed.patch(f"/api/cron/jobs/{jid}", json={"alias": "sync naar Google Drive", "muted": True})
    assert r.json()["name"] == "sync naar Google Drive" and r.json()["muted"]

    ws = WS(f"/api/cron/ws/run/{jid}", _cookie(authed), query="")
    await ws.open()
    assert (await ws.json())["t"] == "status"
    await ws.read_until(b"klaar")
    end = await ws.json()
    assert end["t"] == "exit" and end["code"] == 0
    await asyncio.wait_for(ws.task, 10)
    assert any(c.endswith("exec sh -c /root/sync.sh'") or "exec sh -c /root/sync.sh" in c for c in node.commands)
    agen, db = await _db()
    run = (await db.execute(select(CronRun).where(CronRun.job_id == jid, CronRun.trigger == "manueel"))).scalar_one()
    assert run.status == "ok" and "klaar" in run.output
    node.server.close()
