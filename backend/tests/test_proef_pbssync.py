"""Proef van de PBS-sync: wat "stap 1 en 2 zelf uitvoeren" zou doen, zonder iets te veranderen.

De scripts lopen hier echt, met sh en een nep-proxmox-backup-manager die elke aanroep bijhoudt: in de proef mag die
alleen gelezen worden, en in het echt moet ze precies krijgen wat de proef toonde.
"""

import asyncio
import re
import shlex
import subprocess
from contextlib import asynccontextmanager
from itertools import product

import asyncssh
import httpx
import pytest
from sqlalchemy import func, select

from app import ssh_exec
from app.models import AuditLog, Event, Notification, SshHost
from app.monitoring import coverage, pbssync
from app.monitoring.checks import HttpClients
from app.ssh_login import Login

from .test_homelab import FP, PX, Lab
from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db, _notes
from .test_verbindingen import _idle_in_transaction

SSH_PW = "ssh-wachtwoord-geheim-123"
TILE_PW = "pbs-tegel-geheim-456789"
SECRET = "5a1e7c00-dead-beef-0000-123456789abc"
READ = {("user", "list"), ("user", "list-tokens"), ("remote", "list"), ("sync-job", "list")}

FAKE = r"""#!/bin/sh
# Nep-proxmox-backup-manager: houdt elke aanroep bij (argumenten gescheiden door \037) en een kleine toestand.
D=$FAKE_PBS
for a in "$@"; do printf '%s\037' "$a"; done >> "$D/calls"
printf '\n' >> "$D/calls"
list() { printf '['; sep=; while IFS= read -r x; do printf '%s{"%s":"%s"}' "$sep" "$1" "$x"; sep=,; done < "$D/$2"; printf ']\n'; }
case "$1 $2" in
  "user list") list userid users ;;
  "user list-tokens") grep -qx "$3" "$D/users" || { echo "no such user '$3'" >&2; exit 1; }; list tokenid tokens ;;
  "user create") echo "$3" >> "$D/users" ;;
  "user delete-token") grep -vx "$3!$4" "$D/tokens" > "$D/t"; mv "$D/t" "$D/tokens" ;;
  "user generate-token")
    if grep -qx "$3!$4" "$D/tokens"; then echo "token already exists" >&2; exit 1; fi
    echo "$3!$4" >> "$D/tokens"
    printf '{"tokenid":"%s","value":"%s"}\n' "$3!$4" "$FAKE_SECRET" ;;
  "acl update") ;;
  "remote list") list name remotes ;;
  "remote create") if grep -qx "$3" "$D/remotes"; then echo "remote exists" >&2; exit 1; fi; echo "$3" >> "$D/remotes" ;;
  "remote update") ;;
  "sync-job list") list id syncs ;;
  "sync-job create") echo "$3" >> "$D/syncs" ;;
  *) echo "onbekend: $*" >&2; exit 2 ;;
esac
"""
# sudo -n zonder wachtwoord: gewoon uitvoeren.
SUDO = '#!/bin/sh\n[ "$1" = "-n" ] && shift\nexec "$@"\n'


@pytest.fixture
def fakebin(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    for name, text in (("proxmox-backup-manager", FAKE), ("sudo", SUDO)):
        (d / name).write_text(text)
        (d / name).chmod(0o755)
    return d


class FakePbs:
    """Nep-PBS: voert elk script echt uit met sh, met de nep-proxmox-backup-manager. Ook over SSH (asyncssh)."""

    def __init__(self, tmp, fakebin, name):
        self.dir = tmp / name
        self.dir.mkdir()
        for f in ("users", "tokens", "remotes", "syncs", "calls"):
            (self.dir / f).write_text("")
        self.env = {"PATH": f"{fakebin}:/usr/bin:/bin", "FAKE_PBS": str(self.dir), "FAKE_SECRET": SECRET}
        self.key = asyncssh.generate_private_key("ssh-ed25519")
        self.commands: list[str] = []
        self.stdin: list[str] = []

    def add(self, what, *names):
        with open(self.dir / what, "a") as f:
            f.writelines(n + "\n" for n in names)

    def calls(self) -> list[list[str]]:
        lines = (self.dir / "calls").read_text().splitlines()
        return [["proxmox-backup-manager", *line.split("\x1f")[:-1]] for line in lines]

    def changes(self) -> list[list[str]]:
        """De aanroepen die iets veranderen (alles behalve lezen)."""
        return [a for a in self.calls() if tuple(a[1:3]) not in READ]

    def reset_calls(self):
        (self.dir / "calls").write_text("")

    def sh(self, script, stdin=""):
        r = subprocess.run(["sh", "-c", script], input=stdin, env=self.env, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout + r.stderr

    async def handle(self, proc):
        cmd = proc.command or ""
        self.commands.append(cmd)
        data = await proc.stdin.read()
        self.stdin.append(data)
        p = await asyncio.create_subprocess_exec("/bin/sh", "-c", cmd, stdin=asyncio.subprocess.PIPE,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                 env=self.env)
        out, err = await p.communicate(data.encode())
        proc.stdout.write(out.decode())
        proc.stderr.write(err.decode())
        proc.exit(p.returncode)

    async def start(self):
        class S(asyncssh.SSHServer):
            def begin_auth(self, u):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, u, p):
                return p == SSH_PW

        self.server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[self.key],
                                                   process_factory=self.handle)
        return self.server.sockets[0].getsockname()[1]


def _p(**kw):
    return {"source_id": 1, "target_id": 2, "host": "192.168.0.70", "port": 8007, "src_store": "backup",
            "dst_store": "pi", "schedule": "06:00", "fingerprint": FP, "remote": "pbs-vm", "token": "pbs-pi",
            "job": "pbs-vm-naar-pbs-pi", **kw}


def _plus(out: str) -> list[list[str]]:
    return [shlex.split(x[2:]) for x in out.splitlines() if x.startswith("+ ")]


def _no_pw(argv: list[str]) -> list[str]:
    return [a if prev != "--password" else "<pw>" for prev, a in zip(["", *argv], argv)]


# --- De scripts zelf ------------------------------------------------------------------------------------------------

def _unguarded(script: str) -> tuple[int, list[str]]:
    """(aantal aanroepen, regels met een aanroep die niet alleen leest en niet via doe gaat)."""
    rx = re.compile(r"proxmox-backup-manager(?:\s+(\S+)\s+(\S+))?")
    n, bad = 0, []
    for line in script.splitlines():
        # Tekst in echo en het opzoeken van het programma voeren niets uit.
        line = re.sub(r'echo "[^"]*"', "", line).replace("command -v proxmox-backup-manager", "")
        for m in rx.finditer(line):
            n += 1
            if (m.group(1), m.group(2)) not in READ and not line[:m.start()].endswith("doe "):
                bad.append(line)
    return n, bad


def test_alles_wat_verandert_gaat_via_doe():
    """Vangnet: een commando dat iets verandert zonder doe, zou in de proef echt als root lopen."""
    for proef in (False, True):
        for script in (pbssync._source_script(_p(), "PBS-Pi", proef), pbssync._target_script(_p(), "PBS-VM", proef)):
            assert "doe() {" in script
            n, bad = _unguarded(script)
            assert n >= 5 and bad == [], bad
            # Het vangnet zelf: een nieuw commando zonder doe valt op, ook als het "list" niet is.
            for extra in ("proxmox-backup-manager remote remove x", "  proxmox-backup-manager user update u",
                          "x && proxmox-backup-manager acl update /datastore/s Admin --auth-id u"):
                assert _unguarded(script + extra + "\n")[1] == [extra]
    # Beide vormen komen uit dezelfde bron: alleen doe() en het geheim verschillen.
    for build in (lambda proef: pbssync._source_script(_p(), "PBS-Pi", proef),
                  lambda proef: pbssync._target_script(_p(), "PBS-VM", proef)):
        real, dry = build(False), build(True)
        assert real.replace(pbssync._DOE, "DOE").replace("IFS= read -r PW", "PW") == \
            dry.replace(pbssync._DOE_PROEF, "DOE").replace("PW='<geheim uit stap 1>'", "PW")
    assert "read -r" not in pbssync._target_script(_p(), "PBS-VM", proef=True)


def test_proef_en_echt_nemen_dezelfde_weg(tmp_path, fakebin):
    """Voor elke begintoestand: de proef verandert niets en toont precies wat het echte script daarna uitvoert,
    en het plan zonder SSH (met de voorwaarden erbij) bevat die commando's."""
    p = _p()
    se, si = pbssync._source(p, "PBS-Pi")
    te, ti = pbssync._target(p, "PBS-VM")
    static = {"src": pbssync._would(se, si), "dst": pbssync._would({**te, "PW": pbssync.PLACEHOLDER}, ti)}
    static = {k: {x.split("   # als: ")[0] for x in v} for k, v in static.items()}
    i = 0
    for user, token, remote, job in product((False, True), repeat=4):
        if token and not user:
            continue
        i += 1
        src, dst = FakePbs(tmp_path, fakebin, f"src{i}"), FakePbs(tmp_path, fakebin, f"dst{i}")
        if user:
            src.add("users", pbssync.USER)
        if token:
            src.add("tokens", f"{pbssync.USER}!pbs-pi")
        if remote:
            dst.add("remotes", "pbs-vm")
        if job:
            dst.add("syncs", "pbs-vm-naar-pbs-pi")

        code, out = src.sh(pbssync._source_script(p, "PBS-Pi", proef=True))
        assert code == 0 and src.changes() == [], (out, src.calls())
        src_would = _plus(out)
        code, dout = dst.sh(pbssync._target_script(p, "PBS-VM", proef=True))
        assert code == 0 and dst.changes() == [], (dout, dst.calls())
        dst_would = _plus(dout)
        assert ("token homepage-sync@pbs!pbs-pi bestaat al" in out) == token
        assert ("sync-job pbs-vm-naar-pbs-pi bestaat al" in dout) == job
        assert {shlex.join(a) for a in src_would} <= static["src"] and {shlex.join(a) for a in dst_would} <= static["dst"]

        code, out = src.sh(pbssync._source_script(p, "PBS-Pi"))
        assert code == 0, out
        assert src.changes() == src_would
        assert pbssync.SECRET.search(out).group(1) == SECRET
        code, out = dst.sh(pbssync._target_script(p, "PBS-VM"), stdin=SECRET + "\n")
        assert code == 0, out
        # Het geheim komt in het echt via stdin aan, de proef toonde de plaatshouder.
        assert [_no_pw(a) for a in dst.changes()] == [_no_pw(a) for a in dst_would]
        assert all(a[a.index("--password") + 1] == SECRET for a in dst.changes() if "--password" in a)
        assert all(a[a.index("--password") + 1] == pbssync.PLACEHOLDER for a in dst_would if "--password" in a)
        assert pbssync._said(out, te, ti, "sync-job") is job
    assert i == 12


def test_proef_op_een_machine_zonder_pbs(tmp_path, fakebin):
    pbs = FakePbs(tmp_path, fakebin, "geen")
    pbs.env["PATH"] = "/usr/bin:/bin"
    code, out = pbs.sh(pbssync._source_script(_p(), "PBS-Pi", proef=True))
    assert code == 1 and "check: fout: proxmox-backup-manager niet gevonden" in out and "+ " not in out
    code, out = pbs.sh(pbssync._source_script(_p(), "PBS-Pi"))
    assert code == 1 and "niet gevonden" in out


# --- De routes ------------------------------------------------------------------------------------------------------

async def _setup(authed, world=None):
    http = HttpClients(httpx.MockTransport(world or Lab()))
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets=PX, name="pve50")
    # Het geheim van de PBS-tegels mag nergens in een proef staan.
    pb = {"username": "a@pbs!b", "password": TILE_PW}
    vm = await _svc(authed, g, "proxmoxbackupserver", "https://192.168.0.70:8007", secrets=pb, name="PBS-VM")
    pi = await _svc(authed, g, "proxmoxbackupserver", "https://192.168.0.80:8007", secrets=pb, name="PBS-Pi")
    agen, db = await _db()
    await coverage.run_coverage(db, http)
    await db.commit()
    plan = (await authed.get("/api/backups")).json()["sync"]["plan"]
    return vm, pi, db, plan, agen


async def _counts(db):
    return [(await db.execute(select(func.count()).select_from(m))).scalar() for m in (AuditLog, Event, Notification)]


async def test_proef_zonder_ssh_hosts(authed, monkeypatch):
    vm, pi, db, plan, agen = await _setup(authed)

    async def no_ssh(*a, **kw):
        raise AssertionError("de proef zonder controle mag geen SSH openen")
    monkeypatch.setattr(pbssync, "_run", no_ssh)
    before = await _counts(db)
    r = await authed.post("/api/backups/sync/proef", json=plan)
    assert r.status_code == 200, r.text
    got = r.json()
    pl, log = got["plan"], got["log"]
    assert pl["proef"] and not pl["controle"] and log == []
    assert pl["title"] == "PBS-sync instellen: PBS-VM → PBS-Pi, elke dag om 06:00"
    checks = {c["what"]: c for c in pl["checks"]}
    assert checks["SSH-host voor PBS-VM"]["ok"] is False and checks["SSH-host voor PBS-Pi"]["ok"] is False
    assert checks["Plaats op PBS-Pi"]["ok"] is True
    assert checks["Elke dag om 06:00"]["ok"] is True and "na de back-up van 02:30" in checks["Elke dag om 06:00"]["detail"]
    assert checks["Vingerafdruk van PBS-VM"]["ok"] is True
    # De tegel ziet geen remotes of sync-jobs: onzeker, niet "bestaat niet".
    assert checks["Remote pbs-vm op PBS-Pi"]["ok"] is None
    assert any("De echte knop zou nu weigeren" in w and "Geen SSH-host voor PBS-VM en PBS-Pi" in w
               for w in pl["warnings"])
    # Eerst de bron, dan het doel; met de echte waarden en de voorwaarde erbij.
    s1, s2 = pl["steps"]
    assert s1["machine"] == "PBS-VM: geen SSH-host" and s2["machine"] == "PBS-Pi: geen SSH-host"
    assert "proxmox-backup-manager user generate-token homepage-sync@pbs pbs-pi --output-format json" in s1["call"]
    assert ("proxmox-backup-manager user delete-token homepage-sync@pbs pbs-pi   # als: token "
            "homepage-sync@pbs!pbs-pi bestaat al") in s1["call"]
    assert "sync-job create pbs-vm-naar-pbs-pi --store pi --remote pbs-vm --remote-store backup --schedule 06:00" \
        in s2["call"]
    assert "--password '<geheim uit stap 1>'" in s2["call"] and s2["when"] == "als stap 1 lukt"
    assert "remote remove pbs-vm" in s2["note"] and "user delete-token homepage-sync@pbs pbs-pi" in s1["note"]
    assert "op PBS-Pi verandert niets" in s1["on_fail"]
    # Een proef schrijft niets weg: geen audit (geen SSH), geen melding, niets op de tijdlijn.
    assert await _counts(db) == before

    # Ongeldig plan: dezelfde 422 als /sync/plan.
    bad = await authed.post("/api/backups/sync/proef", json={**plan, "host": "x; rm -rf /"})
    assert bad.status_code == 422


async def test_proef_met_controle_en_daarna_echt(authed, tmp_path, fakebin):
    vm, pi, db, plan, agen = await _setup(authed)
    src, dst = FakePbs(tmp_path, fakebin, "vm"), FakePbs(tmp_path, fakebin, "pi")
    ids = {}
    for fake, name, sid in ((src, "pbs-vm", None), (dst, "pi-ssh", pi)):
        port = await fake.start()
        r = await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                      "password": SSH_PW, "service_id": sid})
        ids[name] = r.json()["id"]
    for name, fake in (("pbs-vm", src), ("pi-ssh", dst)):
        h = await db.get(SshHost, ids[name])
        h.host_key = fake.key.export_public_key().decode()
    await db.commit()
    # Op de bron bestaan de gebruiker en het token al, op het doel de remote.
    src.add("users", pbssync.USER)
    src.add("tokens", f"{pbssync.USER}!pbs-pi")
    dst.add("remotes", "pbs-vm")
    before = await _counts(db)

    r = await authed.post("/api/backups/sync/proef", json=plan)
    assert r.status_code == 200, r.text
    text = r.text
    for secret in (SSH_PW, TILE_PW, SECRET):
        assert secret not in text
    pl, log = r.json()["plan"], r.json()["log"]
    assert pl["controle"] is True
    # Niets veranderd: alleen gelezen, op beide machines, en het doel kreeg geen geheim.
    assert src.changes() == [] and dst.changes() == [] and src.calls() and dst.calls()
    assert dst.stdin == [""]
    s1, s2 = pl["steps"]
    assert s1["machine"].startswith("PBS-VM: pbs-vm (root@127.0.0.1:") and s1["who"] == "root"
    assert s2["machine"].startswith("PBS-Pi: pi-ssh (root@127.0.0.1:")
    assert s1["script"].startswith("sh -c ") and "doe() { \"$@\"; }" in s1["script"]
    # De echte weg, niet alle mogelijkheden: geen user create (bestaat al), wel het token vervangen.
    assert s1["call"].splitlines() == [
        "proxmox-backup-manager user delete-token homepage-sync@pbs pbs-pi",
        "proxmox-backup-manager user generate-token homepage-sync@pbs pbs-pi --output-format json",
        "proxmox-backup-manager acl update /datastore/backup DatastoreReader --auth-id homepage-sync@pbs",
        "proxmox-backup-manager acl update /datastore/backup DatastoreReader --auth-id 'homepage-sync@pbs!pbs-pi'"]
    assert [x.split()[1:3] for x in s2["call"].splitlines()] == [["remote", "update"], ["sync-job", "create"]]
    checks = {c["what"]: c["ok"] for c in pl["checks"]}
    assert checks["Op PBS-VM: gebruiker homepage-sync@pbs bestaat al"] is True
    assert checks["SSH-host voor PBS-VM"] is True and checks["Hostsleutel van pi-ssh"] is True
    assert "Remote pbs-vm op PBS-Pi" not in checks  # de controle weet het zeker, geen voorspelling meer
    assert any(w.startswith("Op PBS-Pi: remote pbs-vm bestaat al: wordt overschreven") for w in pl["warnings"])
    assert any("token homepage-sync@pbs!pbs-pi bestaat al: wordt vervangen" in w for w in pl["warnings"])
    assert log[0].startswith("$ proef op PBS-VM (127.0.0.1)") and any("+ proxmox-backup-manager" in x for x in log)
    assert pl["after"][0] == "melding en tijdlijn: PBS-sync ingesteld: PBS-VM → PBS-Pi" and len(pl["after"]) == 3
    # Alleen een auditregel (de proef meldde zich aan als root), geen melding en niets op de tijdlijn.
    audit, events, notes = await _counts(db)
    assert (audit, events, notes) == (before[0] + 1, before[1], before[2])
    a = (await db.execute(select(AuditLog).order_by(AuditLog.id.desc()))).scalars().first()
    assert a.action == "pbs_sync_proef" and a.detail["job"] == "pbs-vm-naar-pbs-pi"

    # Zonder controle: geen SSH, geen audit.
    n = len(src.commands)
    r = await authed.post("/api/backups/sync/proef?controle=false", json=plan)
    assert r.status_code == 200 and not r.json()["plan"]["controle"] and len(src.commands) == n
    assert (await _counts(db))[0] == audit

    # Nu echt: precies wat de proef toonde, in dezelfde volgorde.
    shown = {"src": [shlex.split(x) for x in s1["call"].splitlines()],
             "dst": [shlex.split(x) for x in s2["call"].splitlines()]}
    src.reset_calls()
    dst.reset_calls()
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 200, r.text
    assert SECRET not in r.text and SSH_PW not in r.text
    assert src.changes() == shown["src"]
    assert [_no_pw(a) for a in dst.changes()] == [_no_pw(a) for a in shown["dst"]]
    assert dst.stdin[-1] == SECRET + "\n" and SECRET not in dst.commands[-1]
    assert not r.json()["job_existed"]
    assert ("PBS-sync ingesteld: PBS-VM → PBS-Pi", "ok", "Sync-job pbs-vm-naar-pbs-pi op PBS-Pi, elke dag om 06:00.") \
        in await _notes(db, "backup")

    # Opnieuw: de sync-job bestaat nu. De proef zegt dat hij blijft zoals hij is, en de melding beweert geen uur.
    r = (await authed.post("/api/backups/sync/proef", json=plan)).json()["plan"]
    assert [x.split()[1:3] for x in r["steps"][1]["call"].splitlines()] == [["remote", "update"]]
    assert any("sync-job pbs-vm-naar-pbs-pi bestaat al: blijft zoals hij is" in w for w in r["warnings"])
    # De controle weet het, ook al zien de bewaarde gegevens van de tegel de sync-job nog niet.
    assert r["after"][0].startswith("melding en tijdlijn: PBS-sync bijgewerkt: PBS-VM → PBS-Pi")
    assert not any("elke dag om 06:00" in x for x in r["after"])
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 200 and r.json()["job_existed"]
    title, level, body = (await _notes(db, "backup"))[-1]
    assert title == "PBS-sync bijgewerkt: PBS-VM → PBS-Pi" and "niet aangepast" in body and "06:00" not in body


async def test_proef_bron_faalt_doel_toch_bekeken(authed, tmp_path, fakebin):
    vm, pi, db, plan, agen = await _setup(authed)
    src, dst = FakePbs(tmp_path, fakebin, "vm"), FakePbs(tmp_path, fakebin, "pi")
    src.env["PATH"] = "/usr/bin:/bin"  # geen proxmox-backup-manager: geen PBS
    for fake, name, sid in ((src, "pbs-vm", vm), (dst, "pbs-pi", pi)):
        port = await fake.start()
        hid = (await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                         "password": SSH_PW, "service_id": sid})).json()["id"]
        h = await db.get(SshHost, hid)
        h.host_key = fake.key.export_public_key().decode()
    await db.commit()
    pl = (await authed.post("/api/backups/sync/proef", json=plan)).json()["plan"]
    checks = {c["what"]: c for c in pl["checks"]}
    assert checks["Op PBS-VM: proxmox-backup-manager niet gevonden, is dit wel een PBS?"]["ok"] is False
    assert dst.commands and dst.changes() == []  # het doel is toch nagekeken
    assert checks["Op PBS-Pi: remote pbs-vm bestaat nog niet"]["ok"] is True
    assert pl["skipped"][0]["what"] == "Stap 2 op PBS-Pi" and "stopt de run al op PBS-VM" in pl["skipped"][0]["why"]


async def test_sudo_login(authed, tmp_path, fakebin):
    vm, pi, db, plan, agen = await _setup(authed)
    src, dst = FakePbs(tmp_path, fakebin, "vm"), FakePbs(tmp_path, fakebin, "pi")
    for fake, name, sid in ((src, "pbs-vm", vm), (dst, "pbs-pi", pi)):
        port = await fake.start()
        hid = (await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                         "username": "beheer", "password": SSH_PW,
                                                         "service_id": sid})).json()["id"]
        h = await db.get(SshHost, hid)
        h.host_key = fake.key.export_public_key().decode()
    await db.commit()
    pl = (await authed.post("/api/backups/sync/proef", json=plan)).json()["plan"]
    s1 = pl["steps"][0]
    assert s1["who"] == "beheer met sudo -n" and s1["script"].startswith("sudo -n sh -c ")
    assert src.commands[0].startswith("sudo -n sh -c ") and src.changes() == []
    assert {c["what"]: c["ok"] for c in pl["checks"]}["Aanmelden op pbs-vm"] is None
    assert s1["call"].splitlines()[0] == ("proxmox-backup-manager user create homepage-sync@pbs --comment "
                                          "'sync naar pbs-pi, door de homepage'")


async def test_echte_run_weigert_voor_de_bron(authed, monkeypatch):
    """Wat de proef met ✕ toont, weigert de echte run, nog voor er iets op de bron gebeurt."""
    world = Lab()
    world.pbs["192.168.0.80"]["avail"] = 100e9  # 400 GB past niet in 100 GB
    vm, pi, db, plan, agen = await _setup(authed, world)
    calls = []

    async def fake_run(db, h, script, stdin=None):
        calls.append(h.name)
        return 0, '{"value":"x"}'
    monkeypatch.setattr(pbssync, "_run", fake_run)
    db.add(SshHost(name="pbs-vm", host="192.168.0.70", host_key="ssh-ed25519 AAAA"))
    db.add(SshHost(name="pbs-pi", host="10.0.0.9", service_id=pi))
    await db.commit()

    pl = (await authed.post("/api/backups/sync/proef", json=plan)).json()["plan"]
    bad = {c["what"] for c in pl["checks"] if c["ok"] is False}
    assert bad == {"Plaats op PBS-Pi", "Hostsleutel van pbs-pi"}
    assert calls == []  # hostsleutel ontbreekt: geen controle via SSH
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 422 and "Past waarschijnlijk niet" in r.json()["detail"]
    assert "Hostsleutel van pbs-pi nog niet bevestigd" in r.json()["detail"]
    assert calls == []
    assert not (await db.execute(select(AuditLog).where(AuditLog.action == "pbs_sync_create"))).scalars().all()

    # Blokkeren en ✕ vallen samen, ook voor de vingerafdruk.
    r = (await authed.post("/api/backups/sync/proef", json={**plan, "fingerprint": ""})).json()["plan"]
    assert "Vingerafdruk van PBS-VM" in {c["what"] for c in r["checks"] if c["ok"] is False}
    r = await authed.post("/api/backups/sync/create", json={**plan, "fingerprint": ""})
    assert r.status_code == 422 and "Vingerafdruk van PBS-VM onbekend" in r.json()["detail"]
    assert calls == []


def test_voorcontrole_en_weigeren_vallen_samen():
    src = {"service_id": 1, "name": "PBS-VM", "host": "192.168.0.70", "fingerprint": FP}
    dst = {"service_id": 2, "name": "PBS-Pi", "host": "192.168.0.80", "remotes": [], "syncs": []}
    ok_host = SshHost(id=1, name="a", host="h", port=22, username="root", host_key="k", service_id=1)
    no_key = SshHost(id=2, name="b", host="h", port=22, username="root", host_key=None, service_id=2)
    for fp, level, hs, hd in product((FP, ""), ("ok", "warn", "err"), (ok_host, None), (ok_host, no_key, None)):
        notes = {"ok": ["Past: x"], "warn": ["Krap: x"], "err": ["Past waarschijnlijk niet: x"]}[level]
        c = {"plan": _p(fingerprint=fp), "level": level, "notes": notes, "src": src, "dst": dst}
        login = Login("root", None, None)
        checks = pbssync.preflight(c, {}, hs, hd, login, login)
        assert bool(pbssync.blocked(c, hs, hd)) == any(x["ok"] is False for x in checks), (fp, level, hs, hd)


async def test_geen_transactie_open_tijdens_ssh(authed, monkeypatch):
    """Proef en echte run: de sessie zonder transactie terwijl SSH loopt."""
    vm, pi, db, plan, agen = await _setup(authed)
    seen = []

    class Conn:
        async def run(self, cmd, **kw):
            seen.append((db.in_transaction(), await _idle_in_transaction()))
            # Het echte script van de bron geeft een geheim; de proef (met doe die afdrukt) niet.
            out = '{"value":"' + SECRET + '"}\n' if "generate-token" in cmd and "for a in" not in cmd else "klaar\n"

            class R:
                exit_status, stdout, stderr = 0, out, ""
            return R()

    @asynccontextmanager
    async def connect(h, login):
        yield Conn()
    monkeypatch.setattr(ssh_exec, "connect", connect)
    hs = SshHost(name="pbs-vm", host="192.168.0.70", host_key="k")
    hd = SshHost(name="pbs-pi", host="192.168.0.80", host_key="k")
    db.add_all([hs, hd])
    await db.commit()
    from app.routers.backups import PlanIn, _check
    c = await _check(db, PlanIn(**plan))
    ran = await pbssync.proef_run(db, c, hs, hd)
    assert [r["code"] for r in ran] == [0, 0]
    await db.execute(select(SshHost))  # transactie open: _run moet ze sluiten
    r = await pbssync.create(db, c, hs, hd)
    assert r["log"][0].startswith("$ op PBS-VM") and not r["job_existed"]
    assert seen == [(False, 0)] * 4


async def test_doel_faalt_geheim_gemaskeerd(authed, monkeypatch):
    vm, pi, db, plan, agen = await _setup(authed)
    db.add(SshHost(name="pbs-vm", host="192.168.0.70", host_key="k"))
    db.add(SshHost(name="pbs-pi", host="10.0.0.9", service_id=pi, host_key="k"))
    await db.commit()

    async def fake_run(db, h, script, stdin=None):
        if h.name == "pbs-vm":
            return 0, '{"tokenid":"homepage-sync@pbs!pbs-pi","value":"' + SECRET + '"}\n'
        return 1, f"check: remote pbs-vm bestaat nog niet\nError: bad request: password '{SECRET}' rejected\n"
    monkeypatch.setattr(pbssync, "_run", fake_run)
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 502 and SECRET not in r.text and "Op PBS-Pi mislukt (exit 1)" in r.text
    assert await _notes(db, "backup") == []


async def test_proef_zegt_wat_daarna_volgt_als_de_sync_job_al_bestaat(authed, monkeypatch):
    """Bestaat de sync-job al volgens de laatste gegevens, dan laat de echte run hem staan (ook zijn uur) en zegt de
    melding "bijgewerkt": de proef belooft dan geen nieuw uur. Zonder SSH-controle."""
    async def no_ssh(*a, **kw):
        raise AssertionError("de proef zonder controle mag geen SSH openen")
    monkeypatch.setattr(pbssync, "_run", no_ssh)
    world = Lab()
    vm, pi, db, plan, agen = await _setup(authed, world)
    http = HttpClients(httpx.MockTransport(world))

    async def after(syncs):
        world.syncs = syncs
        await coverage.run_coverage(db, http)
        await db.commit()
        pl = (await authed.post("/api/backups/sync/proef", json=plan)).json()["plan"]
        assert not pl["controle"]
        return pl["after"]

    job = {"store": "pi", "remote": "pbs-vm", "remote-store": "backup", "schedule": "21:00", "last-run-state": "OK"}
    a = await after([{**job, "id": "pbs-vm-naar-pbs-pi"}])
    assert a[0] == ("melding en tijdlijn: PBS-sync bijgewerkt: PBS-VM → PBS-Pi (sync-job pbs-vm-naar-pbs-pi bestond "
                    "al en blijft zoals hij was)")
    assert "06:00 wordt niet ingesteld" in a[2] and not any("elke dag om 06:00" in x for x in a)

    # Een andere sync-job: deze bestaat nog niet en wordt ingesteld, met het uur.
    a = await after([{**job, "id": "iets-anders"}])
    assert a[0] == "melding en tijdlijn: PBS-sync ingesteld: PBS-VM → PBS-Pi"
    assert "PBS-Pi haalt zelf elke dag om 06:00 een kopie op" in a[2] and len(a) == 3

    # De tegel ziet geen remotes of sync-jobs: onzeker, en dat staat erbij.
    a = await after([])
    assert a[0] == "melding en tijdlijn: PBS-sync ingesteld: PBS-VM → PBS-Pi"
    assert "bestaat sync-job pbs-vm-naar-pbs-pi toch al" in a[-1] and "'PBS-sync bijgewerkt'" in a[-1]
