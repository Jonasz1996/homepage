"""Vangnetten bij updates installeren: het dashboard zelf nooit 's nachts of samen met andere machines, en een
mislukte apt-get update (er is niets geïnstalleerd) draait niets terug."""

import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models import AppState, Notification, SshHost, UpdateRun
from app.monitoring import upgrade
from app.monitoring.checks import HttpClients
from app.monitoring.noodplan import STATE_KEY as NOODPLAN_KEY

from .test_upgrade_herstel import Node, _db, _host, _maker_from, _t, _updates_state, _wait

NOTHING = "apt-get update mislukte, er is niets geïnstalleerd"
DOWNLOAD = "downloaden van de pakketten mislukte (mirror of DNS weg?), er is niets geïnstalleerd"
# De echte upgrade.me (conftest vervangt die in elke test door een lege Me()).
REAL_ME = upgrade.me
NO_HTTP = HttpClients(httpx.MockTransport(lambda r: httpx.Response(404)))


class Apt(Node):
    """Nep-node waar apt kan mislukken zoals het echte script het meldt.
    mode: ok | update (apt-get update mislukt) | download (alleen downloaden mislukt) | install (installeren mislukt,
    exit 100) | rc99 (exit 99 zonder regel)
    | marker100 (de regel, maar exit 100)."""

    def __init__(self):
        super().__init__()
        self.mode = "ok"

    async def handle(self, proc):
        cmd = proc.command or ""
        if "apt-get" in cmd and self.mode != "ok":
            self.commands.append(cmd)
            if self.mode in ("update", "marker100", "rc99", "download"):
                proc.stdout.write("Err:1 http://deb.debian.org/debian bookworm InRelease\n")
                proc.stdout.write("E: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease\n")
            else:
                proc.stdout.write("Setting up openssl (3.0.15-1) ...\ndpkg: error processing package openssl\n")
            if self.mode in ("update", "marker100"):
                proc.stdout.write("@@NOUPDATE apt-get\n")
            if self.mode == "download":
                proc.stdout.write("@@NOUPDATE apt-get download\n")
            proc.exit({"update": 99, "rc99": 99, "marker100": 100, "install": 100, "download": 99}[self.mode])
            return
        await super().handle(proc)


# --- het script zelf ---------------------------------------------------------------------------------------------

def _script(tmp_path, tool: str, update_rc: int, install_rc: int, packages=None, download_rc: int = 0
            ) -> tuple[int, str, list[str]]:
    """Het echte installatiescript, met een nep-apt-get of nep-apk als enige programma op het PATH."""
    bin_dir, log = tmp_path / "bin", tmp_path / "calls"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / tool
    fake.write_text(f'#!/bin/sh\necho "$*" >> {log}\ncase " $* " in *" update "*) exit {update_rc};; '
                    f'*" --download-only "*) exit {download_rc};; esac\nexit {install_rc}\n')
    fake.chmod(0o755)
    r = subprocess.run(["/bin/sh", "-c", upgrade.script(packages)], env={"PATH": str(bin_dir)}, capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, timeout=30)
    calls = log.read_text().splitlines() if log.exists() else []
    log.unlink(missing_ok=True)
    return r.returncode, r.stdout, calls


def test_script_zegt_apart_dat_er_nog_niets_geinstalleerd_is(tmp_path):
    # Pakketlijst niet te verversen: een eigen regel en exitcode 99, en er wordt niets geïnstalleerd.
    rc, out, calls = _script(tmp_path, "apt-get", 100, 0, ["openssl"])
    assert rc == upgrade.NOUPDATE_RC and "@@NOUPDATE apt-get" in out.splitlines() and calls == ["update -q"]
    # Downloaden mislukt (mirror of DNS weg, een bron die apt-get update alleen als waarschuwing meldde): ook dan is er
    # nog niets geïnstalleerd, en het echte installeren begint niet.
    rc, out, calls = _script(tmp_path, "apt-get", 0, 0, ["openssl"], download_rc=100)
    assert rc == upgrade.NOUPDATE_RC and "@@NOUPDATE apt-get download" in out.splitlines()
    assert len(calls) == 2 and "--download-only install --only-upgrade openssl" in calls[1]
    # Een fout tijdens het installeren: 100 zoals apt-get zelf, zonder die regel. Hetzelfde commando, eerst alleen
    # downloaden.
    rc, out, calls = _script(tmp_path, "apt-get", 0, 100, ["openssl"])
    assert rc == 100 and "@@NOUPDATE" not in out and len(calls) == 3
    assert calls[1].endswith("--download-only install --only-upgrade openssl")
    assert calls[2].endswith(" install --only-upgrade openssl") and "--download-only" not in calls[2]
    rc, out, calls = _script(tmp_path, "apt-get", 0, 0)
    assert rc == 0 and "@@NOUPDATE" not in out and calls[1].endswith("--download-only upgrade --with-new-pkgs")
    assert calls[2].endswith(" upgrade --with-new-pkgs") and "--download-only" not in calls[2]
    # apk: hetzelfde voor apk update; apk upgrade geeft zijn eigen exitcode door.
    os.remove(tmp_path / "bin" / "apt-get")
    rc, out, calls = _script(tmp_path, "apk", 1, 0)
    assert rc == upgrade.NOUPDATE_RC and "@@NOUPDATE apk" in out.splitlines() and calls == ["update -q"]
    rc, out, calls = _script(tmp_path, "apk", 0, 3)
    assert rc == 3 and "@@NOUPDATE" not in out and calls == ["update -q", "upgrade"]


@pytest.mark.skipif(not shutil.which("apt-get"), reason="geen apt-get op deze machine")
def test_downloaden_mislukt_met_de_echte_apt_get(tmp_path):
    """Met de echte apt-get, in eigen mappen: de pakketlijst lukt, maar het pakket zelf is niet te halen, zoals een
    mirror die 's nachts wegvalt (of DNS weg, met de pakketlijst van de vorige keer). Zonder eerst alleen te downloaden
    mislukte apt-get upgrade met 100 en draaide de nachtelijke run terug, terwijl er niets geïnstalleerd was."""
    real = shutil.which("apt-get")
    d = tmp_path / "apt"
    for sub in ("state/lists/partial", "cache/archives/partial", "parts", "prefs", "repo"):
        (d / sub).mkdir(parents=True)
    fields = "Architecture: all\nMaintainer: x <x@example.org>\nDescription: test\n"
    # Versie 1 staat erop, versie 2 staat in de lijst van de bron, maar het .deb-bestand ontbreekt.
    (d / "status").write_text("Package: hp-test\nStatus: install ok installed\nVersion: 1\n" + fields + "\n")
    (d / "repo" / "Packages").write_text("Package: hp-test\nVersion: 2\nFilename: ./hp-test_2_all.deb\nSize: 1000\n"
                                         f"SHA256: {'0' * 64}\n" + fields + "\n")
    (d / "sources.list").write_text(f"deb [trusted=yes] file:{d / 'repo'} ./\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    wrap = bin_dir / "apt-get"
    # Niets van deze machine wordt gelezen of veranderd; dpkg komt er niet aan te pas (het downloaden mislukt eerst).
    wrap.write_text(f"""#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin exec {real} -o Dir::State={d}/state -o Dir::Cache={d}/cache \\
  -o Dir::Etc::SourceList={d}/sources.list -o Dir::Etc::SourceParts={d}/parts -o Dir::Etc::PreferencesParts={d}/prefs \\
  -o Dir::State::status={d}/status -o APT::Sandbox::User=root -o Debug::NoLocking=true "$@"
""")
    wrap.chmod(0o755)
    r = subprocess.run(["/bin/sh", "-c", upgrade.script(None)], env={"PATH": str(bin_dir)},
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    out = r.stdout + r.stderr
    assert "hp-test" in out and "Failed to fetch" in out, out
    assert r.returncode == upgrade.NOUPDATE_RC and "@@NOUPDATE apt-get download" in r.stdout.splitlines(), out
    assert upgrade.nothing_installed(r.returncode, "apt-get download") == DOWNLOAD


def test_alleen_exitcode_en_regel_samen_betekenen_niets_geinstalleerd():
    assert upgrade.nothing_installed(99, "apt-get") == NOTHING
    assert upgrade.nothing_installed(99, "apk") == "apk update mislukte, er is niets geïnstalleerd"
    # 100 kan apt-get zelf geven, ook halverwege het installeren; 99 zonder de regel (apk met 99 fouten) ook niet.
    assert upgrade.nothing_installed(100, "apt-get") is None
    assert upgrade.nothing_installed(99, "apt-get download") == DOWNLOAD
    assert upgrade.nothing_installed(100, "apt-get download") is None
    assert upgrade.nothing_installed(99, "apt-get iets") is None and upgrade.nothing_installed(99, "dnf") is None
    assert upgrade.nothing_installed(99, None) is None and upgrade.nothing_installed(99, "rm -rf") is None


# --- de run ------------------------------------------------------------------------------------------------------

async def _ct_setup(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    node = Apt()
    port = await node.start()
    hid = await _host(authed, "pve50", port, node.key, source="pve:9:node/pve50")
    agen, db = await _db()
    ct = f"ssh:{hid}:ct:105"
    await _updates_state(db, [_t(ct, "plex", "ct")])
    return node, hid, ct, agen, db


async def test_apt_get_update_mislukt_handmatig_niet_terugdraaien(authed, monkeypatch):
    node, hid, ct, agen, db = await _ct_setup(authed, monkeypatch)
    node.mode = "update"
    r = (await authed.post("/api/updates/install", json={"targets": [ct]})).json()
    run = await _wait(authed, r["runs"][0]["id"])
    assert run["status"] == "fout" and run["error"] == NOTHING and run["exit_code"] == 99
    assert run["snapshot"]["name"].startswith("hp-upd-") and run["snapshot"]["unused"] is True
    # Terugdraaien kan niet: er veranderde niets, terug zou alleen weggooien wat de machine sindsdien schreef.
    assert run["can_rollback"] is False
    assert "niet terugdraaien" in run["output"] and "@@NOUPDATE" not in run["output"]
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback")).status_code == 409
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback/proef")).status_code == 409
    assert not any("pct rollback" in c for c in node.commands)
    [n] = (await db.execute(select(Notification).where(Notification.source == "updates"))).scalars().all()
    assert n.title == "Updates op plex mislukt" and NOTHING in n.body and "Terugdraaien" not in n.body

    # Een fout tijdens het installeren blijft terug te draaien, en die snapshot blijft staan.
    node.mode = "install"
    r = (await authed.post("/api/updates/install", json={"targets": [ct]})).json()
    bad = await _wait(authed, r["runs"][0]["id"])
    assert bad["status"] == "fout" and "exitcode 100" in bad["error"] and bad["can_rollback"] is True
    assert "unused" not in bad["snapshot"]

    # Na keep_days ruimt het gewone opruimen de snapshot op die niet nodig was, net als die van een geslaagde run.
    for rid in (run["id"], bad["id"]):
        u = await db.get(UpdateRun, rid)
        await db.refresh(u)
        u.finished_at = datetime.now(timezone.utc) - timedelta(days=8)
    await db.commit()
    todo = await upgrade.cleanup_todo(db, 7)
    assert [t[0] for t in todo] == [run["id"]]
    p = await upgrade.describe_cleanup(db, NO_HTTP)
    assert [s["call"] for s in p["steps"]] == [f"pct delsnapshot 105 {run['snapshot']['name']}"]
    assert any("run 'fout'" in x["why"] for x in p["skipped"] if bad["snapshot"]["name"] in x["what"])
    assert await upgrade.cleanup_snapshots(_maker_from(agen), NO_HTTP) == 1
    assert f"pct delsnapshot 105 {run['snapshot']['name']}" in node.commands[-1]
    await agen.aclose()


async def test_apt_get_update_mislukt_snachts_niet_terugdraaien(authed, monkeypatch):
    node, hid, ct, agen, db = await _ct_setup(authed, monkeypatch)
    await authed.put("/api/updates/settings", json={"auto": True, "hour": 3, "keep_days": 7})
    maker = _maker_from(agen)

    async def night(day: int) -> dict:
        [rid] = await upgrade.auto_updates(maker, NO_HTTP, datetime(2026, 10, day, 3, 1).astimezone())
        return (await authed.get(f"/api/updates/runs/{rid}")).json()

    node.mode = "update"
    run = await night(5)
    assert run["status"] == "fout" and run["error"] == NOTHING and run["snapshot"]["unused"] is True
    assert not any("pct rollback" in c for c in node.commands)
    titles = [(n.title, n.body) for n in (await db.execute(select(Notification).where(Notification.source == "updates")))
              .scalars()]
    assert titles == [("Nachtelijke updates op plex mislukt",
                       f"{NOTHING}\nNiet teruggedraaid: er is niets veranderd. De volgende nacht opnieuw.")]

    # Alleen het downloaden mislukt: ook niets veranderd, niet terugdraaien.
    node.mode = "download"
    run = await night(6)
    assert run["status"] == "fout" and run["error"] == DOWNLOAD and run["snapshot"]["unused"] is True
    assert not any("pct rollback" in c for c in node.commands)

    # Exit 99 zonder de regel, of de regel met exit 100: gewoon mislukt, dus terug naar de snapshot.
    for day, mode in ((7, "rc99"), (8, "marker100"), (9, "install")):
        node.mode = mode
        run = await night(day)
        assert run["status"] == "teruggedraaid", (mode, run)
        assert "unused" not in run["snapshot"]
        assert f"pct rollback 105 {run['snapshot']['name']}" in node.commands[-1], mode

    # De proef van vannacht zegt het ook.
    p = await upgrade.describe_auto(db, NO_HTTP)
    inst = next(s for s in p["steps"] if s["call"].startswith("alleen de beveiligingsupdates"))
    assert "lukt apt-get update (of apk update) of het downloaden niet" in inst["call"] and "niet teruggedraaid" in inst["on_fail"]
    back = next(s for s in p["steps"] if s["call"].startswith("pct rollback"))
    assert "niet als apt-get update of het downloaden mislukt" in back["when"]
    await agen.aclose()


# --- het dashboard zelf ------------------------------------------------------------------------------------------

def test_eigen_adressen_en_mac_adressen(tmp_path, monkeypatch):
    fib = tmp_path / "fib_trie"
    fib.write_text("""Main:
  +-- 0.0.0.0/0 3 0 5
     +-- 127.0.0.0/8 2 0 2
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 192.168.10.0/24 2 0 2
           |-- 192.168.10.0
              /24 link UNICAST
           |-- 192.168.10.156
              /32 host LOCAL
        |-- 192.168.10.255
           /32 link BROADCAST
""")
    inet6 = tmp_path / "if_inet6"
    inet6.write_text("00000000000000000000000000000001 01 80 10 80       lo\n"
                     "fe80000000000000be2411fffe0000aa 02 40 20 80     eth0\n"
                     "2a0201000000000000000000000000aa 02 40 00 00     eth0\n")
    net = tmp_path / "net"
    for name, mac in (("lo", "00:00:00:00:00:00"), ("eth0", "BC:24:11:00:00:AA"), ("weird", "iets")):
        (net / name).mkdir(parents=True)
        (net / name / "address").write_text(mac + "\n")
    assert upgrade.own_ips(fib, inet6) == {"192.168.10.156", "2a02:100::aa"}
    assert upgrade.own_macs(net) == {"bc:24:11:00:00:aa"}
    assert upgrade.own_ips(tmp_path / "weg", tmp_path / "weg") == set()

    # me(): de eigen adressen plus het IP dat install.sh invulde, zonder loopback.
    monkeypatch.setattr(upgrade, "own_ips", lambda: {"192.168.10.156"})
    monkeypatch.setattr(upgrade, "own_macs", lambda: {"bc:24:11:00:00:aa"})
    monkeypatch.setattr(upgrade.get_settings(), "syslog_target", "192.168.20.5")
    monkeypatch.setattr(upgrade.socket, "gethostname", lambda: "Homepage.lan")
    assert REAL_ME() == upgrade.Me(frozenset({"192.168.10.156", "192.168.20.5"}), frozenset({"bc:24:11:00:00:aa"}),
                                   "homepage")
    monkeypatch.setattr(upgrade.get_settings(), "syslog_target", "127.0.0.1")
    assert REAL_ME().ips == {"192.168.10.156"}
    assert upgrade.NOODPLAN_KEY == NOODPLAN_KEY


def _noodplan(*guests) -> AppState:
    return AppState(key=NOODPLAN_KEY, value={"at": "2026-10-12T06:00:00+00:00", "data": {"clusters": [
        {"key": "pve:9", "nodes": [{"name": "pve50"}], "guests": list(guests)}]}})


def _guest(kind, vmid, mac=None, ip=None) -> dict:
    return {"type": kind, "vmid": vmid, "node": "pve50", "ip": ip,
            "nets": [{"if": "net0", "mac": mac}] if mac else []}


async def test_herkent_het_dashboard_aan_wat_het_zelf_weet(authed, monkeypatch):
    agen, db = await _db()
    ident = upgrade.Me(frozenset({"192.168.10.156"}), frozenset({"bc:24:11:00:01:05"}), "homepage")
    monkeypatch.setattr(upgrade, "me", lambda: ident)
    node = SshHost(name="pve50", host="192.168.0.50", host_key="x", source="pve:9:node/pve50")
    hosts = [node,
             SshHost(name="dash-ip", host="192.168.10.156", host_key="x"),
             SshHost(name="lokaal", host="127.0.0.1", port=22, host_key="x"),
             SshHost(name="tunnel", host="127.0.0.1", port=2222, host_key="x"),
             SshHost(name="naam", host="homepage.lan", host_key="x"),
             SshHost(name="nas", host="192.168.0.9", host_key="x"),
             SshHost(name="vm-dash", host="192.168.30.7", host_key="x", source="pve:9:qemu/110"),
             SshHost(name="ct107", host="192.168.10.156", host_key="x", source="pve:9:lxc/107")]
    db.add_all(hosts)
    db.add(_noodplan(_guest("lxc", 105, mac="BC:24:11:00:01:05"), _guest("lxc", 106, mac="bc:24:11:00:01:06"),
                     _guest("qemu", 110, ip="192.168.10.156")))
    await db.commit()
    ids = {h.name: h.id for h in hosts}

    async def who(key, name=None):
        p = await upgrade.plan_for(db, key, name)
        await upgrade.mark_self(db, [p])
        return p.me

    assert "192.168.10.156 is een adres van het dashboard" == await who(f"ssh:{ids['dash-ip']}")
    assert "127.0.0.1:22 is het dashboard zelf" == await who(f"ssh:{ids['lokaal']}")
    assert await who(f"ssh:{ids['tunnel']}") is None  # een doorgestuurde poort naar een andere machine
    assert "homepage.lan is de hostname van het dashboard" == await who(f"ssh:{ids['naam']}")
    assert await who(f"ssh:{ids['nas']}") is None
    # Het noodplan: het MAC-adres uit de config in Proxmox, of het IP van een VM.
    node_id = ids["pve50"]
    assert "MAC-adres bc:24:11:00:01:05" in await who(f"ssh:{node_id}:ct:105", "iets")
    assert "qemu 110 heeft 192.168.10.156" in await who(f"ssh:{ids['vm-dash']}")
    # De SSH-host van de CT zelf heeft een adres van het dashboard.
    assert "192.168.10.156 is een adres van het dashboard" == await who(f"ssh:{node_id}:ct:107", "ct107")
    # Alleen de hostname uit de scan: telt, tenzij het noodplan de MAC-adressen van die CT kent en geen ervan klopt.
    assert "zoals de hostname van het dashboard" in await who(f"ssh:{node_id}:ct:120", "homepage")
    assert await who(f"ssh:{node_id}:ct:106", "homepage") is None
    assert await who(f"ssh:{node_id}:ct:121", "plex") is None
    assert await who(f"ssh:{node_id}") is None
    await agen.aclose()


async def test_dashboard_zelf_nooit_snachts_of_samen_met_andere(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    node = Apt()
    port = await node.start()
    hid = await _host(authed, "pve50", port, node.key, source="pve:9:node/pve50")
    monkeypatch.setattr(upgrade, "me", lambda: upgrade.Me(frozenset({"192.168.10.156"}),
                                                          frozenset({"bc:24:11:00:01:05"}), "homepage"))
    agen, db = await _db()
    db.add(_noodplan(_guest("lxc", 105, mac="bc:24:11:00:01:05"), _guest("lxc", 106, mac="bc:24:11:00:01:06")))
    await db.commit()
    dash, plex = f"ssh:{hid}:ct:105", f"ssh:{hid}:ct:106"
    await _updates_state(db, [_t(dash, "homepage", "ct"), _t(plex, "plex", "ct")])

    plans = (await authed.get("/api/updates/plans")).json()
    assert "MAC-adres" in plans[dash]["self"] and plans[plex]["self"] is None and plans[dash]["can"] is True

    # 's Nachts: alleen plex; de proef zegt waarom het dashboard overgeslagen wordt.
    await authed.put("/api/updates/settings", json={"auto": True, "hour": 3, "keep_days": 7})
    p = await upgrade.describe_auto(db, NO_HTTP)
    assert p["runs"] == [{"key": plex, "name": "plex"}]
    why = {x["what"]: x["why"] for x in p["skipped"]}["homepage"]
    assert why.startswith("het dashboard zelf (het MAC-adres bc:24:11:00:01:05 van lxc 105 is dat van het dashboard)")
    assert "nooit 's nachts" in why and "bootstrap.sh" in why and "Console" in why
    ids = await upgrade.auto_updates(_maker_from(agen), NO_HTTP, datetime(2026, 10, 5, 3, 1).astimezone())
    assert [(await db.get(UpdateRun, i)).target for i in ids] == [plex]
    assert not any("pct snapshot 105" in c or "pct exec 105" in c for c in node.commands)

    # Alles bijwerken (meer dan één machine): het dashboard geweigerd, met dezelfde reden; de rest loopt.
    p = (await authed.post("/api/updates/install/proef", json={"targets": [dash, plex]})).json()
    assert p["runs"] == [{"key": plex, "name": "plex"}] and p["refused"][0]["self"] is True
    r = (await authed.post("/api/updates/install", json={"targets": [dash, plex]})).json()
    assert [x["target"] for x in r["runs"]] == [plex]
    assert r["refused"] == [{"key": dash, "name": "homepage", "why": p["refused"][0]["why"], "self": True}]
    await _wait(authed, r["runs"][0]["id"])
    # (na de run scant de router opnieuw; de nep-node kent geen scan)
    await _updates_state(db, [_t(dash, "homepage", "ct"), _t(plex, "plex", "ct")])

    # Bewust alleen het dashboard: kan, maar de proef en de run zeggen dat het beter anders kan.
    p = (await authed.post("/api/updates/install/proef", json={"targets": [dash]})).json()
    assert p["runs"] == [{"key": dash, "name": "homepage"}] and p["refused"] == []
    [w] = [w for w in p["warnings"] if "het dashboard zelf" in w]
    assert w.startswith("homepage is het dashboard zelf (") and "breekt de run af" in w
    assert "deploy/bootstrap.sh" in w and "apt update && apt upgrade" in w
    r = (await authed.post("/api/updates/install", json={"targets": [dash]})).json()
    run = await _wait(authed, r["runs"][0]["id"])
    assert run["status"] == "ok" and run["output"].startswith("let op: homepage is het dashboard zelf")
    assert any("pct exec 105" in c for c in node.commands)

    # Een nachtelijke run die toch voor het dashboard klaarstaat (het kreeg intussen dit adres): niets via SSH.
    n = len(node.commands)
    u = UpdateRun(target=dash, target_name="homepage", trigger="auto", security_only=True, status="wacht",
                  snapshot={"kind": "pct"}, reboot_needed=False)
    db.add(u)
    await db.commit()
    assert await upgrade.execute(_maker_from(agen), u.id, NO_HTTP, ["openssl"]) == "fout"
    await db.refresh(u)
    assert u.error.startswith("het dashboard zelf") and len(node.commands) == n
    await agen.aclose()


async def test_plans_zonder_noodplan_of_eigen_adres(authed):
    """Geen noodplan en een machine die niet het dashboard is: niets overgeslagen (de vaste Me() uit conftest)."""
    node = Node()
    hid = await _host(authed, "pve50", await node.start(), node.key)
    agen, db = await _db()
    await _updates_state(db, [_t(f"ssh:{hid}:ct:105", "homepage", "ct")])
    plans = (await authed.get("/api/updates/plans")).json()
    assert plans[f"ssh:{hid}:ct:105"] == {"can": True, "why": None, "snapshot": "pct", "nosnap": None, "self": None}
    await agen.aclose()
