import asyncio
import json
import os
import re
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.config import get_settings
from app.db import ensure_state
from app.integrations import IntegrationError
from app.models import AppState, AuditLog, ConfigVersion, Device, Event, Notification
from app.monitoring import noodplan as nood, noodplan_doc as doc
from app.monitoring.checks import HttpClients
from app.security import encrypt

from .test_buitenaf import CF, _stale
from .test_integrations import _group, _svc
from .test_kaart_hersteltest import _maker
from .test_meldingen_onderhoud import _db


# Een noodplan zoals de worker het bewaart, met de hand geschreven (voor het document alleen).
def _value(**data):
    guest = {"vmid": 101, "type": "lxc", "name": "homepage", "node": "pve50", "status": "running", "onboot": True,
             "order": 3, "nets": [{"if": "net0", "mac": "bc:24:11:00:00:01", "bridge": "vmbr0", "tag": 10,
                                   "ip": "192.168.10.156/24"}],
             "ip": "192.168.10.156", "ip_from": "vast",
             "disks": [{"key": "rootfs", "storage": "local-lvm", "size": "32G", "in_backup": True},
                       {"key": "mp0", "bind": "/mnt/tank/media", "mp": "/media", "in_backup": False, "why": "bind mount"}],
             "bound": [], "config_from": "api", "backups": [{"pbs": "PBS pi", "last": "2026-10-12T01:00:05+00:00"}],
             "volids": {"pbs-pi": "pbs-pi:backup/ct/101/2026-10-12T01:00:05Z"},
             "coverage": {"level": "ok", "why": "2 kopieën"}, "services": [{"name": "Homepage", "url": "https://home.jbogaert.be"}],
             "roles": ["dashboard"]}
    base = {"dashboard": {"versie": "v1.4.0", "ip": "192.168.10.156", "guest": guest, "domains": ["home.jbogaert.be"],
                          "offsite_on": True, "offsite_dir": "/mnt/homepage-backup", "backup_dir": "/var/backups/homepage",
                          "versions": {"postgresql": "17.6", "timescaledb": "2.22.1"}},
            "clusters": [{"key": "pve:3", "service": "PVE", "name": "thuis", "qdevice": "192.168.0.60",
                          "nodes": [{"name": "pve50", "ip": "192.168.0.50", "ip_from": "netwerk",
                                     "corosync_ip": "10.10.10.50", "online": True, "arch": "x86_64"}],
                          "guests": [guest],
                          "pbs_storages": [{"storage": "pbs-pi", "server": "192.168.0.60", "datastore": "backup",
                                            "username": "pve@pbs", "encrypted": "12:34:56"}],
                          "jobs": [{"id": "backup-nacht", "schedule": "01:00", "storage": "pbs-pi", "enabled": True,
                                    "all": True, "targets": [101], "except": [9000]}]}],
            "access": [], "pbs": [], "tunnels": []}
    return {"v": 1, "at": "2026-10-12T10:02:11+00:00", "seconds": 41, "sources": [
        {"key": "pve:3", "name": "Proxmox pve50", "ok": True}], "data": {**base, **data}}


def test_document_html_en_md():
    bl = doc.blocks(_value())
    html, md = doc.to_html(bl, "Noodplan"), doc.to_md(bl)
    assert html.startswith("<!doctype html>") and "<script" not in html and "<h1" in html
    assert md.startswith("# Noodplan homelab")
    for title in ("1. Eerst", "2. Toegang zonder DNS", "3. Nodes en wat erop draait", "4. Back-ups: waar ze staan",
                  "5. Een CT of VM terugzetten", "6. Configuratie van OPNsense en NPM",
                  "7. Sleutels: welke je nodig hebt en waar ze staan", "8. Het dashboard zelf terugzetten"):
        assert f"## {title}" in md and f">{title}</h2>" in html
    # De rij van de CT, met de schijf die niet in de back-up zit in het rood.
    assert "192.168.10.156 (corosync 10.10.10.50)" not in md and "pve50 · 192.168.0.50 (corosync 10.10.10.50)" in md
    assert "mp0 bind /mnt/tank/media op /media **niet in de back-up**" in md
    assert '<strong class="bad">niet in de back-up</strong>' in html
    assert "| ↳ diensten: Homepage (<https://home.jbogaert.be>) · dit is het dashboard |" in md
    assert '<tr class="svc"><td colspan="7">' in html
    assert "`pct restore 101 pbs-pi:backup/ct/101/2026-10-12T01:00:05Z --storage local-lvm`" in md
    assert "alle behalve 9000" in md and "ja, vingerafdruk 12:34:56" in md
    assert "key paperkey /etc/pve/priv/storage/pbs-pi.enc --output-format text" in md
    assert "Volgende versie: maandag 19/10." in md and "pg_restore" in md
    # Geen naam die op een geheim lijkt met ":" of "=" erachter (de maskering zou het woord erna vervangen).
    from app.masking import mask
    assert mask(md) == md and mask(html) == html


def test_escape():
    bad = {"name": "<script>alert(1)</script>", "url": "javascript:alert(1)"}
    v = _value()
    v["data"]["clusters"][0]["guests"][0]["services"] = [bad, {"name": "Jellyfin", "url": "https://jf.jbogaert.be/?a=1&b=2"}]
    bl = doc.blocks(v)
    html, md = doc.to_html(bl, "Noodplan"), doc.to_md(bl)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "<script>" not in html
    assert "<script>alert(1)</script>" in md
    assert "javascript:alert(1)" in html and 'href="javascript' not in html
    assert 'href="https://jf.jbogaert.be/?a=1&amp;b=2"' in html
    links = re.findall(r"<a [^>]*>", html)
    assert links and all('target="_blank"' in a and 'rel="noopener noreferrer"' in a for a in links)


def test_pick_config_en_parsers():
    cfg = {"net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0,firewall=1", "ipconfig0": "ip=192.168.0.30/24,gw=192.168.0.1",
           "scsi0": "local-lvm:vm-100-disk-0,size=32G", "hostpci0": "0000:01:00.0,pcie=1", "nameserver": "192.168.0.1",
           "description": "wachtwoord=hunter2", "cipassword": "x", "sshkeys": "ssh-rsa%20AAA", "hookscript": "local:snippets/x",
           "arch": "amd64", "onboot": 1, "startup": "order=2,up=30", "agent": "enabled=1,fstrim_cloned_disks=1"}
    p = nood.pick_config(cfg, "qemu", "pve50")
    flat = repr(p)
    assert "hunter2" not in flat and "ssh-rsa" not in flat and "snippets" not in flat and "'x'" not in flat
    assert p["nets"] == [{"if": "net0", "mac": "bc:24:11:00:00:02", "bridge": "vmbr0", "tag": None,
                          "ip": "192.168.0.30/24", "gw": "192.168.0.1", "model": "virtio", "cloudinit": True}]
    assert p["arch"] == "amd64" and p["dns"]["nameserver"] == "192.168.0.1" and p["onboot"] and p["order"] == 2
    assert p["agent"] and p["bound"] == [{"key": "hostpci0", "what": "PCI 0000:01:00.0", "node": "pve50"}]
    assert nood.static_ip(p["nets"]) == ("192.168.0.30", "vast (cloud-init)")

    lxc = nood.parse_net("net0", "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.168.10.156/24,gw=192.168.10.1,"
                                 "tag=10,type=veth", "lxc")
    assert (lxc["mac"], lxc["ip"], lxc["gw"], lxc["bridge"], lxc["tag"]) == \
        ("bc:24:11:00:00:01", "192.168.10.156/24", "192.168.10.1", "vmbr0", 10)
    assert nood.parse_net("net0", "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:04,ip=dhcp", "lxc")["ip"] == "dhcp"
    q = nood.parse_net("net1", "virtio=BC:24:11:00:00:03,bridge=vmbr1,tag=20", "qemu")
    assert (q["model"], q["mac"], q["tag"]) == ("virtio", "bc:24:11:00:00:03", 20)
    assert nood.parse_ipconfig("ip=192.168.0.30/24,gw=192.168.0.1") == {"ip": "192.168.0.30/24", "gw": "192.168.0.1"}
    assert nood.parse_ipconfig("ip=dhcp,ip6=auto")["ip"] == "dhcp"

    d = nood.parse_disk
    assert d("rootfs", "local-lvm:vm-101-disk-0,size=32G", "lxc")["in_backup"]
    mp1 = d("mp1", "local-lvm:vm-101-disk-1,mp=/data,size=8G", "lxc")
    assert not mp1["in_backup"] and mp1["why"] == "mount point zonder backup=1" and mp1["storage"] == "local-lvm"
    assert d("mp2", "local-lvm:vm-101-disk-2,mp=/srv,size=4G,backup=1", "lxc")["in_backup"]
    bind = d("mp0", "/mnt/tank/media,mp=/media", "lxc")
    assert not bind["in_backup"] and bind["why"] == "bind mount" and bind["bind"] == "/mnt/tank/media"
    dev = d("mp3", "/dev/sdb1,mp=/x", "lxc")
    assert not dev["in_backup"] and dev["why"] == "apparaat"
    assert d("scsi0", "local-lvm:vm-100-disk-0,size=32G", "qemu")["in_backup"]
    s1 = d("scsi1", "local-lvm:vm-100-disk-1,size=100G,backup=0", "qemu")
    assert not s1["in_backup"] and s1["why"] == "backup=0"
    assert d("ide2", "local:iso/debian.iso,media=cdrom", "qemu") is None and d("ide2", "none,media=cdrom", "qemu") is None

    b = nood.parse_bound
    assert b("hostpci0", "0000:01:00.0", "pve51") == {"key": "hostpci0", "what": "PCI 0000:01:00.0", "node": "pve51"}
    assert b("hostpci1", "mapping=gpu,pcie=1", "pve51") == {"key": "hostpci1", "what": "PCI-mapping gpu", "mapping": "gpu"}
    assert b("usb0", "spice", "pve51") is None and b("usb1", "host=046d:c52b", "pve51")["node"] == "pve51"
    assert b("usb2", "mapping=zigbee", "pve51")["mapping"] == "zigbee"
    assert b("dev0", "/dev/ttyUSB0,gid=20", "pve50")["what"] == "apparaat /dev/ttyUSB0"
    assert nood.parse_conf_text("arch: amd64\nnet0: name=eth0,ip=dhcp\n[snap1]\nnet0: oud\n") == \
        {"arch": "amd64", "net0": "name=eth0,ip=dhcp"}

    guests = [{"vmid": 100, "node": "pve50"}, {"vmid": 101, "node": "pve50"}, {"vmid": 102, "node": "pve51"},
              {"vmid": 9000, "node": "pve50"}]
    rows = [{"vmid": 100, "jobs": ["nacht", "pve50"]}, {"vmid": 101, "jobs": ["nacht", "pve50"]},
            {"vmid": 102, "jobs": ["nacht"]}, {"vmid": 9000, "jobs": []}]
    assert nood.job_targets({"id": "nacht", "all": True}, rows, guests) == {"targets": [100, 101, 102], "except": [9000]}
    assert nood.job_targets({"id": "pve50", "all": True, "node": "pve50"}, rows, guests) == \
        {"targets": [100, 101], "except": [9000]}
    assert nood.job_targets({"id": "nacht", "all": True, "enabled": False}, rows, guests)["targets"] == []

    net = [{"iface": "vmbr1", "type": "bridge", "address": "10.10.10.50", "active": 1},
           {"iface": "vmbr0", "type": "bridge", "address": "192.168.0.50", "gateway": "192.168.0.1", "active": 1}]
    assert nood.node_ip(net, "10.10.10.50") == ("192.168.0.50", "netwerk")
    assert nood.node_ip(None, "10.10.10.50") == ("10.10.10.50", "corosync")
    assert nood.node_arch({"current-kernel": {"machine": "x86_64"}}, []) == "x86_64"
    assert nood.node_arch({}, [None, "arm64"]) == "aarch64" and nood.node_arch(None, []) is None

    vols = nood.newest_volids([
        {"volid": "pbs-pi:backup/ct/101/2026-10-10T01:00:05Z", "subtype": "lxc", "vmid": 101, "ctime": 10},
        {"volid": "pbs-pi:backup/ct/101/2026-10-11T01:00:05Z", "vmid": 101, "ctime": 20, "encrypted": "12:34"},
        {"volid": "pbs-pi:backup/vm/100/2026-10-11T01:10:00Z", "subtype": "qemu", "vmid": "100", "ctime": 30}])
    assert vols[("lxc", 101)] == ("pbs-pi:backup/ct/101/2026-10-11T01:00:05Z", 20, "12:34")
    assert vols[("qemu", 100)][0].endswith("vm/100/2026-10-11T01:10:00Z")

    ct = {"vmid": 101, "type": "lxc", "disks": [{"key": "rootfs", "storage": "local-lvm", "in_backup": True},
                                                {"key": "mp1", "storage": "local-lvm", "in_backup": False}]}
    assert nood.restore_command(ct, "pbs-pi:backup/ct/101/x", "pbs-pi") == \
        "pct restore 101 pbs-pi:backup/ct/101/x --storage local-lvm"
    assert nood.restore_command({"vmid": 100, "type": "qemu"}, "pbs-pi:backup/vm/100/x", "pbs-pi") == \
        "qmrestore pbs-pi:backup/vm/100/x 100"
    assert nood.restore_command(ct, None, "pbs-pi") == \
        "pct restore 101 pbs-pi:backup/ct/101/<tijd uit pvesm list> --storage local-lvm"
    assert nood.storage_note(ct) is None  # mp1 zit niet in de back-up
    ct["disks"].append({"key": "mp2", "storage": "tank", "in_backup": True})
    assert "mp2" in nood.storage_note(ct)

    # Maandag 6 uur lokale tijd.
    mon = datetime(2026, 10, 12, 6, 0).astimezone()
    ago = lambda **kw: (mon - timedelta(**kw)).isoformat()  # noqa: E731
    last_week = {"at": ago(days=7)}
    assert not nood.due(last_week, mon - timedelta(minutes=1)) and nood.due(last_week, mon)
    assert not nood.due({"at": mon.isoformat()}, mon + timedelta(hours=1))
    assert nood.due(last_week, mon + timedelta(days=1)) and nood.due(None, mon) and nood.due({}, mon)
    assert not nood.due({**last_week, "tried": ago(minutes=-50)}, mon + timedelta(hours=1))
    assert not nood.due({**last_week, "running": {"at": mon.isoformat()}}, mon + timedelta(minutes=1))
    crashed = {**last_week, "running": {"at": ago(minutes=70)}, "tried": ago(minutes=70)}
    assert nood.due(crashed, mon)
    assert nood.next_slot(mon + timedelta(hours=1)) == mon + timedelta(days=7)


# --- een cluster met twee nodes, een PBS, OPNsense en NPM -------------------------------------------------------------

PVE_URL, PBS_URL = "https://192.168.0.50:8006", "https://192.168.0.60:8007"
T0 = datetime(2026, 10, 12, 4, 2, 11, tzinfo=timezone.utc)
# Geheimen die nooit in het noodplan mogen staan (willekeurig, zodat ze nergens toevallig in de tekst voorkomen).
SECRETS = ("Xq7-pve-9Zt", "Kd2-pbs-4Wm", "Opn-key-7Rk", "Opn-sec-3Vb", "Npm-pw-8Lc", "hunter2", "cloudgeheim-Q1", "Cmt-x9",
           "Blob-zout-5Tq")
RES = [{"type": "node", "node": "pve50", "status": "online"}, {"type": "node", "node": "pve51", "status": "offline"},
       {"type": "lxc", "vmid": 101, "name": "homepage", "node": "pve50", "status": "running"},
       {"type": "qemu", "vmid": 100, "name": "opnsense", "node": "pve50", "status": "running"},
       {"type": "lxc", "vmid": 102, "name": "media", "node": "pve51", "status": "unknown"},
       {"type": "qemu", "vmid": 9000, "name": "sjabloon", "node": "pve50", "status": "stopped", "template": 1}]
CONF = {
    "/api2/json/nodes/pve50/lxc/101/config": {
        "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.168.10.156/24,gw=192.168.10.1,tag=10,type=veth",
        "rootfs": "local-lvm:vm-101-disk-0,size=32G", "mp0": "/mnt/tank/media,mp=/media",
        "mp1": "local-lvm:vm-101-disk-1,mp=/data,size=8G", "mp2": "local-lvm:vm-101-disk-2,mp=/srv,size=4G,backup=1",
        "arch": "amd64", "onboot": 1, "startup": "order=3", "description": "wachtwoord=hunter2", "digest": "abc"},
    "/api2/json/nodes/pve50/qemu/100/config": {
        "net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0", "net1": "virtio=BC:24:11:00:00:03,bridge=vmbr1,tag=20",
        "scsi0": "local-lvm:vm-100-disk-0,size=32G", "scsi1": "local-lvm:vm-100-disk-1,size=100G,backup=0",
        "hostpci0": "0000:01:00.0,pcie=1", "cipassword": "cloudgeheim-Q1", "onboot": 1, "startup": "order=1"},
}
CONF_102 = "arch: amd64\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:04,ip=dhcp\nrootfs: local-lvm:vm-102-disk-0,size=8G\n"
CONTENT = [{"volid": "pbs-pi:backup/ct/101/2026-10-10T01:00:05Z", "subtype": "lxc", "vmid": 101, "ctime": 1760058005},
           {"volid": "pbs-pi:backup/ct/101/2026-10-11T01:00:05Z", "subtype": "lxc", "vmid": 101, "ctime": 1760144405},
           {"volid": "pbs-pi:backup/vm/100/2026-10-11T01:10:00Z", "subtype": "qemu", "vmid": 100, "ctime": 1760145000}]


def _ok(data):
    return httpx.Response(200, json={"data": data})


class World:
    def __init__(self):
        self.seen: list[str] = []
        self.broken_pbs = False

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        self.seen.append(p)
        if req.url.host == "192.168.0.99":
            raise httpx.ConnectError("geen route naar de host", request=req)
        if req.url.host == "192.168.0.60":
            if p == "/api2/json/config/datastore":
                if self.broken_pbs:
                    return httpx.Response(403, json={"data": None})
                return _ok([{"name": "backup", "path": "/mnt/datastore/backup", "comment": "Cmt-x9"}])
            return httpx.Response(404)
        if p == "/api2/json/cluster/resources":
            return _ok(RES)
        if p == "/api2/json/storage":
            return _ok([{"storage": "pbs-pi", "type": "pbs", "server": "192.168.0.60", "datastore": "backup",
                         "fingerprint": "ab:cd", "username": "pve@pbs", "encryption-key": "12:34:56"},
                        {"storage": "local-lvm", "type": "lvmthin"}])
        if p == "/api2/json/nodes/pve50/status":
            return _ok({"current-kernel": {"machine": "x86_64"}, "cpuinfo": {"model": "Intel i5", "cpus": 6},
                        "memory": {"total": 34359738368}})
        if p == "/api2/json/nodes/pve50/network":
            return _ok([{"iface": "vmbr0", "type": "bridge", "address": "192.168.0.50", "gateway": "192.168.0.1",
                         "active": 1}, {"iface": "vmbr1", "type": "bridge", "address": "10.10.10.50", "active": 1}])
        if p in CONF:
            return _ok(CONF[p])
        if p == "/api2/json/nodes/pve50/storage/pbs-pi/content":
            return _ok(CONTENT)
        if p.startswith("/api2/json/nodes/pve51/"):
            return httpx.Response(500, json={"data": None})
        return httpx.Response(404)


async def _setup(authed, monkeypatch, tmp_path, npm_pw="Npm-pw-8Lc", extra_tile=None):
    s = get_settings()
    monkeypatch.setattr(s, "syslog_target", "192.168.10.156")
    monkeypatch.setattr(s, "offsite_dir", tmp_path / "offsite")
    (tmp_path / "nginx").write_text("lan=dicht\nnpm=192.168.0.245\n")
    monkeypatch.setattr(s, "nginx_file", tmp_path / "nginx")
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", PVE_URL, {"insecure": True},
                     {"username": "homepage@pve!dash", "password": "Xq7-pve-9Zt"}, name="PVE")
    pbs = await _svc(authed, g, "proxmoxbackupserver", PBS_URL, {"insecure": True},
                     {"username": "homepage@pbs!dash", "password": "Kd2-pbs-4Wm"}, name="PBS pi")
    await _svc(authed, g, "opnsense", "https://192.168.0.20", secrets={"key": "Opn-key-7Rk", "secret": "Opn-sec-3Vb"},
               name="OPNsense")
    await _svc(authed, g, "npm", "http://192.168.0.245:81", secrets={"username": "jonas@jbogaert.be", "password": npm_pw},
               name="NPM")
    await _svc(authed, g, "link", "https://home.jbogaert.be", name=extra_tile or "Homepage")
    agen, db = await _db()
    states = {
        "coverage": {"at": "2026-10-12T04:00:00+00:00", "clusters": [{
            "service_id": pve, "service": "PVE", "error": None, "nodes": ["pve50", "pve51"],
            "rows": [{"vmid": 101, "type": "ct", "name": "homepage", "pbs_count": 1, "stopped": False,
                      "jobs": ["backup-nacht"], "level": "warn", "why": "maar één kopie",
                      "copies": [{"pbs": "PBS pi", "service_id": pbs, "store": "backup", "ns": "", "age": 10800,
                                  "count": 14}], "restore": {"at": "2026-10-01T05:00:00+00:00", "ok": True}},
                     {"vmid": 100, "type": "vm", "name": "opnsense", "pbs_count": 1, "stopped": False,
                      "jobs": ["backup-nacht"], "level": "warn", "why": "maar één kopie",
                      "copies": [{"pbs": "PBS pi", "service_id": pbs, "store": "backup", "ns": "", "age": 10200,
                                  "count": 14}]},
                     {"vmid": 102, "type": "ct", "name": "media", "pbs_count": 0, "stopped": False, "jobs": [],
                      "copies": [], "level": "err",
                      "why": "zit in geen enkele back-upjob"}],
            "jobs": [{"id": "backup-nacht", "storage": "pbs-pi", "schedule": "01:00", "enabled": True, "all": True,
                      "node": None, "pool": None, "comment": "Cmt-x9", "pbs": True, "server": "192.168.0.60",
                      "datastore": "backup"}]}],
            "pbs": [{"service_id": pbs, "name": "PBS pi", "host": "192.168.0.60", "port": 8007, "fingerprint": "ab:cd",
                     "stores": [{"store": "backup", "used": 812e9, "total": 1.8e12, "groups": 34}], "syncs": [],
                     "remotes": [], "error": None}]},
        "cluster": {"items": [{"service_id": pve, "cluster": "thuis", "quorate": True,
                               "qdevice": {"host": "192.168.0.61", "state": "Connected"},
                               "nodes": [{"name": "pve50", "online": True, "ip": "10.10.10.50", "version": "8.4.1"},
                                         {"name": "pve51", "online": False, "ip": "10.10.10.51"}]}]},
        "npm_routes": {"hosts": {"home.jbogaert.be": {"host": "192.168.10.156", "port": 80, "scheme": "http"}}},
        "selfcheck": {"backups": [{"name": "homepage-2026-10-12.dump", "at": "2026-10-12T01:30:00+00:00", "size": 9}],
                      "verified": {"ok": True, "why": "93 tabellen"},
                      "offsite": {"enabled": True, "dir": "/mnt/homepage-backup", "error": None, "count": 3,
                                  "latest": {"name": "homepage-2026-10-12.dump"}, "key": True}},
        "offsite_key": {"at": "2026-09-03T18:10:00+00:00", "blob": {"salt": "Blob-zout-5Tq"}, "sha256": "ff"},
        "secret_key_saved": {"at": "2026-09-01T10:00:00+00:00"},
    }
    for key, value in states.items():
        (await ensure_state(db, key, {})).value = value
    db.add(Device(mac="bc:24:11:00:00:02", ip="192.168.0.20", last_seen=T0 - timedelta(hours=1)))
    db.add(Device(mac="a0:8c:fd:11:22:33", ip="192.168.0.50", last_seen=T0 - timedelta(hours=1)))
    db.add(ConfigVersion(item=f"pve:{pve}:102", name="CT 102 media · 102.conf", kind="pve", ts=T0 - timedelta(days=1),
                         sha="0" * 64, size=len(CONF_102), content=encrypt(CONF_102)))
    await db.commit()
    await agen.aclose()
    return pve, pbs


async def _plan(db) -> dict:
    return (await db.get(AppState, nood.STATE_KEY, populate_existing=True)).value


async def _run(world, now=T0, **kw):
    return await nood.run(_maker(), HttpClients(httpx.MockTransport(world)), now=now, **kw)


async def test_noodplan_inhoud(authed, monkeypatch, tmp_path):
    await _setup(authed, monkeypatch, tmp_path)
    world = World()
    assert (await _run(world, trigger="knop", user="jonas"))["ok"]
    agen, db = await _db()
    value = await _plan(db)
    html, masked, kinds = await nood.render(db, value, "html")
    md = (await nood.render(db, value, "md"))[0]
    assert value["trigger"] == "knop" and value["by"] == "jonas" and value["running"] is None
    assert "https://192.168.0.50:8006" in html and "pve50 · 192.168.0.50 (corosync 10.10.10.50) · x86_64" in md
    assert "Proxmox 8.4.1 · online" in md and "MAC a0:8c:fd:11:22:33 (Wake-on-LAN) · Intel i5 · 6 cpu · 32 GB" in md
    # pve51 is offline en had nog nooit een noodplan: het corosync-IP, en de architectuur uit de kopie van CT 102.
    assert "pve51 · 10.10.10.51 (corosync-IP) · x86_64" in md and "offline" in md
    row101 = next(line for line in md.splitlines() if line.startswith("| 101 |"))
    assert "192.168.10.156 (vast)" in row101 and "bc:24:11:00:00:01 vmbr0 VLAN 10" in row101
    assert "rootfs local-lvm 32G" in row101 and "mp0 bind /mnt/tank/media op /media **niet in de back-up**" in row101
    assert "| rootfs local-lvm 32G; mp0 bind" in row101 and "mp1 local-lvm 8G /data **niet in de back-up**" in row101
    assert "mp2 local-lvm 4G /srv |" in row101
    assert row101.rstrip(" |").endswith("PBS pi 12/10 01:00") and "autostart 3" in row101
    row100 = next(line for line in md.splitlines() if line.startswith("| 100 |"))
    assert "192.168.0.20 (ARP/DHCP (OPNsense), gezien 12/10)" in row100 and "net1 bc:24:11:00:00:03 vmbr1 VLAN 20" in row100
    assert "scsi1 local-lvm 100G **niet in de back-up**" in row100
    assert "**gebonden aan pve50** (PCI 0000:01:00.0)" in md and "dit is OPNsense" in md
    assert "↳ diensten: Homepage (<https://home.jbogaert.be>) · dit is het dashboard" in md
    assert "`pct restore 101 pbs-pi:backup/ct/101/2026-10-11T01:00:05Z --storage local-lvm`" in md
    assert "`qmrestore pbs-pi:backup/vm/100/2026-10-11T01:10:00Z 100`" in md
    assert "`pct restore 102 pbs-pi:backup/ct/102/<tijd uit pvesm list> --storage local-lvm` | **geen back-up** |" in md
    assert "| 102 | media | CT · status onbekend |" in md
    assert "configuratie uit de kopie van 11/10 (de node gaf geen antwoord)" in md
    assert "**onbekend** (node niet bereikbaar, IP via DHCP)" in md and "**geen back-up!** zit in geen enkele" in md
    assert "met ID pbs-pi (dezelfde naam" in md and "fingerprint ab:cd" in md and "ja, vingerafdruk 12:34:56" in md
    assert "key paperkey /etc/pve/priv/storage/pbs-pi.enc --output-format text" in md
    assert "`proxmox-backup-manager datastore create backup /mnt/datastore/backup --reuse-datastore true`" in md
    assert "| backup-nacht | 01:00 | pbs-pi (PBS 192.168.0.60, datastore backup) | alle behalve 102 |" in md
    assert "cluster thuis, QDevice op 192.168.0.61" in md and "Nginx Proxy Manager" in md
    assert "| OPNsense | <https://192.168.0.20> | IP in de tegel | VM 100 op pve50 |" in md
    assert "| Dit dashboard | <https://home.jbogaert.be> | alleen via NPM" in md and "pct enter 101 op pve50" in md
    assert "homepage-terugzetten" in md and "pg_restore -d homepage" in md
    assert "versleuteld in /mnt/homepage-backup/secret.key.enc (wachtzin ingesteld 3/9)" in md
    stored = json.dumps(value)
    for secret in SECRETS + (get_settings().secret_key_file.read_text().strip(),):
        assert secret not in html and secret not in md and secret not in stored, secret
    assert "***" not in html and "***" not in md and masked == 0 and kinds == [] and value["masked"] == 0
    # Eén config per VM/CT, ook niet opnieuw voor het IP; de template telt niet mee.
    assert world.seen.count("/api2/json/nodes/pve50/lxc/101/config") == 1 and "/9000/" not in " ".join(world.seen)
    assert nood.counts(value["data"]) == {"nodes": 2, "guests": 3, "pbs": 1, "domains": 1, "zonder_backup": 1,
                                          "niet_in_backup": 3}
    ev = (await db.execute(select(Event).where(Event.title == "Noodplan bijgewerkt"))).scalar_one()
    assert ev.body == "2 nodes, 3 VM's en CT's (op vraag van jonas)" and ev.kind == "gezondheid"
    await agen.aclose()


async def test_live_ip():
    class Px:
        def __init__(self, answer):
            self.answer, self.seen = answer, []

        async def get(self, path):
            self.seen.append(path)
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
    ct = Px([{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": "192.168.0.31/24"}])
    assert await nood._live_ip(ct, "pve50", "lxc", 103) == ("192.168.0.31", "CT-interfaces", None)
    assert ct.seen == ["/nodes/pve50/lxc/103/interfaces"]
    vm = Px({"result": [{"name": "ens18", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "192.168.0.32"}]}]})
    assert await nood._live_ip(vm, "pve50", "qemu", 104) == ("192.168.0.32", "guest agent", None)
    assert vm.seen == ["/nodes/pve50/qemu/104/agent/network-get-interfaces"]
    no = Px(IntegrationError("Geweigerd (HTTP 403)"))
    assert (await nood._live_ip(no, "pve50", "qemu", 104))[2] == "geen rechten (VM.GuestAgent.Audit)"
    agent = Px(IntegrationError("HTTP 500: QEMU guest agent is not running"))
    assert (await nood._live_ip(agent, "pve50", "qemu", 104))[2] == "geen QEMU guest agent"


async def test_masker_vangnet(authed, monkeypatch, tmp_path):
    # (a) Een tegel met het geheim van het Proxmox-token als naam, op CT 101: in "diensten".
    await _setup(authed, monkeypatch, tmp_path, extra_tile="Xq7-pve-9Zt")
    assert (await _run(World()))["ok"]
    agen, db = await _db()
    value = await _plan(db)
    html, n, kinds = await nood.render(db, value, "html")
    assert "Xq7-pve-9Zt" not in html and "diensten: ***" in html and n > 0 and kinds == ["bekend"]
    assert value["masked"] == n and value["masked_kinds"] == ["bekend"]
    assert "op een geheim leek (bekend); dat is vervangen door ***" in html
    assert "Xq7-pve-9Zt" not in (await nood.render(db, value, "md"))[0]
    await agen.aclose()


async def test_masker_woord(authed, monkeypatch, tmp_path):
    # (b) Een geheim dat een gewoon woord is: vervangen, een waarschuwing, geen fout.
    await _setup(authed, monkeypatch, tmp_path, npm_pw="terugzetten")
    assert (await _run(World()))["ok"]
    agen, db = await _db()
    value = await _plan(db)
    md = (await nood.render(db, value, "md"))[0]
    assert "homepage-***" in md and value["masked"] > 0 and "bekend" in value["masked_kinds"]
    assert [k for k, _ in nood.problems(value, T0)] == ["masker"]
    from app import attention
    items = await attention.noodplan_items(db, T0, {})
    assert [i["level"] for i in items] == ["warn"] and "(bekend)" in items[0]["text"]
    assert not (await db.execute(select(Notification).where(Notification.level == "err"))).scalars().all()
    await agen.aclose()


async def test_vorige_versie_bij_fout(authed, monkeypatch, tmp_path):
    _, pbs = await _setup(authed, monkeypatch, tmp_path)
    world = World()
    key = f"bron:pbs:{pbs}"
    assert (await _run(world, T0))["ok"]
    agen, db = await _db()
    first = (await _plan(db))["data"]["pbs"]
    assert first[0]["stores"][0]["path"] == "/mnt/datastore/backup" and first[0]["ip"] == "192.168.0.60"
    world.broken_pbs = True
    for days in (7, 15):
        now = T0 + timedelta(days=days)
        assert (await _run(world, now))["ok"]
        v = await _plan(db)
        assert v["at"] == now.isoformat()
        assert v["data"]["pbs"] == [{**first[0], "stale_from": T0.isoformat()}]
        src = next(s for s in v["sources"] if s["key"] == f"pbs:{pbs}")
        assert not src["ok"] and src["from"] == T0.isoformat() and "403" in src["error"]
        html = (await nood.render(db, v, "html"))[0]
        assert "PBS pi: uit het noodplan van 12/10." in html and "dit deel komt uit het noodplan van 12/10" in html
        assert (key in [k for k, _ in nood.problems(v, now)]) == (days == 15)
    world.broken_pbs = False
    assert (await _run(world, T0 + timedelta(days=16)))["ok"]
    v = await _plan(db)
    src = next(s for s in v["sources"] if s["key"] == f"pbs:{pbs}")
    assert src == {"key": f"pbs:{pbs}", "name": "PBS pi", "ok": True} and v["data"]["pbs"][0]["stale_from"] is None
    assert nood.problems(v, T0 + timedelta(days=16)) == []
    await agen.aclose()


async def test_nooit_gelukt_en_dubbele_tegel(authed, monkeypatch, tmp_path):
    pve, _ = await _setup(authed, monkeypatch, tmp_path)
    g = await _group(authed)
    # Een tweede tegel naar dezelfde cluster, en een die nog nooit lukte.
    await _svc(authed, g, "proxmox", PVE_URL, {"insecure": True},
               {"username": "homepage@pve!dash", "password": "Xq7-pve-9Zt"}, name="PVE 2")
    bad = await _svc(authed, g, "proxmox", "https://192.168.0.99:8006", {"insecure": True},
                     {"username": "homepage@pve!dash", "password": "Xq7-pve-9Zt"}, name="Oud")
    assert (await _run(World()))["ok"]
    agen, db = await _db()
    v = await _plan(db)
    assert [c["key"] for c in v["data"]["clusters"]] == [f"pve:{pve}"]
    src = next(s for s in v["sources"] if s["key"] == f"pve:{bad}")
    assert not src["ok"] and src["from"] is None and src["failing_since"] == T0.isoformat()
    assert "Oud" in src["name"] and "nog nooit gelukt, dit deel ontbreekt" in (await nood.render(db, v, "md"))[0]
    assert nood.problems(v, T0 + timedelta(days=15))[0][0] == f"bron:pve:{bad}"
    await agen.aclose()


async def test_offsite(authed, monkeypatch, tmp_path):
    await _setup(authed, monkeypatch, tmp_path)
    dst = tmp_path / "offsite"
    agen, db = await _db()
    (await ensure_state(db, "health_settings", {})).value = {"offsite": True}
    await db.commit()
    world = World()

    async def notices():
        return [n.title for n in (await db.execute(select(Notification).where(
            Notification.title.like("Noodplan%")).order_by(Notification.id))).scalars()]

    # De map bestaat niet: een melding (alleen in het dashboard), één keer.
    assert (await _run(world, T0))["ok"]
    v = await _plan(db)
    assert v["offsite"]["enabled"] and v["offsite"]["error"].startswith("map ") and v["offsite"]["at"] is None
    n = (await db.execute(select(Notification).where(Notification.title == "Noodplan niet buiten de container"))).scalar_one()
    assert n.source == "homepage" and n.level == "warn" and n.pushed_at is not None
    assert (await _run(world, T0 + timedelta(hours=2)))["ok"]
    assert await notices() == ["Noodplan niet buiten de container"]

    dst.mkdir()
    old = os.umask(0o077)
    try:
        assert (await _run(world, T0 + timedelta(hours=3)))["ok"]
    finally:
        os.umask(old)
    v = await _plan(db)
    assert v["offsite"]["error"] is None and v["offsite"]["files"] == list(nood.FILES)
    assert v["offsite"]["at"] == (T0 + timedelta(hours=3)).isoformat()
    html, md = (dst / "noodplan.html").read_text(), (dst / "noodplan.md").read_text()
    assert html == (await nood.render(db, v, "html"))[0] and md == (await nood.render(db, v, "md"))[0]
    assert f"Kopie: {dst}/noodplan.html en noodplan.md" in html
    for f in nood.FILES:
        assert (dst / f).stat().st_mode & 0o777 == 0o644
    assert sorted(p.name for p in dst.iterdir()) == sorted(nood.FILES)
    ev = (await db.execute(select(Event).where(Event.title == "Noodplan staat weer buiten de container"))).scalar_one()
    assert ev.level == "ok" and await notices() == ["Noodplan niet buiten de container"]
    last = (await db.execute(select(Event).where(Event.title == "Noodplan bijgewerkt").order_by(Event.id.desc()))
            ).scalars().first()
    assert last.body.endswith(f"kopie in {dst}")

    # Mislukt ook de kopie van de dumps zelf, dan meldt de zelfcontrole het al: hier niet nog eens.
    sc = await ensure_state(db, "selfcheck", {})
    sc.value = {**sc.value, "offsite": {"enabled": True, "error": "map weg", "count": None}}
    await db.commit()
    monkeypatch.setattr(get_settings(), "offsite_dir", tmp_path / "weg")
    assert (await _run(world, T0 + timedelta(hours=4)))["ok"]
    assert (await _plan(db))["offsite"]["error"] and await notices() == ["Noodplan niet buiten de container"]

    # Uit: niets geschreven.
    (await ensure_state(db, "health_settings", {})).value = {"offsite": False}
    await db.commit()
    monkeypatch.setattr(get_settings(), "offsite_dir", dst)
    for f in nood.FILES:
        (dst / f).unlink()
    assert (await _run(world, T0 + timedelta(hours=5)))["ok"]
    v = await _plan(db)
    assert not v["offsite"]["enabled"] and not any(dst.iterdir())
    assert "de kopie buiten de container staat uit" in (await nood.render(db, v, "md"))[0]
    await agen.aclose()


async def test_api(authed, monkeypatch, tmp_path):
    from app.routers import noodplan as router
    await _setup(authed, monkeypatch, tmp_path)
    world = World()
    gate, reached = asyncio.Event(), asyncio.Event()

    async def gated(req):
        if req.url.path == "/api2/json/cluster/resources":
            reached.set()
            await gate.wait()
        return world(req)
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(gated)))
    st = (await authed.get("/api/noodplan")).json()
    assert st["at"] is None and st["counts"] is None and not st["running"] and st["sources"] == []
    assert st["offsite"] == {"enabled": False, "dir": str(tmp_path / "offsite")} and st["problems"] == []
    assert (await authed.get("/api/noodplan/document")).json()["detail"] == "Nog geen noodplan"

    # Nu bijwerken: 202, en zolang het loopt 409.
    assert (await authed.post("/api/noodplan/run")).status_code == 202
    # Pas kijken als de run bij Proxmox is: SQLite in de tests heeft maar één verbinding voor alle sessies.
    await asyncio.wait_for(reached.wait(), 10)
    st = (await authed.get("/api/noodplan")).json()
    assert st["running"] and st["running_by"] == "jonas"
    r = await authed.post("/api/noodplan/run")
    assert r.status_code == 409 and r.json()["detail"] == "Loopt al"
    gate.set()
    await router._task
    st = (await authed.get("/api/noodplan")).json()
    assert st["at"] and not st["running"] and st["trigger"] == "knop" and st["by"] == "jonas"
    assert st["counts"] == {"nodes": 2, "guests": 3, "pbs": 1, "domains": 1, "zonder_backup": 1, "niet_in_backup": 3}
    assert all(x["ok"] for x in st["sources"]) and "data" not in st and st["masked"] == 0
    assert st["next"] is None or st["next"] > st["at"]

    # Een run van de worker: de knop ziet hem (en een run naast een lopende stopt meteen).
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    row = await db.get(AppState, nood.STATE_KEY, populate_existing=True)
    row.value = {**row.value, "running": {"at": now.isoformat(), "by": "worker", "pid": 1}}
    await db.commit()
    st = (await authed.get("/api/noodplan")).json()
    assert st["running"] and st["running_by"] == "worker"
    assert (await authed.post("/api/noodplan/run")).status_code == 409
    assert await nood.run(_maker(), HttpClients(httpx.MockTransport(world))) == {"skipped": "loopt al"}
    row = await db.get(AppState, nood.STATE_KEY, populate_existing=True)
    row.value = {**row.value, "running": {"at": (now - timedelta(minutes=10)).isoformat(), "by": "worker", "pid": 1}}
    await db.commit()
    assert not (await authed.get("/api/noodplan")).json()["running"]
    assert (await authed.post("/api/noodplan/run")).status_code == 202
    await router._task

    # Het document: als bijlage, niet bewaard door de browser, in het auditlog.
    r = await authed.get("/api/noodplan/document")
    assert r.status_code == 200 and r.text.startswith("<!doctype html>") and r.headers["content-type"].startswith("text/html")
    assert re.fullmatch(r'attachment; filename="noodplan-\d{4}-\d\d-\d\d\.html"', r.headers["content-disposition"])
    assert r.headers["cache-control"] == "no-store"
    r = await authed.get("/api/noodplan/document", params={"formaat": "md"})
    assert r.text.startswith("# Noodplan") and r.headers["content-disposition"].endswith('.md"')
    assert r.headers["content-type"].startswith("text/markdown")
    rows = (await db.execute(select(AuditLog).where(AuditLog.action.like("noodplan%")).order_by(AuditLog.id))).scalars().all()
    assert [a.action for a in rows] == ["noodplan_run", "noodplan_run", "noodplan_view", "noodplan_view"]
    assert rows[-1].detail["formaat"] == "md" and rows[-1].detail["masked"] == 0 and rows[-1].detail["kinds"] == []
    assert (await authed.get("/api/noodplan/document", params={"formaat": "pdf"})).status_code == 422

    # Van buitenaf: het document staat uit, de stand en de proef niet.
    r = await authed.get("/api/noodplan/document", headers=CF)
    assert r.status_code == 403 and r.json()["detail"] == "buiten:downloads"
    assert (await authed.get("/api/noodplan", headers=CF)).status_code == 200
    assert (await authed.post("/api/noodplan/proef", headers=CF)).status_code == 200

    # De proef: alle paden die de run vroeg, zonder zelf iets te vragen.
    seen, before = set(world.seen), len(world.seen)
    plan = (await authed.post("/api/noodplan/proef")).json()
    assert len(world.seen) == before and plan["proef"] is True and plan["title"] == "Noodplan bijwerken"
    first = plan["steps"][0]
    assert first["via"] == "proxmox-api" and first["who"] == "API-token homepage@pve!dash"
    assert first["machine"] == "PVE (https://192.168.0.50:8006)"
    assert "GET /api2/json/cluster/resources" in first["call"] and "/nodes/{node}/network" in first["call"]
    assert "(pve50, pve51)" in first["call"] and "(3 keer, één per VM/CT)" in first["call"]
    assert "GET /api2/json/nodes/pve50/storage/pbs-pi/content?content=backup" in first["call"]
    live = plan["steps"][1]
    assert "/agent/network-get-interfaces" in live["call"] and live["when"] and live["on_fail"]
    pbs = next(x for x in plan["steps"] if x["via"] == "pbs-api")
    assert pbs["call"] == "GET /api2/json/config/datastore" and pbs["who"] == "API-token homepage@pbs!dash"
    asked = set()
    for prefix, table in (("pve", nood.PVE_CALLS), ("pbs", nood.PBS_CALLS)):
        for key, path in table.items():
            rx = re.compile("/api2/json" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path.split("?")[0])) + "$")
            if any(rx.match(p) for p in seen):
                asked.add(f"{prefix}:{key}")
    assert {"pve:resources", "pve:storage", "pve:status", "pve:network", "pve:config", "pve:content",
            "pbs:datastores"} <= asked <= set(plan["calls"])
    assert {"pve:lxc_ifs", "pve:agent"} <= set(plan["calls"])
    assert [s["what"] for s in plan["skipped"]] == ["DNS opzoeken", f"noodplan.html en noodplan.md naar {tmp_path / 'offsite'}"]
    checks = {c["what"]: c for c in plan["checks"]}
    assert checks["Back-updekking"]["ok"] is True and checks["Er loopt geen ander noodplan"]["ok"] is True
    assert checks[f"Map {tmp_path / 'offsite'}"]["ok"] is None
    assert plan["after"][0].startswith("Het noodplan in het dashboard wordt vervangen (nu: van ")
    dumped = json.dumps(plan)
    assert not any(x in dumped for x in SECRETS)

    # Herbevestiging verlopen: het document vraagt opnieuw 2FA, de stand niet.
    await _stale(authed)
    r = await authed.get("/api/noodplan/document")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.get("/api/noodplan")).status_code == 200
    await agen.aclose()


async def test_proef_zonder_tegels(authed, monkeypatch, tmp_path):
    s = get_settings()
    monkeypatch.setattr(s, "offsite_dir", tmp_path)
    agen, db = await _db()
    (await ensure_state(db, "health_settings", {})).value = {"offsite": True}
    await db.commit()
    plan = (await authed.post("/api/noodplan/proef")).json()
    assert plan["warnings"] == ["Geen Proxmox-tegel: het noodplan bevat dan alleen het dashboard zelf."]
    checks = {c["what"]: c for c in plan["checks"]}
    assert checks[f"Map {tmp_path}"] == {"what": f"Map {tmp_path}", "ok": True, "detail": "bestaat en is beschrijfbaar"}
    assert checks["Back-updekking"]["ok"] is None and plan["calls"] == []
    assert plan["steps"][-1]["call"].startswith(f"schrijft noodplan.html en noodplan.md naar {tmp_path}")
    assert plan["after"][0] == "Het eerste noodplan komt in het dashboard."
    await agen.aclose()


async def test_worker(authed, monkeypatch, tmp_path):
    from app.monitoring.worker import Worker
    await _setup(authed, monkeypatch, tmp_path)
    w = Worker(_maker())
    w.http = HttpClients(httpx.MockTransport(World()))
    # Net gestart: eerst de andere taken (dekking, cluster, apparaten, routes).
    await w.noodplan_job()
    agen, db = await _db()
    assert await db.get(AppState, nood.STATE_KEY) is None
    w.started -= nood.START_DELAY
    await w.noodplan_job()
    v = await _plan(db)
    assert v["trigger"] == "week" and v["by"] is None and v["at"]
    # Deze week is er al een: niet opnieuw.
    at = v["at"]
    await w.noodplan_job()
    assert (await _plan(db))["at"] == at
    ev = (await db.execute(select(Event).where(Event.title == "Noodplan bijgewerkt"))).scalars().all()
    assert len(ev) == 1 and "op vraag van" not in ev[0].body
    await agen.aclose()


async def test_aandacht_en_checklist(authed, monkeypatch, tmp_path):
    from app import attention, setupcheck
    _, pbs = await _setup(authed, monkeypatch, tmp_path)
    agen, db = await _db()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    async def items():
        return [i for i in (await attention.collect(db))["items"] if i["key"] == "noodplan"]

    # Nog nooit gemaakt: alleen de checklist.
    assert await items() == []
    row = await setupcheck.noodplan_row(db)
    assert row["state"] == "none" and row["fix"] == {"window": "noodplan"} and row["group"] == "proxmox"
    await agen.aclose()

    # Gemaakt, maar de kopie buiten de container staat uit.
    assert (await _run(World(), now - timedelta(days=16)))["ok"]
    agen, db = await _db()
    row = await setupcheck.noodplan_row(db)
    assert row["state"] == "half" and row["fix"] == {"window": "health", "tab": "homepage"}
    assert "alleen in het dashboard" in row["text"]
    # 16 dagen oud: een punt in Aandacht.
    [it] = await items()
    assert it["level"] == "warn" and it["area"] == "back-ups" and it["fix"] == {"window": "noodplan"}
    assert "16 dagen geleden" in it["text"] and it["text"].endswith("Infrastructuur → Noodplan → nu bijwerken.")

    # De kopie aan, de map bestaat, maar de PBS geeft deze week geen antwoord: half, maar geen punt (één week).
    (await ensure_state(db, "health_settings", {})).value = {"offsite": True}
    await db.commit()
    (tmp_path / "offsite").mkdir()
    world = World()
    assert (await _run(world, now - timedelta(days=1)))["ok"]
    world.broken_pbs = True
    assert (await _run(world, now))["ok"]
    row = await setupcheck.noodplan_row(db)
    assert row["state"] == "half" and row["text"].endswith("maar onvolledig.") and "PBS pi" in row["todo"][0]
    assert await items() == []

    # Alles in orde.
    assert (await _run(World(), now + timedelta(minutes=1)))["ok"]
    row = await setupcheck.noodplan_row(db)
    assert row["state"] == "ok" and row["text"].endswith(f"kopie in {tmp_path / 'offsite'}.")
    assert await items() == []
    # De checklist zelf heeft de rij, na de hersteltest.
    done = await setupcheck.run(db, HttpClients(httpx.MockTransport(World())), {})
    keys = [r["key"] for g in done["groups"] for r in g["rows"]]
    assert keys.index("noodplan") == keys.index("restoretest") + 1
    await agen.aclose()
