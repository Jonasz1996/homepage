import re
from datetime import datetime, timedelta

from app.monitoring import noodplan as nood, noodplan_doc as doc


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
