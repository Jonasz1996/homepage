import re

from app.monitoring import noodplan_doc as doc


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
