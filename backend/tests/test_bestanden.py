"""Bestanden naast de terminal (zoals WinSCP): bladeren, uploaden in stukken, downloaden (ook als zip), bewerken, en
van buitenaf dicht zoals de terminal. Tegen een echte SFTP-server van asyncssh met een eigen map als /."""

import asyncio
import io
import os
import stat
import time
import zipfile
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app import bestanden
from app.main import app
from app.models import AuditLog, Session, SshHost

from .conftest import PASSWORD, H
from .test_beveiliging import _reauth
from .test_ssh import Server, _db

CF = {"X-Homepage-Via-Cf": "1"}


@pytest.fixture(autouse=True)
async def _schoon():
    yield
    await bestanden.close_all()


@pytest.fixture
async def sftpd(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[host_key],
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(root)))
    port = server.sockets[0].getsockname()[1]
    yield {"port": port, "host_key": host_key, "root": root, "server": server}
    # Eerst de vensters dicht: sinds Python 3.12 wacht wait_closed() tot elke verbinding weg is. Blijft er toch een
    # open (een fout in het sluiten), dan faalt de test, in plaats van dat alles blijft hangen.
    await bestanden.close_all()
    server.close()
    await asyncio.wait_for(server.wait_closed(), 10)


async def _host(authed, port: int, password: str = "goed") -> int:
    r = await authed.post("/api/ssh/hosts", json={"name": "pve", "host": "127.0.0.1", "port": port,
                                                  "username": "root", "password": password})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _open(authed, sftpd) -> tuple[int, str]:
    hid = await _host(authed, sftpd["port"])
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert r.status_code == 200 and r.json()["hostkey"]["fp"] == sftpd["host_key"].get_fingerprint("sha256"), r.text
    assert (await authed.post(f"/api/ssh/hosts/{hid}/files/hostkey",
                              json={"fp": r.json()["hostkey"]["fp"]})).status_code == 200
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert r.status_code == 200 and r.json()["id"], r.text
    return hid, r.json()["id"]


async def _actions() -> list[AuditLog]:
    db = await _db()
    return list((await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars())


async def _list(authed, fs: str, path: str = "/") -> dict:
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": path})
    assert r.status_code == 200, r.text
    return r.json()


def _names(listing: dict) -> dict[str, dict]:
    return {e["name"]: e for e in listing["entries"]}


async def _upload(authed, fs: str, dir_: str, name: str, data: bytes, overwrite: bool = False,
                  mtime: float | None = None, order=None) -> dict:
    body = {"dir": dir_, "name": name, "size": len(data), "overwrite": overwrite, "mtime": mtime}
    r = await authed.post(f"/api/ssh/files/{fs}/upload", json=body)
    assert r.status_code == 200, r.text
    up = r.json()
    if "exists" in up:
        return up
    chunk = up["chunk"]
    for i in order if order is not None else range(up["chunks"]):
        r = await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/{i}", content=data[i * chunk:(i + 1) * chunk])
        assert r.status_code == 200, r.text
    r = await authed.post(f"/api/ssh/files/{fs}/upload/{up['id']}/finish")
    assert r.status_code == 200, r.text
    return r.json()


def _parts(root) -> list[str]:
    return [p.name for p in root.rglob("*") if bestanden.PART.match(p.name)]


# --- Openen -----------------------------------------------------------------------------------------------------

async def test_eerst_hostsleutel_dan_openen_en_audit(authed, sftpd):
    hid = await _host(authed, sftpd["port"])
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert "id" not in r.json() and r.json()["hostkey"]["alg"] == "ssh-ed25519"
    # Een andere vingerafdruk dan de server nu toont: niets bewaard.
    r = await authed.post(f"/api/ssh/hosts/{hid}/files/hostkey", json={"fp": "SHA256:nep"})
    assert r.status_code == 409, r.text
    assert (await authed.get("/api/ssh/hosts")).json()[0]["host_key_fingerprint"] is None
    fp = sftpd["host_key"].get_fingerprint("sha256")
    assert (await authed.post(f"/api/ssh/hosts/{hid}/files/hostkey", json={"fp": fp})).status_code == 200
    assert (await authed.get("/api/ssh/hosts")).json()[0]["host_key_fingerprint"] == fp
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    o = r.json()
    assert o["home"] == "/" and o["user"] == "root" and o["name"] == "pve" and o["chunk"] == bestanden.CHUNK
    acts = await _actions()
    assert [a.detail.get("via") for a in acts if a.action == "ssh_hostkey_accepted"] == ["bestanden"]
    assert [a.detail["name"] for a in acts if a.action == "sftp_open"] == ["pve"]


async def test_openen_vraagt_verse_2fa_daarna_niet(authed, sftpd):
    hid = await _host(authed, sftpd["port"])
    db = await _db()
    await db.execute(update(SshHost).values(host_key=sftpd["host_key"].export_public_key().decode()))
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.post(f"/api/ssh/hosts/{hid}/files/hostkey", json={"fp": "x"})).status_code == 403
    await _reauth(authed)
    fs = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    # Zoals een open terminal: het venster blijft werken zonder nieuwe code.
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    assert (await _list(authed, fs))["path"] == "/"
    (sftpd["root"] / "a.txt").write_text("x")
    assert (await authed.post(f"/api/ssh/files/{fs}/read", json={"path": "/a.txt"})).status_code == 200


async def test_verkeerd_wachtwoord_en_geen_sftp(authed, sftpd):
    hid = await _host(authed, sftpd["port"], password="fout")
    db = await _db()
    await db.execute(update(SshHost).values(host_key=sftpd["host_key"].export_public_key().decode()))
    await db.commit()
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert r.status_code == 502 and "geweigerd" in r.json()["detail"], r.text
    # Een server zonder SFTP-subsysteem.
    hk = asyncssh.generate_private_key("ssh-ed25519")
    plain = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[hk])
    try:
        port = plain.sockets[0].getsockname()[1]
        hid2 = await _host(authed, port)
        await db.execute(update(SshHost).where(SshHost.id == hid2).values(host_key=hk.export_public_key().decode()))
        await db.commit()
        r = await authed.post(f"/api/ssh/hosts/{hid2}/files")
        assert r.status_code == 502 and "Subsystem sftp" in r.json()["detail"], r.text
    finally:
        plain.close()


async def test_veranderde_hostsleutel_geweigerd(authed, sftpd):
    hid = await _host(authed, sftpd["port"])
    db = await _db()
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    await db.execute(update(SshHost).values(host_key=other))
    await db.commit()
    r = await authed.post(f"/api/ssh/hosts/{hid}/files")
    assert r.status_code == 502 and "veranderd" in r.json()["detail"]
    assert "ssh_hostkey_mismatch" in [a.action for a in await _actions()]


# --- Bladeren ---------------------------------------------------------------------------------------------------

async def test_map_bekijken(authed, sftpd):
    root = sftpd["root"]
    (root / "etc").mkdir()
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (root / ".verborgen").write_text("")
    (root / "groot.bin").write_bytes(b"\0" * 5000)
    os.chmod(root / "groot.bin", 0o640)
    # Absoluut: de testserver van asyncssh leest een relatief doel tegenover zijn eigen werkmap (OpenSSH niet).
    os.symlink(root / "etc", root / "naar-etc")
    os.symlink("bestaat-niet", root / "kapot")
    os.symlink("etc/hosts", root / "naar-hosts")
    _, fs = await _open(authed, sftpd)
    lst = await _list(authed, fs, "/")
    e = _names(lst)
    assert set(e) == {"etc", ".verborgen", "groot.bin", "naar-etc", "kapot", "naar-hosts"}
    assert e["etc"]["type"] == "dir" and e["groot.bin"]["type"] == "file" and e["groot.bin"]["size"] == 5000
    assert e["groot.bin"]["mode"] == 0o640 and e["groot.bin"]["perms"] == "-rw-r-----"
    assert e["naar-etc"]["type"] == "link" and e["naar-etc"]["to"] == "dir" and e["naar-etc"]["target"] == "/etc"
    assert e["naar-hosts"]["to"] == "file" and e["kapot"]["broken"] is True
    assert e["groot.bin"]["mtime"] == int(os.stat(root / "groot.bin").st_mtime)
    assert lst["free"] and lst["count"] == 6 and not lst["truncated"]
    # Dubbele en afsluitende slashes; via een symlink naar het echte pad.
    assert (await _list(authed, fs, "//naar-etc/"))["path"] == "/etc"
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/bestaat-niet"})
    assert r.status_code == 404 and "bestaat niet" in r.json()["detail"]
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "etc"})
    assert r.status_code == 422


async def test_rare_namen_en_veel_bestanden(authed, sftpd, monkeypatch):
    root = sftpd["root"]
    os.mkdir(bytes(root) + b"/caf\xe9")  # Latin-1, geen UTF-8
    (root / "één.txt").write_text("x")
    monkeypatch.setattr(bestanden, "LIST_MAX", 1)
    _, fs = await _open(authed, sftpd)
    lst = await _list(authed, fs)
    # Niet verder gelezen dan nodig (een map met miljoenen bestanden).
    assert lst["truncated"] and len(lst["entries"]) == 1
    monkeypatch.setattr(bestanden, "LIST_MAX", 100)
    e = _names(await _list(authed, fs))
    assert e["één.txt"]["odd"] is False
    assert e["caf�"]["odd"] is True and e["caf�"]["type"] == "dir"


# --- Mappen, hernoemen, verwijderen, rechten ---------------------------------------------------------------------

async def test_map_maken_hernoemen_verwijderen_rechten(authed, sftpd):
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    post = lambda p, **b: authed.post(f"/api/ssh/files/{fs}/{p}", json=b)  # noqa: E731
    assert (await post("mkdir", path="/nieuw")).status_code == 200
    r = await post("mkdir", path="/nieuw")
    assert r.status_code == 409 and "bestaat al" in r.json()["detail"]
    assert (await post("mkdir", path="/a/b/c", parents=True)).status_code == 200 and (root / "a/b/c").is_dir()
    (root / "x.txt").write_text("x")
    (root / "y.txt").write_text("y")
    r = await post("rename", path="/x.txt", to="/y.txt")
    assert r.status_code == 409 and (root / "x.txt").exists()
    assert (await post("rename", path="/x.txt", to="/y.txt", overwrite=True)).status_code == 200
    assert (root / "y.txt").read_text() == "x" and not (root / "x.txt").exists()
    assert (await post("rename", path="/y.txt", to="/a/b/z.txt")).status_code == 200
    assert (root / "a/b/z.txt").exists()
    assert (await post("rename", path="/", to="/x")).status_code == 400
    assert (await post("chmod", path="/a/b/z.txt", mode="600")).status_code == 200
    assert stat.S_IMODE(os.stat(root / "a/b/z.txt").st_mode) == 0o600
    assert (await post("chmod", path="/a/b/z.txt", mode="999")).status_code == 422
    # Een map met inhoud alleen met recursive; / nooit.
    r = await post("delete", paths=["/a"])
    assert r.status_code == 409 and "met inhoud" in r.json()["detail"] and (root / "a").exists()
    assert (await post("delete", paths=["/nieuw"])).json() == {"deleted": 1}
    assert (await post("delete", paths=["/a"], recursive=True)).json() == {"deleted": 1}
    assert not (root / "a").exists()
    for p in ("/", "//", "/.", "/a/.."):
        r = await post("delete", paths=[p], recursive=True)
        assert r.status_code in (400, 404), (p, r.text)
    assert root.exists()
    os.symlink("/", root / "wortel")
    assert (await post("delete", paths=["/wortel"], recursive=True)).json() == {"deleted": 1}
    assert root.exists() and not os.path.lexists(root / "wortel")
    acts = [a.action for a in await _actions()]
    for a in ("sftp_mkdir", "sftp_rename", "sftp_chmod", "sftp_delete"):
        assert a in acts


# --- Bewerken ---------------------------------------------------------------------------------------------------

async def test_bewerken(authed, sftpd):
    root = sftpd["root"]
    (root / "conf").write_bytes(b"a = 1\r\nb = 2\r\n")
    os.chmod(root / "conf", 0o600)
    _, fs = await _open(authed, sftpd)
    post = lambda p, **b: authed.post(f"/api/ssh/files/{fs}/{p}", json=b)  # noqa: E731
    r = (await post("read", path="/conf")).json()
    assert r["text"] == "a = 1\nb = 2\n" and r["eol"] == "crlf" and r["mode"] == 0o600
    w = await post("write", path="/conf", text="a = 3\nb = 2\n", eol="crlf", mtime=r["mtime"], size=r["size"])
    assert w.status_code == 200, w.text
    assert (root / "conf").read_bytes() == b"a = 3\r\nb = 2\r\n"
    assert stat.S_IMODE(os.stat(root / "conf").st_mode) == 0o600
    # Intussen gewijzigd: eerst weigeren, met force toch.
    (root / "conf").write_text("ander\n")
    w2 = await post("write", path="/conf", text="mijn\n", mtime=w.json()["mtime"], size=w.json()["size"])
    assert w2.status_code == 409 and "intussen gewijzigd" in w2.json()["detail"]
    assert (await post("write", path="/conf", text="mijn\n", mtime=0, size=0, force=True)).status_code == 200
    assert (root / "conf").read_text() == "mijn\n"
    # Nieuw bestand: nooit over een bestaand.
    assert (await post("write", path="/nieuw.txt", text="")).status_code == 200 and (root / "nieuw.txt").exists()
    assert (await post("write", path="/conf", text="weg")).status_code == 409
    assert (root / "conf").read_text() == "mijn\n"
    # Via een symlink: het doel wordt bewerkt, de link blijft.
    os.symlink("conf", root / "link")
    r = (await post("read", path="/link")).json()
    assert (await post("write", path="/link", text="via link\n", mtime=r["mtime"], size=r["size"])).status_code == 200
    assert os.path.islink(root / "link") and (root / "conf").read_text() == "via link\n"
    (root / "bin").write_bytes(b"\x7fELF\0\0")
    assert (await post("read", path="/bin")).status_code == 415
    (root / "latin").write_bytes(b"caf\xe9")
    assert (await post("read", path="/latin")).status_code == 415
    (root / "groot").write_bytes(b"x" * (bestanden.EDIT_MAX + 1))
    assert (await post("read", path="/groot")).status_code == 413
    assert (await post("read", path="/")).status_code == 400
    assert _parts(root) == []
    acts = [a.action for a in await _actions()]
    assert acts.count("sftp_edit") == 4 and "sftp_read" in acts


# --- Uploaden ---------------------------------------------------------------------------------------------------

async def test_uploaden_in_stukken(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 10)
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    data = bytes(range(256)) * 2
    mtime = time.time() - 86400 * 3
    e = await _upload(authed, fs, "/", "data.bin", data, mtime=mtime, order=reversed(range(-(-len(data) // 10))))
    assert (root / "data.bin").read_bytes() == data and e["name"] == "data.bin" and e["size"] == len(data)
    assert int(os.stat(root / "data.bin").st_mtime) == int(mtime)
    # Bestaat al: eerst vragen, dan overschrijven met de rechten van het oude.
    os.chmod(root / "data.bin", 0o751)
    assert (await _upload(authed, fs, "/", "data.bin", b"nieuw"))["exists"]["size"] == len(data)
    assert (root / "data.bin").read_bytes() == data
    await _upload(authed, fs, "/", "data.bin", b"nieuw", overwrite=True)
    assert (root / "data.bin").read_bytes() == b"nieuw" and stat.S_IMODE(os.stat(root / "data.bin").st_mode) == 0o751
    # Een map uploaden: tussenliggende mappen worden gemaakt. Een leeg bestand gaat ook.
    await _upload(authed, fs, "/", "foto's/2024/a.jpg", b"jpg")
    await _upload(authed, fs, "/", "leeg", b"")
    assert (root / "foto's/2024/a.jpg").read_bytes() == b"jpg" and (root / "leeg").read_bytes() == b""
    assert _parts(root) == []
    assert [a.detail["path"] for a in await _actions() if a.action == "sftp_upload"] == [
        "/data.bin", "/data.bin", "/foto's/2024/a.jpg", "/leeg"]


async def test_upload_fouten_en_afbreken(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 4)
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    start = lambda **b: authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/", "size": 10, **b})  # noqa: E731
    for bad in ("../x", "a/../b", "/abs", "a//b", "", ".", "a/"):
        assert (await start(name=bad)).status_code == 422, bad
    up = (await start(name="x.bin")).json()
    assert up["chunks"] == 3
    put = lambda i, b: authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/{i}", content=b)  # noqa: E731
    assert (await put(0, b"abc")).status_code == 400  # te kort
    assert (await put(3, b"ab")).status_code == 400  # bestaat niet
    assert (await put(2, b"abc")).status_code == 400  # het laatste stuk is 2 bytes
    assert (await put(0, b"abcd")).status_code == 200
    assert (await put(0, b"abcd")).status_code == 200  # opnieuw sturen mag
    r = await authed.post(f"/api/ssh/files/{fs}/upload/{up['id']}/finish")
    assert r.status_code == 409 and "1 van 3" in r.json()["detail"]
    assert len(_parts(root)) == 1 and not (root / "x.bin").exists()
    assert (await authed.delete(f"/api/ssh/files/{fs}/upload/{up['id']}")).status_code == 200
    assert _parts(root) == [] and not (root / "x.bin").exists()
    assert (await put(1, b"efgh")).status_code == 410
    # Een map met dezelfde naam.
    (root / "map").mkdir()
    r = await start(name="map", overwrite=True)
    assert r.status_code == 409
    # Te groot voor de schijf.
    r = await authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/", "name": "y", "size": 1 << 50})
    assert r.status_code == 507 and "Niet genoeg plaats" in r.json()["detail"]
    # Doelmap bestaat niet.
    r = await authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/nergens", "name": "y", "size": 1})
    assert r.status_code == 404


async def test_upload_naar_symlink_en_stille_upload_opgeruimd(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 4)
    root = sftpd["root"]
    (root / "echt").write_text("oud")
    os.symlink("echt", root / "link")
    _, fs = await _open(authed, sftpd)
    await _upload(authed, fs, "/", "link", b"nieuw!", overwrite=True)
    assert os.path.islink(root / "link") and (root / "echt").read_text() == "nieuw!"
    up = (await authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/", "name": "z", "size": 8})).json()
    assert len(_parts(root)) == 1
    bestanden.SESSIONS[fs].uploads[up["id"]].used -= bestanden.UPLOAD_IDLE + 1
    await bestanden.sweep()
    assert _parts(root) == [] and up["id"] not in bestanden.SESSIONS[fs].uploads


async def test_upload_overleeft_een_nieuwe_verbinding(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 4)
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    up = (await authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/", "name": "z", "size": 8})).json()
    assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/0", content=b"1234")).status_code == 200
    bestanden._drop_conn(bestanden.SESSIONS[fs])
    assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/1", content=b"5678")).status_code == 200
    assert (await authed.post(f"/api/ssh/files/{fs}/upload/{up['id']}/finish")).status_code == 200
    assert (root / "z").read_bytes() == b"12345678"


# --- Downloaden -------------------------------------------------------------------------------------------------

async def test_bestand_downloaden(authed, sftpd):
    root = sftpd["root"]
    data = os.urandom(3 * 1024 * 1024 + 17)
    (root / "rapport é.pdf").write_bytes(data)
    _, fs = await _open(authed, sftpd)
    r = await authed.post(f"/api/ssh/files/{fs}/download", json={"dir": "/", "names": ["rapport é.pdf"]})
    assert r.status_code == 200 and r.json()["zip"] is False and r.json()["name"] == "rapport é.pdf", r.text
    url = r.json()["url"]
    # Een gewone link (zonder de header van de frontend), vanaf hetzelfde IP.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as plain:
        d = await plain.get(url)
    assert d.status_code == 200 and d.content == data
    assert d.headers["content-length"] == str(len(data)) and d.headers["cache-control"] == "no-store"
    assert d.headers["content-disposition"] == ("attachment; filename=\"rapport _.pdf\"; "
                                                "filename*=UTF-8''rapport%20%C3%A9.pdf")
    # Maar één keer.
    assert (await authed.get(url)).status_code == 404
    # Niet vanaf een ander IP, en niet na 60 seconden.
    want = {"dir": "/", "names": ["rapport é.pdf"]}
    url = (await authed.post(f"/api/ssh/files/{fs}/download", json=want)).json()["url"]
    async with AsyncClient(transport=ASGITransport(app=app, client=("192.168.1.77", 1)), base_url="http://test") as o:
        assert (await o.get(url)).status_code == 404
    url = (await authed.post(f"/api/ssh/files/{fs}/download", json=want)).json()["url"]
    bestanden.DOWNLOADS[url.rsplit("/", 1)[1]].expires = time.monotonic() - 1
    assert (await authed.get(url)).status_code == 404
    r = await authed.post(f"/api/ssh/files/{fs}/download", json={"dir": "/", "names": ["weg"]})
    assert r.status_code == 404
    assert [a.detail["names"] for a in await _actions() if a.action == "sftp_download"] == [["rapport é.pdf"]] * 3


async def test_map_als_zip(authed, sftpd):
    root = sftpd["root"]
    (root / "site/css").mkdir(parents=True)
    (root / "site/index.html").write_text("<h1>hoi</h1>")
    (root / "site/css/a.css").write_text("body{}" * 1000)
    (root / "site/leeg").mkdir()
    os.symlink("..", root / "site/lus")
    os.symlink("index.html", root / "site/kopie.html")
    os.mkfifo(root / "site/fifo")
    (root / "los.txt").write_text("los")
    _, fs = await _open(authed, sftpd)
    r = await authed.post(f"/api/ssh/files/{fs}/download", json={"dir": "/", "names": ["site"]})
    assert r.json()["zip"] is True and r.json()["name"] == "site.zip"
    d = await authed.get(r.json()["url"])
    assert d.status_code == 200 and d.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(d.content))
    assert z.testzip() is None
    names = set(z.namelist())
    assert {"site/", "site/index.html", "site/css/", "site/css/a.css", "site/leeg/", "site/kopie.html",
            "NIET-MEEGENOMEN.txt"} == names
    assert z.read("site/css/a.css") == b"body{}" * 1000 and z.read("site/kopie.html") == b"<h1>hoi</h1>"
    skipped = z.read("NIET-MEEGENOMEN.txt").decode()
    assert "site/lus  (symlink naar een map)" in skipped and "site/fifo  (geen gewoon bestand)" in skipped
    # Meerdere: één zip met de naam van de map.
    r = await authed.post(f"/api/ssh/files/{fs}/download", json={"dir": "/site", "names": ["index.html", "css"]})
    assert r.json()["name"] == "site.zip"
    z = zipfile.ZipFile(io.BytesIO((await authed.get(r.json()["url"])).content))
    assert set(z.namelist()) == {"index.html", "css/", "css/a.css"}


# --- Toegang ----------------------------------------------------------------------------------------------------

async def test_van_buitenaf_dicht(authed, sftpd):
    (sftpd["root"] / "a").write_text("a")
    hid, fs = await _open(authed, sftpd)
    url = (await authed.post(f"/api/ssh/files/{fs}/download", json={"dir": "/", "names": ["a"]})).json()["url"]
    for method, path, body in (("post", f"/api/ssh/hosts/{hid}/files", None),
                               ("post", f"/api/ssh/hosts/{hid}/files/hostkey", {"fp": "x"}),
                               ("post", f"/api/ssh/files/{fs}/list", {"path": "/"}),
                               ("post", f"/api/ssh/files/{fs}/read", {"path": "/a"}),
                               ("post", f"/api/ssh/files/{fs}/download", {"dir": "/", "names": ["a"]}),
                               ("post", f"/api/ssh/files/{fs}/upload", {"dir": "/", "name": "b", "size": 1}),
                               ("get", url, None)):
        r = await getattr(authed, method)(path, headers=CF, **({"json": body} if body is not None else {}))
        assert r.status_code == 403 and r.json()["detail"] == "buiten:terminal", (path, r.text)


async def test_venster_hoort_bij_de_sessie(authed, sftpd):
    hid, fs = await _open(authed, sftpd)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=H) as anon:
        assert (await anon.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})).status_code == 401
    # Een andere sessie van dezelfde gebruiker kent dit venster niet.
    s = bestanden.SESSIONS[fs]
    s.sess_id = "een-andere-sessie"
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})
    assert r.status_code == 410
    assert (await authed.post("/api/ssh/files/bestaat-niet/list", json={"path": "/"})).status_code == 410


async def test_sluiten_stilte_en_gewijzigde_host(authed, sftpd):
    hid, fs = await _open(authed, sftpd)
    assert (await authed.post(f"/api/ssh/files/{fs}/close")).status_code == 200
    assert fs not in bestanden.SESSIONS
    assert (await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})).status_code == 410
    fs = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    s = bestanden.SESSIONS[fs]
    # Na 5 minuten stilte gaat de verbinding dicht, het venster niet; het volgende verzoek verbindt opnieuw.
    s.conn_used -= bestanden.CONN_IDLE + 1
    await bestanden.sweep()
    assert s.conn is None and fs in bestanden.SESSIONS
    assert (await _list(authed, fs))["path"] == "/" and s.conn is not None
    # Een verbroken verbinding: ook opnieuw.
    s.conn.close()
    await asyncio.sleep(0.05)
    assert (await _list(authed, fs))["path"] == "/"
    # Na 30 minuten: dicht.
    s.used -= bestanden.IDLE + 1
    await bestanden.sweep()
    assert fs not in bestanden.SESSIONS
    # De host krijgt een ander adres (✎): bij de volgende verbinding opnieuw openen.
    fs = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    moved = {"name": "pve", "host": "127.0.0.2", "port": sftpd["port"], "username": "root"}
    r = await authed.patch(f"/api/ssh/hosts/{hid}", json=moved)
    assert r.status_code == 200, r.text
    bestanden._drop_conn(bestanden.SESSIONS[fs])
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})
    assert r.status_code == 412 and "gewijzigd" in r.json()["detail"]


async def test_hoogstens_twintig_vensters(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "MAX_PER_USER", 2)
    hid, first = await _open(authed, sftpd)
    second = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    third = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    assert first not in bestanden.SESSIONS and {second, third} <= set(bestanden.SESSIONS)


# --- Randgevallen uit de review ---------------------------------------------------------------------------------

async def test_map_verwijderen_met_backslash_en_halve_mislukking_in_auditlog(authed, sftpd, monkeypatch):
    root = sftpd["root"]
    (root / "units/sub/diep").mkdir(parents=True)
    for i in range(40):
        (root / "units" / f"f{i}").write_text("x")
    # Een systemd-unit: sftp.rmtree van asyncssh weigert een naam met een backslash.
    (root / "units" / "mnt-data\\x2d1.mount").write_text("x")
    os.mkdir(bytes(root) + b"/units/caf\xe9")
    _, fs = await _open(authed, sftpd)
    post = lambda p, **b: authed.post(f"/api/ssh/files/{fs}/{p}", json=b)  # noqa: E731
    r = await post("delete", paths=["/units"], recursive=True)
    assert r.status_code == 200, r.text
    assert not (root / "units").exists()
    # Een map die niet weg mag: wat al weg is, staat in het auditlog.
    (root / "oud/vast").mkdir(parents=True)
    for i in range(5):
        (root / "oud/vast" / f"g{i}").write_text("x")
    orig = asyncssh.SFTPServer.rmdir

    def rmdir(self, path):
        if path.endswith(b"/vast"):
            raise asyncssh.SFTPPermissionDenied("nee")
        return orig(self, path)

    monkeypatch.setattr(asyncssh.SFTPServer, "rmdir", rmdir)
    r = await post("delete", paths=["/oud"], recursive=True)
    assert r.status_code == 403, r.text
    assert (root / "oud/vast").is_dir() and not list((root / "oud/vast").iterdir())
    acts = [a.detail for a in await _actions() if a.action == "sftp_delete"]
    # 41 bestanden, 4 mappen (caf\xe9, diep, sub, units); daarna 5 bestanden en dan de fout.
    assert acts[0]["items"] == 45 and acts[0]["count"] == 1 and "failed" not in acts[0]
    assert acts[1]["items"] == 5 and acts[1]["count"] == 0 and acts[1]["failed"] == "/oud"
    assert "Geen toegang" in acts[1]["error"]


async def test_tijdelijk_bestand_van_een_geheim_bestand_is_niet_leesbaar(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 4)
    root = sftpd["root"]
    (root / "geheim").write_text("oud")
    os.chmod(root / "geheim", 0o600)
    _, fs = await _open(authed, sftpd)
    body = {"dir": "/", "name": "geheim", "size": 8, "overwrite": True}
    up = (await authed.post(f"/api/ssh/files/{fs}/upload", json=body)).json()
    assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/0", content=b"PASS")).status_code == 200
    part = next(p for p in root.iterdir() if bestanden.PART.match(p.name))
    assert stat.S_IMODE(os.stat(part).st_mode) == 0o600
    assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/1", content=b"WORD")).status_code == 200
    assert (await authed.post(f"/api/ssh/files/{fs}/upload/{up['id']}/finish")).status_code == 200
    assert (root / "geheim").read_bytes() == b"PASSWORD" and stat.S_IMODE(os.stat(root / "geheim").st_mode) == 0o600
    # Een nieuw bestand krijgt gewoon de standaardrechten van de host.
    mask = os.umask(0)
    os.umask(mask)
    await _upload(authed, fs, "/", "nieuw", b"x")
    assert stat.S_IMODE(os.stat(root / "nieuw").st_mode) == 0o666 & ~mask


async def test_bewerken_houdt_setuid_en_gemengde_regeleindes(authed, sftpd):
    root = sftpd["root"]
    (root / "helper").write_text("#!/bin/sh\n")
    os.chmod(root / "helper", 0o4755)
    (root / "script").write_bytes(b"#!/bin/sh\necho a\necho b\r\n")
    (root / "win").write_bytes(b"a\r\nb\r\nc\n")
    _, fs = await _open(authed, sftpd)
    post = lambda p, **b: authed.post(f"/api/ssh/files/{fs}/{p}", json=b)  # noqa: E731
    r = (await post("read", path="/helper")).json()
    assert (await post("write", path="/helper", text="#!/bin/sh\nexit 0\n", mtime=r["mtime"],
                       size=r["size"])).status_code == 200
    assert stat.S_IMODE(os.stat(root / "helper").st_mode) == 0o4755
    # Eén verdwaalde CRLF maakt van een Linux-script geen Windows-bestand.
    r = (await post("read", path="/script")).json()
    assert r["eol"] == "lf" and r["mixed"] is True
    assert (await post("write", path="/script", text=r["text"], eol=r["eol"], mtime=r["mtime"],
                       size=r["size"])).status_code == 200
    assert (root / "script").read_bytes() == b"#!/bin/sh\necho a\necho b\n"
    r = (await post("read", path="/win")).json()
    assert r["eol"] == "crlf" and r["mixed"] is True
    r = (await post("read", path="/helper")).json()
    assert r["eol"] == "lf" and r["mixed"] is False


async def _andere_hostsleutel(sftpd):
    """De server op dezelfde poort, nu met een andere hostsleutel (herinstalleerd, of iemand ertussen)."""
    sftpd["server"].close()
    await asyncio.wait_for(sftpd["server"].wait_closed(), 10)
    return await asyncssh.create_server(
        Server, "127.0.0.1", sftpd["port"], server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(sftpd["root"])))


async def test_andere_hostsleutel_bij_opnieuw_verbinden(authed, sftpd):
    hid, fs = await _open(authed, sftpd)
    bestanden._drop_conn(bestanden.SESSIONS[fs])
    other = await _andere_hostsleutel(sftpd)
    try:
        r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})
        assert r.status_code == 412 and "veranderd" in r.json()["detail"], r.text
        assert fs not in bestanden.SESSIONS
        # Ook daarna: niet "verlopen" (waarop de frontend stil opnieuw zou openen), dezelfde uitleg.
        r = await authed.post(f"/api/ssh/files/{fs}/read", json={"path": "/a"})
        assert r.status_code == 412 and "veranderd" in r.json()["detail"], r.text
        acts = [a for a in await _actions() if a.action == "ssh_hostkey_mismatch"]
        assert [a.detail["via"] for a in acts] == ["bestanden"]
    finally:
        await bestanden.close_all()
        other.close()
        await asyncio.wait_for(other.wait_closed(), 10)


async def test_andere_hostsleutel_bij_drie_verzoeken_tegelijk(authed, sftpd, monkeypatch):
    from app.routers import bestanden as route

    hid, fs = await _open(authed, sftpd)
    bestanden._drop_conn(bestanden.SESSIONS[fs])
    other = await _andere_hostsleutel(sftpd)
    real, tries, audited = bestanden._connect, [], []

    async def counted(h, login):
        tries.append(1)
        return await real(h, login)

    real_audit = route.audit

    async def audit(db, request, user, action, **detail):
        audited.append(action)
        await real_audit(db, request, user, action, **detail)

    monkeypatch.setattr(bestanden, "_connect", counted)
    monkeypatch.setattr(route, "audit", audit)
    try:
        # Twee uploads en de lijst tegelijk: één keer aanmelden op de host, één keer in het auditlog.
        rs = await asyncio.gather(*(authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"}) for _ in range(3)))
        assert [r.status_code for r in rs] == [412] * 3 and all("veranderd" in r.json()["detail"] for r in rs)
        assert len(tries) == 1 and audited == ["ssh_hostkey_mismatch"]
    finally:
        await bestanden.close_all()
        other.close()
        await asyncio.wait_for(other.wait_closed(), 10)


async def test_andere_login_bij_opnieuw_verbinden(authed, sftpd):
    hid, fs = await _open(authed, sftpd)
    changed = {"name": "pve", "host": "127.0.0.1", "port": sftpd["port"], "username": "backup"}
    r = await authed.patch(f"/api/ssh/hosts/{hid}", json=changed)
    assert r.status_code == 200, r.text
    # Zolang de verbinding er is, blijft het root; opnieuw verbinden als backup gebeurt niet stil.
    assert (await _list(authed, fs))["path"] == "/"
    s = bestanden.SESSIONS[fs]
    bestanden._drop_conn(s)
    r = await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})
    assert r.status_code == 412 and "root werd backup" in r.json()["detail"], r.text
    # Elk volgend verzoek van dat venster krijgt dezelfde uitleg, ook een upload of een download.
    for p, b in (("delete", {"paths": ["/a"]}), ("download", {"dir": "/", "names": ["a"]})):
        r = await authed.post(f"/api/ssh/files/{fs}/{p}", json=b)
        assert r.status_code == 412 and "root werd backup" in r.json()["detail"], r.text
    # Alleen voor dit venster in deze browsersessie: anders gewoon verlopen.
    s.sess_id = "een-andere-sessie"
    bestanden.CHANGED[fs] = bestanden.CHANGED[fs][:2] + ("een-andere-sessie",) + bestanden.CHANGED[fs][3:]
    assert (await authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"})).status_code == 410


async def test_venster_dicht_terwijl_het_opnieuw_verbindt(authed, sftpd, monkeypatch):
    _, fs = await _open(authed, sftpd)
    s = bestanden.SESSIONS[fs]
    bestanden._drop_conn(s)
    real, made = bestanden._connect, []
    started, go_on = asyncio.Event(), asyncio.Event()

    async def slow(h, login):
        started.set()
        await go_on.wait()
        conn, sftp = await real(h, login)
        made.append(conn)
        return conn, sftp

    monkeypatch.setattr(bestanden, "_connect", slow)
    task = asyncio.create_task(authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"}))
    await asyncio.wait_for(started.wait(), 5)
    # Het tabblad gaat dicht terwijl een trage host nog antwoordt: die verbinding mag niet blijven hangen.
    assert (await authed.post(f"/api/ssh/files/{fs}/close")).status_code == 200
    go_on.set()
    r = await task
    assert r.status_code == 410, r.text
    await asyncio.wait_for(made[0].wait_closed(), 5)
    assert s.conn is None and s.sftp is None


async def test_venster_dicht_terwijl_het_oude_halve_bestanden_opruimt(authed, sftpd, monkeypatch):
    root = sftpd["root"]
    hid, fs = await _open(authed, sftpd)
    for n in ("a", "b"):
        (root / f".{n}.homepage-0000000{n}.part").write_bytes(b"geheim")
    bestanden.LEFTOVER[hid] = {f"/.{n}.homepage-0000000{n}.part" for n in ("a", "b")}
    s = bestanden.SESSIONS[fs]
    bestanden._drop_conn(s)
    real, started, go_on = asyncssh.SFTPClient.remove, asyncio.Event(), asyncio.Event()

    async def slow(self, path):
        started.set()
        await go_on.wait()
        return await real(self, path)

    monkeypatch.setattr(asyncssh.SFTPClient, "remove", slow)
    task = asyncio.create_task(authed.post(f"/api/ssh/files/{fs}/list", json={"path": "/"}))
    await asyncio.wait_for(started.wait(), 5)
    assert (await authed.post(f"/api/ssh/files/{fs}/close")).status_code == 200
    go_on.set()
    r = await task
    assert r.status_code == 410, r.text
    # Niet vergeten: bij de volgende verbinding met die host alsnog.
    assert len(_parts(root)) == 2 and len(bestanden.LEFTOVER[hid]) == 2
    monkeypatch.setattr(asyncssh.SFTPClient, "remove", real)
    assert (await authed.post(f"/api/ssh/hosts/{hid}/files")).status_code == 200
    assert _parts(root) == [] and not bestanden.LEFTOVER


async def test_afmelden_terwijl_een_venster_opent(authed, sftpd, monkeypatch):
    hid, fs = await _open(authed, sftpd)
    await bestanden.close_all()
    real, made = bestanden._connect, []
    started, go_on = asyncio.Event(), asyncio.Event()

    async def slow(h, login):
        started.set()
        await go_on.wait()
        made.append(await real(h, login))
        return made[-1]

    monkeypatch.setattr(bestanden, "_connect", slow)
    task = asyncio.create_task(authed.post(f"/api/ssh/hosts/{hid}/files"))
    await asyncio.wait_for(started.wait(), 5)
    assert (await authed.post("/api/auth/logout")).status_code == 200
    go_on.set()
    r = await task
    assert r.status_code == 410, r.text
    assert not bestanden.SESSIONS and not bestanden.OPENING
    await asyncio.wait_for(made[0][0].wait_closed(), 5)


async def test_wachtwoord_wijzigen_sluit_de_vensters_van_andere_sessies(authed, sftpd):
    hid, fs = await _open(authed, sftpd)
    mine = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    loose = (await authed.post(f"/api/ssh/hosts/{hid}/files")).json()["id"]
    other = bestanden.SESSIONS[fs]
    other.sess_id = "een-andere-sessie"
    bestanden.SESSIONS[loose].sess_id = "zonder-login:jonas"
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "nog-een-lang-wachtwoord"})
    assert r.status_code == 200, r.text
    assert fs not in bestanden.SESSIONS and other.conn is None
    assert {mine, loose} <= set(bestanden.SESSIONS)


async def test_groep_blijft_als_de_login_de_eigenaar_niet_mag_zetten():
    calls = []

    class Fake:
        async def chown(self, path, uid, gid):
            calls.append((uid, gid))
            if uid != 1000:
                raise asyncssh.SFTPPermissionDenied("Operation not permitted")

        async def lstat(self, path):
            return asyncssh.SFTPAttrs(uid=1000, gid=1000)

        async def chmod(self, path, mode):
            calls.append(oct(mode))

    # app:app 0660, bewerkt door jonas (uid 1000) uit de groep app: jonas wordt eigenaar, de groep blijft app.
    await bestanden._keep_attrs(Fake(), "/srv/app/config.yml",
                                asyncssh.SFTPAttrs(uid=33, gid=33, permissions=stat.S_IFREG | 0o660))
    assert calls == [(33, 33), (1000, 33), "0o660"]


async def test_afmelden_sluit_vensters_en_downloadlinks(authed, sftpd):
    (sftpd["root"] / "a").write_text("a")
    _, fs = await _open(authed, sftpd)
    want = {"dir": "/", "names": ["a"]}
    url = (await authed.post(f"/api/ssh/files/{fs}/download", json=want)).json()["url"]
    # De browsersessie bestaat niet meer (bv. ingetrokken op een ander toestel): de link werkt niet.
    bestanden.DOWNLOADS[url.rsplit("/", 1)[1]].sess_id = "ingetrokken"
    assert (await authed.get(url)).status_code == 410
    url = (await authed.post(f"/api/ssh/files/{fs}/download", json=want)).json()["url"]
    assert (await authed.post("/api/auth/logout")).status_code == 200
    assert fs not in bestanden.SESSIONS
    assert (await authed.get(url)).status_code == 404


async def test_map_uploaden_maakt_mappen_ook_als_de_upload_niet_afloopt(authed, sftpd):
    root = sftpd["root"]
    (root / "bestaat").mkdir()
    _, fs = await _open(authed, sftpd)
    up = (await authed.post(f"/api/ssh/files/{fs}/upload",
                            json={"dir": "/", "name": "nieuw/diep/a.txt", "size": 1})).json()
    assert "made" not in up
    assert (await authed.delete(f"/api/ssh/files/{fs}/upload/{up['id']}")).status_code == 200
    assert (root / "nieuw/diep").is_dir() and _parts(root) == []
    await _upload(authed, fs, "/", "bestaat/b.txt", b"b")
    await _upload(authed, fs, "/bestaat", "c/d/e.txt", b"e")
    made = [a.detail for a in await _actions() if a.action == "sftp_mkdir"]
    assert made == [{"name": "pve", "path": "/nieuw", "via": "upload"},
                    {"name": "pve", "path": "/bestaat/c", "via": "upload"}]


async def test_symlink_naar_een_map_zonder_utf8_naam(authed, sftpd):
    root = sftpd["root"]
    os.makedirs(bytes(root) + b"/caf\xe9/sub")
    # Absoluut, zoals in test_map_bekijken (de testserver).
    os.symlink(bytes(root) + b"/caf\xe9/sub", bytes(root) + b"/link")
    _, fs = await _open(authed, sftpd)
    lst = await _list(authed, fs, "/link")
    # Het pad blijft het gevraagde: een upload hier gaat naar de echte map, niet naar een kopie met vervangtekens.
    assert lst["path"] == "/link" and lst["odd"] is True
    await _upload(authed, fs, lst["path"], "a.txt", b"a")
    assert os.path.exists(bytes(root) + b"/caf\xe9/sub/a.txt")


async def test_kleinere_stukken_op_vraag(authed, sftpd):
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    data = os.urandom(200_000)
    body = {"dir": "/", "name": "x", "size": len(data), "chunk": bestanden.MIN_CHUNK}
    up = (await authed.post(f"/api/ssh/files/{fs}/upload", json=body)).json()
    assert up["chunk"] == bestanden.MIN_CHUNK and up["chunks"] == 4
    for i in range(4):
        part = data[i * up["chunk"]:(i + 1) * up["chunk"]]
        assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/{i}", content=part)).status_code == 200
    assert (await authed.post(f"/api/ssh/files/{fs}/upload/{up['id']}/finish")).status_code == 200
    assert (root / "x").read_bytes() == data
    r = await authed.post(f"/api/ssh/files/{fs}/upload", json={**body, "name": "y", "chunk": 1000})
    assert r.status_code == 422


async def test_half_bestand_bij_de_volgende_verbinding_opgeruimd(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "CHUNK", 4)
    root = sftpd["root"]
    _, fs = await _open(authed, sftpd)
    up = (await authed.post(f"/api/ssh/files/{fs}/upload", json={"dir": "/", "name": "z", "size": 8})).json()
    assert (await authed.put(f"/api/ssh/files/{fs}/upload/{up['id']}/0", content=b"1234")).status_code == 200
    bestanden._drop_conn(bestanden.SESSIONS[fs])
    assert (await authed.delete(f"/api/ssh/files/{fs}/upload/{up['id']}")).status_code == 200
    assert len(_parts(root)) == 1
    await _list(authed, fs)
    assert _parts(root) == [] and not bestanden.LEFTOVER


async def _session(authed, sftpd):
    _, fs = await _open(authed, sftpd)
    s = bestanden.SESSIONS[fs]
    return s, s.sftp


async def test_zip_breekt_af_als_de_verbinding_wegvalt(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "READ_BLOCK", 64 * 1024)
    root = sftpd["root"]
    (root / "site").mkdir()
    for i in range(3):
        (root / "site" / f"f{i}.bin").write_bytes(os.urandom(512 * 1024))
    s, sftp = await _session(authed, sftpd)
    gen = bestanden.zip_stream(s, sftp, "/", ["site"])
    assert await anext(gen) is not None and s.busy == 1
    s.conn.close()
    await asyncio.sleep(0.05)
    with pytest.raises(asyncssh.Error):
        async for _ in gen:
            pass
    assert s.busy == 0


async def test_venster_sluiten_laat_een_lopende_download_afmaken(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "READ_BLOCK", 64 * 1024)
    root = sftpd["root"]
    (root / "site").mkdir()
    data = os.urandom(512 * 1024)
    (root / "site/a.bin").write_bytes(data)
    s, sftp = await _session(authed, sftpd)
    sink = io.BytesIO()
    gen = bestanden.zip_stream(s, sftp, "/", ["site"])
    sink.write(await anext(gen))
    await bestanden.close_session(s)
    assert s.closing and s.conn is not None
    # De opruimer laat ze ook staan zolang ze loopt.
    s.conn_used -= bestanden.CONN_IDLE + 1
    await bestanden.sweep()
    assert s.conn is not None
    async for out in gen:
        sink.write(out)
    assert zipfile.ZipFile(sink).read("site/a.bin") == data
    assert s.conn is None and s.busy == 0


async def test_zip_met_te_veel_items(authed, sftpd, monkeypatch):
    monkeypatch.setattr(bestanden, "ZIP_MAX", 3)
    root = sftpd["root"]
    (root / "veel").mkdir()
    for i in range(5):
        (root / "veel" / f"{i}.txt").write_text(str(i))
    s, sftp = await _session(authed, sftpd)
    z = zipfile.ZipFile(io.BytesIO(b"".join([x async for x in bestanden.zip_stream(s, sftp, "/", ["veel"])])))
    assert z.namelist() == ["veel/", "veel/0.txt", "veel/1.txt", "NIET-MEEGENOMEN.txt"]
    assert "hoogstens 3 items" in z.read("NIET-MEEGENOMEN.txt").decode()
