"""De terminal zegt waarom verbinden niet lukt, en waarmee hij aanmeldt.

Jonas zag "Hostsleutel ophalen…" en dacht dat de terminal een login-sleutel zocht; een time-out toonde daarna
alleen "Verbinden mislukt:" zonder reden.
"""

import asyncio
import errno
import socket

import asyncssh
import pytest

from app import ssh_exec
from app.models import SshHost
from app.routers import ssh as ssh_router
from app.ssh_login import Login, geweigerd, methode, waarom

from .test_ssh import WS, _cookie, sshd  # noqa: F401 (fixture)


def test_waarom_heeft_altijd_een_reden():
    t = waarom(asyncio.TimeoutError(), "192.168.0.105", 22, 10)
    assert t.startswith("geen antwoord van 192.168.0.105:22 binnen 10 s.") and "firewall" in t and "poort 22" in t
    assert waarom(TimeoutError(), "h", 2222).startswith("geen antwoord van h:2222. ")
    assert "weigert de verbinding" in waarom(ConnectionRefusedError(111, "Connect call failed"), "h", 22)
    assert "is onbekend (DNS)" in waarom(socket.gaierror(-2, "Name or service not known"), "ct.lan", 22)
    for no in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        assert "niet bereikbaar (geen route)" in waarom(OSError(no, "Connect call failed"), "10.9.9.9", 22)
    assert waarom(asyncssh.ConnectionLost("Connection lost"), "h", 22) == "Connection lost"
    # Een fout zonder tekst: dan minstens zijn naam, nooit leeg.
    assert waarom(asyncssh.Error(0, ""), "h", 22) == "Error"
    assert waarom(OSError(), "h", 22) == "OSError"


def test_methode_en_geweigerd():
    key = asyncssh.generate_private_key("ssh-ed25519")
    assert methode(Login("root", None, "pw")) == "wachtwoord uit ⚙ standaard"
    assert methode(Login("root", None, "pw", own=True)) == "wachtwoord van deze host"
    assert methode(Login("root", key, None, own=True)) == "sleutel van deze host"
    assert methode(Login("root", key, "pw")) == "sleutel, daarna wachtwoord uit ⚙ standaard"
    assert methode(Login("root", None, None)) == "zonder wachtwoord of sleutel"

    t = geweigerd(Login("root", None, "pw"))
    assert t.startswith("Aanmelden als root geweigerd (wachtwoord uit ⚙ standaard): klopt het wachtwoord")
    assert "PermitRootLogin" in t and "authorized_keys" not in t
    t = geweigerd(Login("jonas", key, None, own=True))
    assert "authorized_keys" in t and "wachtwoord" not in t.split(":", 1)[1]
    assert "PermitRootLogin" not in geweigerd(Login("jonas", None, "pw"))
    assert "geen wachtwoord of sleutel ingesteld" in geweigerd(Login("root", None, None))


async def _host(authed, port, **kw) -> int:
    r = await authed.post("/api/ssh/hosts", json={"name": "ct", "host": "127.0.0.1", "port": port, **kw})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_eerste_verbinding_zegt_dat_het_geen_login_is_en_waarmee_hij_aanmeldt(authed, sshd):  # noqa: F811
    hid = await _host(authed, sshd["port"], password="goed")
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    first = await ws.json()
    assert first["t"] == "status" and "vingerafdruk" in first["m"] and "nog voor het aanmelden" in first["m"]
    assert f"127.0.0.1:{sshd['port']}" in first["m"]
    assert (await ws.json())["t"] == "hostkey"
    await ws.send_text({"t": "accept"})
    status = await ws.json()
    assert status["m"] == "Verbinden met root@127.0.0.1 (wachtwoord van deze host)…"
    assert (await ws.json())["t"] == "ready"
    await ws.close()


async def test_standaard_wachtwoord_en_fout_wachtwoord(authed, sshd):  # noqa: F811
    assert (await authed.put("/api/ssh/defaults", json={"username": "root", "password": "fout"})).status_code == 200
    hid = await _host(authed, sshd["port"])
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    await ws.json()
    await ws.send_text({"t": "accept"})
    assert (await ws.json())["m"] == "Verbinden met root@127.0.0.1 (wachtwoord uit ⚙ standaard)…"
    err = await ws.json()
    assert err["t"] == "error"
    assert err["m"].startswith("Aanmelden als root geweigerd (wachtwoord uit ⚙ standaard): klopt het wachtwoord")
    assert "PermitRootLogin" in err["m"]


async def test_poort_dicht_zegt_geweigerd(authed):
    hid = await _host(authed, _closed_port())
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    err = await ws.json()
    assert err["t"] == "error" and err["m"].startswith("Verbinden mislukt: 127.0.0.1:")
    assert "weigert de verbinding" in err["m"]


async def test_geen_antwoord_zegt_ip_poort_en_firewall(authed, monkeypatch):
    async def hangt(host, port, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(ssh_router.asyncssh, "get_server_host_key", hangt)
    monkeypatch.setattr(ssh_router, "CONNECT_TIMEOUT", 0.2)
    hid = await _host(authed, 22)
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    err = await ws.json()
    assert err == {"t": "error", "m": "Verbinden mislukt: geen antwoord van 127.0.0.1:22 binnen 0.2 s. Draait SSH "
                                      "daar, en laat de firewall (bv. OPNsense) de homepage door naar dat IP op poort 22?"}


async def test_niet_bevestigd_is_geen_netwerkfout(authed, sshd, monkeypatch):  # noqa: F811
    monkeypatch.setattr(ssh_router, "HOSTKEY_WAIT", 0.2)
    hid = await _host(authed, sshd["port"], password="goed")
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    assert (await ws.json())["t"] == "hostkey"
    err = await ws.json()
    assert err == {"t": "error", "m": "Hostsleutel niet bevestigd binnen 2 minuten: verbind opnieuw"}


async def test_ssh_exec_zegt_waarom(monkeypatch):
    async def traag(*a, **kw):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(ssh_exec.asyncssh, "connect", traag)
    h = SshHost(name="pbs", host="192.168.0.20", port=22,
                host_key=asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode())
    with pytest.raises(ssh_exec.SshFail) as e:
        async with ssh_exec.connect(h, Login("root", None, "pw")):
            pass
    assert str(e.value).startswith("SSH naar 192.168.0.20 mislukt: geen antwoord van 192.168.0.20:22 binnen 15 s.")

    async def nee(*a, **kw):
        raise asyncssh.PermissionDenied("Permission denied")

    monkeypatch.setattr(ssh_exec.asyncssh, "connect", nee)
    with pytest.raises(ssh_exec.SshFail) as e:
        async with ssh_exec.connect(h, Login("root", None, "pw", own=True)):
            pass
    assert str(e.value).startswith("Aanmelden als root geweigerd (wachtwoord van deze host): klopt het wachtwoord")
