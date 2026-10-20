import logging
import re
from collections import Counter

from app import logring, proef
from app.masking import basic, mask, mask_tree, variants


def test_patronen_maskeren_geheimen_en_laten_id_s_staan():
    cases = {
        "Authorization: PVEAPIToken=homepage@pve!dashboard=0b1c2d3e-aaaa": "Authorization: ***",
        "PVEAPIToken=homepage@pve!dashboard=0b1c2d3e-aaaa": "PVEAPIToken=homepage@pve!dashboard=***",
        "PBSAPIToken=homepage@pbs!sync:5ec4e7-1": "PBSAPIToken=homepage@pbs!sync:***",
        "{'Authorization': 'Bearer abcdefghijklmnopqrstuv'}": "{'Authorization': '***'}",
        "fout bij Bearer abcdefghijklmnopqrstuv": "fout bij Bearer ***",
        "GET https://radarr.lan/api/v3/system?apikey=1234567890abcdef&x=1": "GET https://radarr.lan/api/v3/system?apikey=***&x=1",
        "https://admin:hunter22@npm.lan/api": "https://admin:***@npm.lan/api",
        "POST /api/push/AbCdEfGhIjKlMnOpQrStUv12": "POST /api/push/***",
        "POST /api/hooks/AbCdEfGhIjKlMnOpQrStUv12 202": "POST /api/hooks/*** 202",
        "blob gAAAAABlZz1234567890abcdefghijklmnopq": "blob ***",
        "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmN": "t=***",
        "DB_PASSWORD=supersecret more": "DB_PASSWORD=*** more",
        '{"password": "abc123def"}': '{"password": "***"}',
        "Cookie: hp_session=abcdef123456": "Cookie: ***",
        "set hp_session=abcdef123456; path=/": "set hp_session=***; path=/",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\nAAAA\n-----END OPENSSH PRIVATE KEY-----":
            "-----BEGIN OPENSSH PRIVATE KEY----- *** -----END OPENSSH PRIVATE KEY-----",
    }
    for raw, want in cases.items():
        assert mask(raw) == want, raw
    # Wat geen geheim is, blijft staan.
    for keep in ("API-token homepage-acties@pve!acties",
                 "pct snapshot 105 hp-upd-20261011-030000 --description 'voor updates via homepage, 11/10/2026 03:00'",
                 "sudo -n sh -c 'apt-get update && apt-get -y --only-upgrade install openssl'",
                 'remote create "$R" --auth-id "$U!$T" --password "$PW"',
                 "POST /api2/json/nodes/pve50/lxc/105/status/reboot"):
        assert mask(keep) == keep


def test_bekende_waarden_ook_gecodeerd_en_geteld():
    known = variants(["s3cret/value", "abc", None, "  "])
    assert known == ["s3cret%2Fvalue", "s3cret/value"]
    c = Counter()
    assert mask("a s3cret/value b s3cret%2Fvalue", known, c) == "a *** b ***"
    assert c["bekend"] == 2
    b = basic("homepage", "pw1234")
    assert mask(f"Authorization: Basic {b}", variants([b])) == "Authorization: ***"
    tree = mask_tree({"fout": ["x s3cret/value"], "s3cret/value": 1, "n": 3}, known)
    assert tree == {"fout": ["x ***"], "***": 1, "n": 3}


def test_plan_nummert_maskeert_en_wordt_tekst():
    p = proef.plan("Updates op pve50", [
        proef.step("pve50 (root@192.168.0.50:22)", "ssh", "sh -c 'apt-get update'", who="root", wait="max. 1800 s"),
        proef.step("pve50", "proxmox-api", "POST /api2/json/nodes/pve50/lxc/105/snapshot",
                   who=proef.api_who("homepage@pve!acties"), data={"snapname": "hp-upd-1"}, note="token=lekt"),
    ], checks=[proef.check("hostsleutel bevestigd", True), proef.check("token mag snapshots", None, "niet na te gaan")],
        skipped=[proef.skip("pve51", "fysieke machine")], after=["updates opnieuw scannen"])
    assert [s["nr"] for s in p["steps"]] == [1, 2] and p["proef"] is True
    assert p["steps"][1]["note"] == "token=***"
    assert p["steps"][1]["who"] == "API-token homepage@pve!acties"
    t = proef.text(p)
    assert "1. pve50 (root@192.168.0.50:22) via SSH als root" in t
    assert "2. pve50 via Proxmox-API als API-token homepage@pve!acties" in t
    assert "✓ hostsleutel bevestigd" in t and "? token mag snapshots: niet na te gaan" in t
    assert "overgeslagen: pve51: fysieke machine" in t and "daarna: updates opnieuw scannen" in t
    assert "Er zou niets gebeuren." in proef.text(proef.plan("leeg", []))


def test_waarde_tussen_aanhalingstekens_helemaal_gemaskeerd():
    """Een wachtwoord met spaties of een komma tussen aanhalingstekens: de hele waarde, niet alleen het eerste stuk."""
    cases = {
        '{"password": "correct horse battery staple"}': '{"password": "***"}',
        "{'password': 'p,ss'}": "{'password': '***'}",
        'password: "abc': 'password: "***',  # geen sluitend aanhalingsteken: tot de volgende spatie
        '{"db_password": "a\\"b c", "user": "jonas"}': '{"db_password": "***", "user": "jonas"}',
    }
    for raw, want in cases.items():
        assert mask(raw) == want, raw
        assert mask(want) == want, want  # al gemaskeerd: blijft zo


def _pieces(out: str, value: str) -> list[str]:
    """Woorden in out die een stuk (3+ tekens) van value zijn."""
    return [w for w in re.split(r"[\s'\"]+", out) if len(w) >= 3 and w in value]


def test_afkappen_laat_geen_losse_waarde_achter():
    """Valt een snede in of vlak bij "password: hunter2pw" of "Bearer ...", ook in het woord ervoor of op de spatie
    tussen naam en waarde, dan verdwijnt de waarde helemaal: zonder haar naam herkent het maskeren haar niet meer.
    Zoals een property-test: elke lengte, dus elke plaats van beide sneden."""
    words = " ".join(f"w{i:03d}" for i in range(60))
    for secret, value in (("password: hunter2pw", "hunter2pw"), ("password = hunter2pw", "hunter2pw"),
                          ("Bearer abcdefghijklmnop", "abcdefghijklmnop"),
                          ('"password": "een twee drie vier"', "een twee drie vier"),
                          ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop")):
        text = f"{words} {secret} {words}"
        for n in range(8, len(text)):
            out = mask(logring.cut(text, n))
            assert len(out) <= n, (secret, n, out)
            assert value not in out and not _pieces(out, value), (secret, n, out)


def test_afkappen_midden_in_een_sleutel_of_bekend_geheim():
    """Een PEM-sleutel of een bekend geheim met spaties dat over een snede loopt, valt er helemaal af."""
    body = "\n".join("MIIEv" + f"{i:059d}" for i in range(20))
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    text = f"fout bij inloggen: {pem}\nTraceback (most recent call last): klaar"
    for n in range(40, len(text), 7):
        out = mask(logring.cut(text, n))
        assert "MIIEv" not in out, (n, out)
    phrase = "correct paard nietje batterij"
    text = " ".join(f"w{i:03d}" for i in range(40)) + f" {phrase} " + " ".join(f"w{i:03d}" for i in range(40))
    for n in range(8, len(text)):
        out = mask(logring.cut(text, n, [phrase]), [phrase])
        assert not _pieces(out, phrase), (n, out)
        assert not logring.after(text, len(text) - n, [phrase]).startswith(("paard", "nietje", "batterij"))


def test_logregel_zonder_nul():
    """PostgreSQL weigert \\u0000 in JSONB: met een NUL in de ring zou het bewaren van de regels blijven mislukken."""
    h = logring.RingHandler(size=3)
    lg = logging.getLogger("homepage.test.nul")
    lg.addHandler(h)
    lg.propagate = False
    try:
        lg.warning("syslog van %s: a\x00b\x00", "nas")
        assert h.tail()[-1]["msg"] == "syslog van nas: ab"
    finally:
        lg.removeHandler(h)
        lg.propagate = True


def test_einde_van_een_update_zonder_losse_waarde():
    """De diagnose toont van een update-run alleen het einde van de uitvoer: ook daar valt een geheim dat over de
    snede loopt er helemaal af, en een bekend geheim met spaties ook."""
    from app import diagnose

    words = " ".join(f"w{i:03d}" for i in range(60))
    phrase = "correct paard nietje batterij"
    for secret, value in (("password: hunter2pw", "hunter2pw"), ("Bearer abcdefghijklmnop", "abcdefghijklmnop"),
                          (phrase, phrase)):
        text = f"{words} {secret} {words}"
        token = diagnose._KNOWN.set((phrase,))
        try:
            for n in range(1, len(text)):
                out = mask(diagnose._tail(text, n), [phrase])
                assert value not in out and not _pieces(out, value), (secret, n, out)
        finally:
            diagnose._KNOWN.reset(token)
