"""API's terugzetten uit een back-up (pg_dump), na een fabrieksreset."""

import os
import shutil
import subprocess

import pytest
from sqlalchemy import delete, select
from sqlalchemy.engine import make_url

from app import apiherstel
from app.models import ApiCall, ApiConnection
from app.security import decrypt_json, encrypt_json

from .conftest import TEST_DB
from .test_capacity import _db

COPY = (
    "--\n-- Data for Name: api_connections\n--\n\n"
    "COPY public.api_connections (id, name, category, kind, template, url, config, secrets, created_at, updated_at) FROM stdin;\n"
    "3\tNPM\tInfrastructuur\tnpm\tnpm\thttp://192.168.0.245:81\t{\"insecure\": true}\tSECRET\t2026-11-01 10:00:00+00\t2026-11-01 10:00:00+00\n"
    "4\tEigen\\tAPI\toverig\trest\t\\N\thttp://x.lan\t{}\t\\N\t2026-11-01 10:00:00+00\t2026-11-01 10:00:00+00\n"
    "\\.\n\n"
    "COPY public.api_calls (id, connection_id, name, method, path, query, headers, body, show, fields, \"table\", confirm, position) FROM stdin;\n"
    "9\t4\tstatus\tGET\t/status\t{}\t{}\t\\N\ttile\t[{\"label\": \"versie\", \"path\": \"v\"}]\t{}\tt\t0\n"
    "\\.\n"
)


def test_copy_lezen():
    t = apiherstel.parse_copy(COPY)
    assert [r["name"] for r in t["api_connections"]] == ["NPM", "Eigen\tAPI"]
    assert t["api_connections"][1]["template"] is None
    assert t["api_calls"][0]["table"] == "{}" and t["api_calls"][0]["connection_id"] == "4"
    assert apiherstel._unescape("a\\\\b\\nc\\101") == "a\\b\ncA"


async def test_terugzetten_slaat_bestaande_over_en_leest_sleutels(client):
    agen, db = await _db()
    db.add(ApiConnection(name="NPM nu", kind="npm", url="http://192.168.0.245:81/"))
    await db.commit()
    good = encrypt_json({"token": "abc"})
    tables = apiherstel.parse_copy(COPY.replace("SECRET", good).replace("http://192.168.0.245:81", "http://npm.lan:81"))
    tables["api_connections"].append({**tables["api_connections"][0], "id": "5", "url": "http://other:81",
                                      "secrets": "gAAAAkapot"})
    r = await apiherstel.restore(db, tables)
    await db.commit()
    assert r["added"] == ["NPM", "Eigen\tAPI", "NPM"] and r["no_keys"] == ["NPM"]
    conns = {a.url: a for a in (await db.execute(select(ApiConnection))).scalars().all()}
    assert decrypt_json(conns["http://npm.lan:81"].secrets) == {"token": "abc"}
    assert conns["http://other:81"].secrets is None
    assert [c.name for c in conns["http://x.lan"].calls] == ["status"]
    assert conns["http://x.lan"].calls[0].fields == [{"label": "versie", "path": "v"}]
    # Twee keer: niets dubbel.
    r = await apiherstel.restore(db, tables)
    assert r["added"] == [] and len(r["skipped"]) == 3
    await agen.aclose()


@pytest.mark.skipif(TEST_DB.startswith("sqlite") or not shutil.which("pg_dump"), reason="pg_dump en PostgreSQL nodig")
async def test_van_echte_dump_via_upload(authed, tmp_path):
    agen, db = await _db()
    a = ApiConnection(name="Proxmox", category="Infrastructuur", kind="proxmox", url="https://192.168.0.50:8006",
                      config={"insecure": "true"}, secrets=encrypt_json({"username": "u@pve!t", "password": "p\tq\\r"}))
    a.calls.append(ApiCall(name="versie", path="/version", fields=[{"label": "v", "path": "data.version"}]))
    db.add(a)
    await db.commit()
    url = make_url(TEST_DB)
    env = {**os.environ, "PGPASSWORD": url.password or ""}
    out = tmp_path / "homepage-test.dump"
    subprocess.run(["pg_dump", "-Fc", "-f", str(out), "-h", url.host or "localhost", "-p", str(url.port or 5432),
                    "-U", url.username or "postgres", url.database], check=True, env=env)
    await db.execute(delete(ApiConnection))
    await db.commit()
    await agen.aclose()

    r = await authed.post("/api/apis/herstel/upload", content=out.read_bytes())
    assert r.status_code == 200, r.text
    assert r.json()["added"] == ["Proxmox"] and r.json()["no_keys"] == []
    r = await authed.post("/api/apis/herstel/upload", content=b"geen dump")
    assert r.status_code == 422 and "geen back-up" in r.json()["detail"]

    agen, db = await _db()
    back = (await db.execute(select(ApiConnection))).scalar_one()
    assert decrypt_json(back.secrets) == {"username": "u@pve!t", "password": "p\tq\\r"}
    assert back.config == {"insecure": "true"} and [c.path for c in back.calls] == ["/version"]
    await agen.aclose()


async def test_lijst_van_dumps(authed, tmp_path, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path)
    (tmp_path / "homepage-2026-11-22.dump").write_bytes(b"x")
    r = await authed.get("/api/apis/herstel")
    assert r.status_code == 200 and [d["name"] for d in r.json()["dumps"]] == ["homepage-2026-11-22.dump"]
    r = await authed.post("/api/apis/herstel", json={"name": "../../etc/passwd"})
    assert r.status_code == 404
