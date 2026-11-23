"""Gebouwd zonder herstart: API en worker zien dat ze oudere code draaien dan er op schijf staat."""

from app import codeversie as cv


async def test_herstart_nodig(authed, monkeypatch):
    r = (await authed.get("/api/version")).json()
    assert r["herstart_api"] is False and r["herstart_worker"] is False and r["api_gestart"]
    monkeypatch.setattr(cv, "on_disk", lambda: "nieuw")
    r = (await authed.get("/api/version")).json()
    assert r["herstart_api"] is True
    att = (await authed.get("/api/attention")).json()["items"]
    assert any(i["key"] == "herstart" and "API" in i["title"] for i in att)


def test_worker_vergelijkt_zijn_eigen_code(monkeypatch):
    monkeypatch.setattr(cv, "on_disk", lambda: "b")
    assert cv.worker_stale({"code": "a"}) and not cv.worker_stale({"code": "b"}) and not cv.worker_stale({})
