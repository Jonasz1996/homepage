"""De homepage bewaakt zichzelf: leeft de worker, is er een recente en leesbare back-up van de database, hoe groot
is de database, hoe vol de schijf, en staat er een kopie van back-up én sleutel buiten de container.

De kopie van secret.key wordt versleuteld met een wachtzin die alleen jij kent (scrypt + AES-GCM); de wachtzin
zelf wordt nergens bewaard. Terugzetten: python -m app.health.selfcheck decrypt secret.key.enc > secret.key
"""

import asyncio
import base64
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import ensure_state
from ..deps import event, notify
from ..models import AppState
from ..monitoring.checks import kill

log = logging.getLogger("homepage.health")

SELFCHECK_EVERY = 3600
HEARTBEAT_EVERY = 60
HEARTBEAT_KEY = "worker"
STATE_KEY = "selfcheck"
KEY_STATE = "offsite_key"
WORKER_STALE = timedelta(minutes=5)
BACKUP_STALE = timedelta(hours=36)
DISK_WARN = 90
OFFSITE_KEEP_DAYS = 30
MIN_PASSPHRASE = 12
README = """Kopie van de homepage-database, gemaakt door de homepage zelf.

homepage-JJJJ-MM-DD.dump  pg_dump -Fc van de database (dagelijks, {keep} dagen bewaard)
secret.key.enc            de sleutel waarmee wachtwoorden en API-sleutels in de database versleuteld zijn,
                          zelf versleuteld met jouw wachtzin

Terugzetten op een nieuwe container (na install.sh):
  cd /opt/homepage/backend
  ../.venv/bin/python -m app.health.selfcheck decrypt /pad/naar/secret.key.enc > /etc/homepage/secret.key
  chown root:homepage /etc/homepage/secret.key && chmod 640 /etc/homepage/secret.key
  systemctl stop homepage-api homepage-worker homepage-syslog
  sudo -u postgres dropdb homepage && sudo -u postgres createdb -O homepage homepage
  # Met TimescaleDB (staat standaard aan; dezelfde versie als bij de back-up):
  sudo -u postgres psql -d homepage -c "CREATE EXTENSION timescaledb" -c "SELECT timescaledb_pre_restore()"
  sudo -u postgres pg_restore -d homepage /pad/naar/homepage-JJJJ-MM-DD.dump
  sudo -u postgres psql -d homepage -c "SELECT timescaledb_post_restore()"
  # Zonder TimescaleDB: alleen de pg_restore-regel.
  systemctl start homepage-api homepage-worker homepage-syslog
"""


# --- worker leeft ---------------------------------------------------------------------------------------------

async def heartbeat(db: AsyncSession, started: datetime) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = {"at": now.isoformat(), "started": started.isoformat(), "pid": os.getpid()}
    st = await db.get(AppState, HEARTBEAT_KEY)
    if st:
        st.value = value
    else:
        db.add(AppState(key=HEARTBEAT_KEY, value=value))


def worker_status(value: dict | None, now: datetime) -> dict:
    if not value or not value.get("at"):
        return {"ok": False, "at": None, "started": None, "why": "de worker heeft nog nooit gemeld dat hij draait"}
    at = datetime.fromisoformat(value["at"])
    ok = now - at < WORKER_STALE
    return {"ok": ok, "at": value["at"], "started": value.get("started"),
            "why": None if ok else f"laatste teken van leven {int((now - at).total_seconds() // 60)} min geleden"}


async def check_worker(db: AsyncSession) -> dict:
    """Vanuit de API: de worker kan zijn eigen dood niet melden, dus de API doet dat (één keer)."""
    now = datetime.now(timezone.utc)
    hb = await db.get(AppState, HEARTBEAT_KEY)
    status = worker_status(hb.value if hb else None, now)
    flag = await db.get(AppState, "worker_alert")
    alerted = bool(flag and flag.value.get("down"))
    if hb and not status["ok"] and not alerted:
        notify(db, "De worker van de homepage draait niet",
               f"{status['why']}. Checks, meldingen en back-up-kopieën staan stil.\n"
               "Op de container: systemctl status homepage-worker; journalctl -u homepage-worker -n 50",
               level="err", source="homepage")
        await _set_flag(db, flag, True)
    elif status["ok"] and alerted:
        event(db, "gezondheid", "De worker van de homepage draait weer", level="ok")
        await _set_flag(db, flag, False)
    return status


async def _set_flag(db: AsyncSession, flag: AppState | None, down: bool) -> None:
    # Twee verzoeken tegelijk mogen niet allebei een nieuwe rij proberen toe te voegen.
    flag = flag or await ensure_state(db, "worker_alert")
    flag.value = {"down": down}


# --- back-ups -------------------------------------------------------------------------------------------------

def list_dumps(folder: Path) -> list[dict]:
    try:
        files = [p for p in folder.glob("homepage-*.dump") if p.is_file()]
    except OSError:
        return []
    out = []
    for p in files:
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size,
                    "at": datetime.fromtimestamp(st.st_mtime, timezone.utc).replace(microsecond=0).isoformat()})
    return sorted(out, key=lambda d: d["at"], reverse=True)


async def verify_dump(path: Path) -> tuple[bool | None, str | None]:
    """pg_restore --list leest de inhoudstafel: een afgebroken of lege dump valt zo op, zonder database nodig."""
    exe = shutil.which("pg_restore") or next(iter(sorted(Path("/usr/lib/postgresql").glob("*/bin/pg_restore"))), None)
    if not exe:
        return None, "pg_restore niet gevonden"
    try:
        proc = await asyncio.create_subprocess_exec(str(exe), "--list", str(path), stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
    except OSError as e:
        return None, type(e).__name__
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 120)
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        await kill(proc)  # anders blijft pg_restore draaien
        if isinstance(e, asyncio.CancelledError):
            raise
        return None, type(e).__name__
    if proc.returncode != 0:
        return False, (err.decode(errors="replace").strip().splitlines() or ["onleesbaar"])[-1][:200]
    tables = sum(1 for line in out.decode(errors="replace").splitlines() if " TABLE DATA " in line)
    return (tables > 0), f"{tables} tabellen"


# --- database en schijf ---------------------------------------------------------------------------------------

async def db_size(db: AsyncSession) -> dict:
    if db.bind.dialect.name != "postgresql":
        return {"total": None, "tables": []}
    total = (await db.execute(text("SELECT pg_database_size(current_database())"))).scalar()
    rows = (await db.execute(text(
        "SELECT c.relname, pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')"))).all()
    tables = {name: size for name, size in rows}
    try:
        async with db.begin_nested():
            for name, size in (await db.execute(text(
                    "SELECT hypertable_name, hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass) "
                    "FROM timescaledb_information.hypertables"))).all():
                tables[name] = size
    except Exception:
        pass
    top = sorted(({"name": k, "size": v} for k, v in tables.items() if v), key=lambda t: -t["size"])[:10]
    return {"total": total, "tables": top}


def disk(path: Path) -> dict | None:
    try:
        u = shutil.disk_usage(path)
    except OSError:
        return None
    return {"path": str(path), "total": u.total, "used": u.used, "free": u.free, "pct": round(u.used * 100 / u.total, 1)}


# --- versleutelde sleutel -------------------------------------------------------------------------------------

def _kdf(salt: bytes, n: int) -> Scrypt:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1)


def encrypt_key(secret: bytes, passphrase: str, n: int = 2 ** 15) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _kdf(salt, n).derive(passphrase.encode())
    ct = AESGCM(key).encrypt(nonce, secret, b"homepage-secret-key")
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return {"v": 1, "kdf": "scrypt", "n": n, "r": 8, "p": 1, "salt": b(salt), "nonce": b(nonce), "ct": b(ct)}


def decrypt_key(blob: dict, passphrase: str) -> bytes:
    d = lambda k: base64.b64decode(blob[k])  # noqa: E731
    key = _kdf(d("salt"), int(blob["n"])).derive(passphrase.encode())
    return AESGCM(key).decrypt(d("nonce"), d("ct"), b"homepage-secret-key")


# --- kopie buiten de container --------------------------------------------------------------------------------

def offsite_copy(src: Path, dst: Path, key_blob: dict | None, now: datetime) -> dict:
    """Nieuwste dumps en de versleutelde sleutel naar dst kopiëren. Gooit OSError als het niet lukt."""
    if not dst.is_dir():
        raise OSError(f"map {dst} bestaat niet (koppel er een NAS-share, PBS-opslag of USB-schijf aan)")
    if not os.access(dst, os.W_OK):
        raise OSError(f"geen schrijfrechten op {dst} voor gebruiker homepage")
    copied = []
    for d in list_dumps(src)[:3]:
        target = dst / d["name"]
        if target.exists() and target.stat().st_size == d["size"]:
            continue
        tmp = dst / f".{d['name']}.part"
        shutil.copyfile(src / d["name"], tmp)
        os.replace(tmp, target)
        copied.append(d["name"])
    if key_blob:
        enc = json.dumps(key_blob, indent=1)
        kp = dst / "secret.key.enc"
        if not kp.exists() or kp.read_text() != enc:
            kp.write_text(enc)
            copied.append(kp.name)
    rp = dst / "LEESMIJ.txt"
    readme = README.format(keep=OFFSITE_KEEP_DAYS)
    if not rp.exists() or rp.read_text() != readme:
        rp.write_text(readme)
    for d in list_dumps(dst)[1:]:
        if now - datetime.fromisoformat(d["at"]) > timedelta(days=OFFSITE_KEEP_DAYS):
            (dst / d["name"]).unlink(missing_ok=True)
    there = list_dumps(dst)
    return {"copied": copied, "latest": there[0] if there else None, "count": len(there),
            "key": (dst / "secret.key.enc").exists()}


# --- alles samen ----------------------------------------------------------------------------------------------

async def run_selfcheck(db: AsyncSession, offsite_on: bool) -> dict:
    s = get_settings()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    state = await db.get(AppState, STATE_KEY)
    prev = state.value if state else {}
    dumps = list_dumps(s.backup_dir)
    latest = dumps[0] if dumps else None
    verified = prev.get("verified") or {}
    if latest and (verified.get("name") != latest["name"] or verified.get("size") != latest["size"]):
        ok, why = await verify_dump(s.backup_dir / latest["name"])
        verified = {"name": latest["name"], "size": latest["size"], "ok": ok, "why": why}
        if ok is False:
            notify(db, "Back-up van de homepage is onleesbaar", f"{latest['name']}: {why}", level="err",
                   source="homepage")
    stale = latest is None or now - datetime.fromisoformat(latest["at"]) > BACKUP_STALE
    alerts = dict(prev.get("alerts") or {})
    if stale and not alerts.get("stale"):
        notify(db, "Geen recente back-up van de homepage",
               (f"Laatste: {latest['name']}" if latest else f"Geen enkele dump in {s.backup_dir}") +
               "\nKijk na: systemctl status homepage-backup.timer homepage-backup.service", level="err",
               source="homepage")
    alerts["stale"] = stale

    disks = [d for d in (disk(Path("/")), disk(s.backup_dir) if s.backup_dir.exists() else None) if d]
    disks = list({d["total"]: d for d in disks}.values())
    full = any(d["pct"] >= DISK_WARN for d in disks)
    if full and not alerts.get("disk"):
        d = max(disks, key=lambda d: d["pct"])
        notify(db, f"Schijf van de homepage is {d['pct']:.0f}% vol", f"{d['path']}: nog {d['free'] // 2**20} MB vrij",
               level="warn", source="homepage")
    alerts["disk"] = full

    offsite = {"enabled": offsite_on, "dir": str(s.offsite_dir), "error": None}
    if offsite_on:
        ks = await db.get(AppState, KEY_STATE)
        blob = ks.value.get("blob") if ks else None
        try:
            offsite.update(await asyncio.to_thread(offsite_copy, s.backup_dir, s.offsite_dir, blob, now))
            offsite["at"] = now.isoformat()
            if not blob:
                offsite["error"] = "sleutel nog niet meegekopieerd: stel een wachtzin in"
        except OSError as e:
            offsite["error"] = str(e)[:300]
            offsite["at"] = (prev.get("offsite") or {}).get("at")
        err = offsite["error"] if offsite.get("count") is None else None
        if err and alerts.get("offsite") != err:
            notify(db, "Kopie van de back-up buiten de container mislukt", err, level="warn", source="homepage")
        elif not err and alerts.get("offsite"):
            event(db, "gezondheid", "Kopie van de back-up buiten de container lukt weer", level="ok")
        alerts["offsite"] = err

    value = {"checked_at": now.isoformat(), "backups": dumps[:14], "backup_dir": str(s.backup_dir),
             "verified": verified, "stale": stale, "db": await db_size(db), "disks": disks, "offsite": offsite,
             "alerts": alerts}
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


def _main(argv: list[str]) -> int:
    import getpass

    if len(argv) != 2 or argv[0] != "decrypt":
        print("gebruik: python -m app.health.selfcheck decrypt secret.key.enc > secret.key", file=sys.stderr)
        return 2
    blob = json.loads(Path(argv[1]).read_text())
    try:
        sys.stdout.write(decrypt_key(blob, getpass.getpass("wachtzin: ")).decode())
    except Exception:
        print("Verkeerde wachtzin of beschadigd bestand.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
