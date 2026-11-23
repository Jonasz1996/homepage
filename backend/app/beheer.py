"""Beheer vanaf de commandoregel in de container, voor als je niet meer binnen raakt (2FA-app kwijt, wachtwoord
vergeten) of alles wil wissen zonder de browser. Wie in de container root is, mag dit: zo iemand kan de database toch
al lezen en wijzigen.

Gebruik (als root, via deploy/beheer.sh = homepage-beheer, dat de juiste gebruiker en instellingen kiest):
  homepage-beheer gebruikers
  homepage-beheer herstel <code>        kan niet meer inloggen: de code die de inlogpagina toonde (Wachtwoord vergeten
                                        of kan niet inloggen?). 2FA uit, alle sessies weg en een tijdelijk wachtwoord
                                        (1 uur geldig). Daarmee inloggen, een eigen wachtwoord kiezen en 2FA opnieuw
                                        instellen. Een gebruikersnaam in plaats van de code kan ook
  homepage-beheer 2fa-reset [naam]      2FA uit en alle sessies weg: daarna inloggen met je wachtwoord en 2FA opnieuw
                                        instellen (QR-code)
  homepage-beheer wachtwoord [naam]     een nieuw wachtwoord (minstens 12 tekens), alle sessies weg
  homepage-beheer fabrieksreset         alles wissen zoals Instellingen → Fabrieksreset (vraagt WIS ALLES)
"""

import argparse
import asyncio
import getpass
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from .config import get_settings
from .db import get_maker
from . import herstel as herstel_code
from .models import AuditLog, HerstelVerzoek, Session, User

ZIN = "WIS ALLES"


async def _user(db, naam: str | None) -> User:
    users = (await db.execute(select(User).order_by(User.id))).scalars().all()
    if not users:
        raise SystemExit("Er is nog geen account: open het dashboard en maak er een aan (setup-code: "
                         f"{get_settings().setup_token_file}).")
    if naam is None:
        if len(users) > 1:
            raise SystemExit("Meer dan één account: geef de naam mee (homepage-beheer gebruikers).")
        return users[0]
    for u in users:
        if u.username == naam:
            return u
    for u in users:  # inloggen kijkt ook niet naar hoofdletters
        if u.username.lower() == naam.lower():
            return u
    raise SystemExit(f"Geen account {naam!r}. Bestaande: {', '.join(u.username for u in users)}")


def _audit(db, user: User | None, action: str, **detail) -> None:
    db.add(AuditLog(user_id=user.id if user else None, action=action, detail={**detail, "cli": True}, ip=None))


async def gebruikers() -> int:
    async with get_maker()() as db:
        for u in (await db.execute(select(User).order_by(User.id))).scalars():
            extra = "\ttijdelijk wachtwoord" if u.password_temp_until else ""
            print(f"{u.username}\t2FA {'aan' if u.totp_enabled else 'uit'}\tlaatst ingelogd {u.last_login_at or '-'}{extra}")
    return 0


async def tfa_reset(naam: str | None) -> int:
    from .deps import notify

    async with get_maker()() as db:
        user = await _user(db, naam)
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_last_step = None
        n = (await db.execute(delete(Session).where(Session.user_id == user.id))).rowcount
        _audit(db, user, "2fa-reset")
        notify(db, "2FA gewist vanaf de commandoregel",
               f"2FA van {user.username} is uitgezet in de container (homepage-beheer); {n} sessies zijn afgemeld. "
               "Log in met je wachtwoord en stel 2FA opnieuw in.", level="warn", source="auth")
        await db.commit()
    print(f"2FA van {user.username} staat uit en {n} sessies zijn afgemeld.")
    print("Open het dashboard, log in met je wachtwoord en scan de nieuwe QR-code. Tot dan werkt het dashboard ook")
    print("zonder login niet (dat vraagt een account met 2FA).")
    return 0


async def wachtwoord(naam: str | None) -> int:
    from .security import hash_password_async

    async with get_maker()() as db:
        user = await _user(db, naam)
        pw = getpass.getpass(f"Nieuw wachtwoord voor {user.username} (minstens 12 tekens): ")
        if len(pw) < 12 or len(pw) > 256:
            raise SystemExit("Minstens 12 en hoogstens 256 tekens.")
        if getpass.getpass("Nog eens: ") != pw:
            raise SystemExit("Niet gelijk, er is niets veranderd.")
        user.password_hash = await hash_password_async(pw)
        user.password_temp_until = None
        n = (await db.execute(delete(Session).where(Session.user_id == user.id))).rowcount
        _audit(db, user, "wachtwoord", cli=True)
        await db.commit()
    print(f"Nieuw wachtwoord voor {user.username}; {n} sessies zijn afgemeld (bekende toestellen ook).")
    return 0


def tijdelijk_wachtwoord() -> str:
    """Vier groepjes van vier, bv. k7mq-x2fa-9tbe-hw4r: 19 tekens, ruim 78 bits."""
    return herstel_code.groepjes()


async def _uit_code(db, code: str) -> tuple[User, HerstelVerzoek]:
    """Het openstaande verzoek van de inlogpagina bij deze code, en het account van de login die erin staat."""
    v = (await db.execute(select(HerstelVerzoek).where(HerstelVerzoek.code_hash == herstel_code.code_hash(code))
                          )).scalar_one_or_none()
    if v is None or v.used_at is not None:
        raise SystemExit("Deze code is onbekend of al gebruikt. Laat de gebruiker op de inlogpagina een nieuwe vragen "
                         "(Wachtwoord vergeten of kan niet inloggen?).")
    if v.expires_at.replace(tzinfo=v.expires_at.tzinfo or timezone.utc) < datetime.now(timezone.utc):
        raise SystemExit("Deze code is verlopen. Laat de gebruiker op de inlogpagina een nieuwe vragen.")
    user = await db.get(User, v.user_id) if v.user_id else None
    if user is None:
        namen = ", ".join(u.username for u in (await db.execute(select(User).order_by(User.id))).scalars())
        raise SystemExit(f"Deze code is gevraagd voor {v.login!r}, maar dat account bestaat niet. Bestaande: "
                         f"{namen or '-'}. Laat de gebruiker een nieuwe code vragen met de juiste gebruikersnaam.")
    return user, v


async def herstel(code_of_naam: str | None, uren: int = 1) -> int:
    """Accountherstel: 2FA uit, alle sessies en gsm's afgemeld, en een tijdelijk wachtwoord dat maar `uren` geldig is.
    Wie ermee inlogt, moet eerst een eigen wachtwoord kiezen en dan 2FA opnieuw instellen. Normaal met de code van de
    inlogpagina (HR-...): de login staat in dat verzoek. Een naam (of niets, bij één account) kan ook."""
    from .deps import notify
    from .monitoring import webpush
    from .security import hash_password_async

    if not 1 <= uren <= 168:
        raise SystemExit("--uren moet tussen 1 en 168 liggen.")
    pw = tijdelijk_wachtwoord()
    async with get_maker()() as db:
        verzoek = None
        if code_of_naam and herstel_code.is_code(code_of_naam):
            user, verzoek = await _uit_code(db, code_of_naam)
            verzoek.used_at = datetime.now(timezone.utc)
        else:
            user = await _user(db, code_of_naam)
        user.password_hash = await hash_password_async(pw)
        user.password_temp_until = datetime.now(timezone.utc) + timedelta(hours=uren)
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_last_step = None
        n = (await db.execute(delete(Session).where(Session.user_id == user.id))).rowcount
        # Andere openstaande codes voor dit account vervallen: elke code geeft hoogstens één keer een wachtwoord.
        await db.execute(delete(HerstelVerzoek).where(HerstelVerzoek.user_id == user.id,
                                                      HerstelVerzoek.used_at.is_(None)))
        await webpush.forget_renew(db, user.id)
        _audit(db, user, "herstel", uren=uren, met_code=verzoek is not None,
               **({"aangevraagd_vanaf": verzoek.ip} if verzoek else {}))
        notify(db, "Account hersteld vanaf de commandoregel",
               f"{user.username} kreeg in de container (homepage-beheer herstel) een tijdelijk wachtwoord, 2FA staat "
               f"uit en {n} sessies zijn afgemeld. Was jij dit niet, voer het commando dan zelf opnieuw uit.",
               level="warn", source="auth")
        await db.commit()
    print(f"Account {user.username} is hersteld: 2FA staat uit en {n} sessies zijn afgemeld.")
    if verzoek is not None:
        print(f"(code gevraagd op {verzoek.created_at.astimezone():%d/%m/%Y %H:%M} vanaf {verzoek.ip or '?'})")
    print()
    print(f"  Tijdelijk wachtwoord: {pw}")
    print(f"  Geldig tot: {user.password_temp_until.astimezone():%d/%m/%Y %H:%M}")
    print()
    print("Geef dit door aan de gebruiker. Die logt ermee in op de inlogpagina, kiest een eigen wachtwoord en scant")
    print("daarna een nieuwe QR-code met de authenticator-app (2FA). Het oude wachtwoord werkt niet meer.")
    return 0


async def fabrieksreset(ja: bool) -> int:
    from .routers.fabrieksreset import wipe

    if not ja:
        print("Dit wist ALLES in de database van het dashboard: tegels, pagina's, API's en geheimen, SSH, cronjobs,")
        print("geschiedenis, meldingen, instellingen, de achtergrond en het account. De dagelijkse back-ups en")
        print("/etc/homepage blijven. Maak eerst een back-up als je wil terug kunnen (homepage-backup).")
        if input(f"Typ {ZIN} om verder te gaan: ").strip().upper() != ZIN:
            print("Niets gewist.")
            return 1
    async with get_maker()() as db:
        await wipe(db)
        _audit(db, None, "fabrieksreset", door="commandoregel")
        await db.commit()
    print("Alles gewist. Open het dashboard en maak opnieuw een account aan.")
    try:
        code = get_settings().setup_token_file.read_text().strip()
        print(f"Setup-code: {code}")
    except OSError:
        print(f"De setup-code staat in {get_settings().setup_token_file}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="homepage-beheer", description="Beheer van het dashboard in de container.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gebruikers", help="de accounts en of 2FA aan staat")
    s = sub.add_parser("herstel", help="kan niet inloggen: 2FA uit en een tijdelijk wachtwoord")
    s.add_argument("code", nargs="?", metavar="code|naam",
                   help="de code van de inlogpagina (HR-...), of een gebruikersnaam")
    s.add_argument("--uren", type=int, default=1, help="hoe lang het tijdelijke wachtwoord geldt, in uren (standaard 1)")
    s = sub.add_parser("2fa-reset", help="2FA uit en alle sessies weg (2FA-app kwijt)")
    s.add_argument("naam", nargs="?")
    s = sub.add_parser("wachtwoord", help="een nieuw wachtwoord instellen")
    s.add_argument("naam", nargs="?")
    s = sub.add_parser("fabrieksreset", help="alles wissen, terug naar de eerste start")
    s.add_argument("--ja", action="store_true", help="niet om WIS ALLES vragen")
    a = p.parse_args(argv)
    if a.cmd == "gebruikers":
        return asyncio.run(gebruikers())
    if a.cmd == "herstel":
        return asyncio.run(herstel(a.code, a.uren))
    if a.cmd == "2fa-reset":
        return asyncio.run(tfa_reset(a.naam))
    if a.cmd == "wachtwoord":
        return asyncio.run(wachtwoord(a.naam))
    return asyncio.run(fabrieksreset(a.ja))


if __name__ == "__main__":
    sys.exit(main())
