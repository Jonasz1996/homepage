"""Accountherstel ("Kan niet inloggen?"): de code die de inlogpagina toont en homepage-beheer herstel <code> inleest.

De code is een willekeurig token dat de server uitgeeft voor een openstaand verzoek (tabel herstel_verzoeken, alleen
de sha256 ervan). De opgegeven login zit in dat verzoek, niet in de code zelf: niemand kan dus zelf een code voor een
andere naam verzinnen, en een code geldt maar één keer en maar zo lang als VERZOEK_GELDIG.
"""

import hashlib
import re
import secrets
from datetime import timedelta

# Zonder tekens die je verwart (0/O, 1/l/I): de code wordt voorgelezen of overgetypt.
TEKENS = "abcdefghjkmnpqrstuvwxyz23456789"
PREFIX = "HR"
# Hoe lang de gebruiker heeft om de code bij de beheerder te krijgen; het tijdelijke wachtwoord geldt daarna 1 uur.
VERZOEK_GELDIG = timedelta(hours=24)
# Zoveel openstaande verzoeken hoogstens: wie de pagina blijft aanroepen, verdringt enkel de oudste.
MAX_OPEN = 50

_CODE = re.compile(rf"^{PREFIX}(?:-?[{TEKENS}]{{4}}){{4}}$", re.IGNORECASE)


def groepjes(n: int = 4) -> str:
    """Vier groepjes van vier, bv. k7mq-x2fa-9tbe-hw4r: ruim 78 bits."""
    return "-".join("".join(secrets.choice(TEKENS) for _ in range(4)) for _ in range(n))


def nieuwe_code() -> str:
    return f"{PREFIX}-{groepjes().upper()}"


def is_code(tekst: str) -> bool:
    return bool(_CODE.match(tekst.strip().replace(" ", "")))


def code_hash(code: str) -> str:
    """Hoofdletters, spaties en streepjes tellen niet: zo werkt de code ook als de beheerder ze anders overtypt."""
    kern = re.sub(r"[\s-]", "", code).upper()
    return hashlib.sha256(kern.encode()).hexdigest()
