"""Wake-on-LAN: een magic packet sturen naar een machine die uit staat."""

import re
import socket

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})(\2[0-9A-Fa-f]{2}){4}$")


def normalize_mac(mac: str) -> str | None:
    mac = (mac or "").strip()
    if not MAC_RE.match(mac):
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def magic_packet(mac: str) -> bytes:
    norm = normalize_mac(mac)
    if norm is None:
        raise ValueError("Ongeldig MAC-adres")
    return b"\xff" * 6 + bytes.fromhex(norm.replace(":", "")) * 16


def send(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Een paar keer: UDP kan verloren gaan en kost niets.
        for _ in range(3):
            s.sendto(packet, (broadcast, port))
