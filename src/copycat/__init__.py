from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.System import readers

GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]


def find_reader(name: str = "ACR122U"):
    for reader in readers():
        if name in str(reader):
            return reader
    raise RuntimeError(f"No {name} reader found (is pcscd running and pn533 blacklisted?)")


def read_uid(timeout: int = 10) -> tuple[bytes, bytes]:
    """Wait for a card on the ACR122U and return (uid, atr)."""
    reader = find_reader()
    service = CardRequest(readers=[reader], timeout=timeout).waitforcard()
    conn = service.connection
    conn.connect()
    try:
        data, sw1, sw2 = conn.transmit(GET_UID)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"GET UID failed: SW={sw1:02X}{sw2:02X}")
        return bytes(data), bytes(conn.getATR())
    finally:
        conn.disconnect()


def main() -> None:
    print(f"Reader: {find_reader()}")
    print("Place a card on the reader...")
    try:
        uid, atr = read_uid()
    except CardRequestTimeoutException:
        print("No card detected.")
        return
    print(f"UID: {uid.hex(':').upper()}")
    print(f"ATR: {atr.hex(' ').upper()}")
