"""PC/SC commands and bounded known-key inspection; no key recovery."""

from smartcard.scard import SCARD_UNPOWER_CARD
from smartcard.System import readers

from copycat.dump import (
    CARD_TYPES,
    CopycatError,
    Dump,
    Sector,
    access_conditions,
    key_b_readable,
    layout,
)

DEFAULT_KEYS = tuple(
    bytes.fromhex(key)
    for key in (
        "FFFFFFFFFFFF",
        "A0A1A2A3A4A5",
        "D3F7D3F7D3F7",
        "000000000000",
        "B0B1B2B3B4B5",
        "AABBCCDDEEFF",
        "4D3A99C351DD",
        "1A982C7E459A",
        "A0478CC39091",
        "533CB6C723F6",
        "8FD0A4F256E9",
        "0004A2B3C4D5",
        "0123456789AB",
        "123456789ABC",
        "ABCDEF123456",
        "714C5C886E97",
        "587EE5F9350F",
        "A22AE129C013",
        "123456ABCDEF",
        "ABCDEFABCDEF",
        "010203040506",
        "111111111111",
        "222222222222",
        "484558414354",
    )
)


class Card:
    def __init__(self):
        available = [reader for reader in readers() if "ACR122U" in str(reader)]
        if len(available) != 1:
            raise CopycatError(
                "Expected one ACR122U reader; check USB, pcscd and kernel NFC drivers"
            )
        self.connection = available[0].createConnection()

    def __enter__(self):
        try:
            self.connection.connect(disposition=SCARD_UNPOWER_CARD)
            self.uid = self.read_uid()
            self.atr = bytes(self.connection.getATR())
            types = {b"\x00\x01": "classic-1k", b"\x00\x02": "classic-4k"}
            if len(self.uid) != 4:
                raise CopycatError("Only 4-byte-UID MIFARE Classic cards are supported")
            if (
                len(self.atr) != 20
                or self.atr[7:13] != bytes.fromhex("a00000030603")
                or self.atr[13:15] not in types
            ):
                raise CopycatError("Card is not identified as MIFARE Classic 1K/4K")
            self.card_type = types[self.atr[13:15]]
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.connection.disconnect()

    def command(self, apdu):
        data, sw1, sw2 = self.connection.transmit(apdu)
        return bytes(data), (sw1 << 8) | sw2

    def read_uid(self) -> bytes:
        data, status = self.command([0xFF, 0xCA, 0, 0, 0])
        if status != 0x9000:
            raise CopycatError("Reader could not retrieve the card UID")
        return data

    def check_identity(self):
        if self.read_uid() != self.uid:
            raise CopycatError("Card changed during operation; stopped")

    def reset(self, expected_uid: bytes | None = None):
        self.connection.disconnect()
        self.connection.connect(disposition=SCARD_UNPOWER_CARD)
        expected = self.uid if expected_uid is None else expected_uid
        if self.read_uid() != expected:
            raise CopycatError("Unexpected card UID after reset; stopped")
        self.uid = expected
        self.atr = bytes(self.connection.getATR())

    def authenticate(self, sector: int, key: bytes, key_type: str) -> bool:
        self.reset()
        _, status = self.command([0xFF, 0x82, 0, 0, 6, *key])
        if status != 0x9000:
            raise CopycatError("Reader rejected volatile key loading")
        first, _ = layout(sector)
        _, status = self.command(
            [0xFF, 0x86, 0, 0, 5, 1, 0, first, 0x60 if key_type == "a" else 0x61, 0]
        )
        if status == 0x9000:
            return True
        if status in {0x6300, 0x6982, 0x6985}:
            return False
        raise CopycatError(f"Unexpected authentication status: {status:04X}")

    def read(self, block: int) -> bytes | None:
        data, status = self.command([0xFF, 0xB0, 0, block, 16])
        if status == 0x9000 and len(data) == 16:
            return data
        if status in {0x6300, 0x6982, 0x6985}:
            return None
        raise CopycatError(f"Unexpected read response at block {block}: {status:04X}")

    def write(self, block: int, data: bytes):
        self.check_identity()
        _, status = self.command([0xFF, 0xD6, 0, block, 16, *data])
        if status != 0x9000:
            raise CopycatError(
                f"Write rejected at block {block}: {status:04X}; no automatic retry"
            )


def capture(card: Card, keys: list[bytes], progress=lambda _: None) -> Dump:
    candidates = list(dict.fromkeys(keys))
    sectors = []
    for index in range(CARD_TYPES[card.card_type]):
        first, count = layout(index)
        sector = Sector([None] * (count - 1))
        for key_type in ("a", "b"):
            if sector.complete:
                break
            for key in candidates:
                if not card.authenticate(index, key, key_type):
                    continue
                setattr(sector, "key_" + key_type, key.hex())
                # A failed read can invalidate authentication on some readers.
                # Re-authenticate each block instead of misclassifying later reads.
                for offset in range(count - 1):
                    if sector.data[offset] is None:
                        if not card.authenticate(index, key, key_type):
                            raise CopycatError(
                                "Authentication became inconsistent during capture"
                            )
                        data = card.read(first + offset)
                        if data is not None:
                            sector.data[offset] = data.hex()
                if not card.authenticate(index, key, key_type):
                    raise CopycatError(
                        "Authentication became inconsistent during capture"
                    )
                trailer = card.read(first + count - 1)
                if trailer is not None:
                    sector.access = trailer[6:10].hex()
                    access_conditions(sector.access)
                    if key_type == "a" and key_b_readable(sector.access):
                        sector.key_b = trailer[10:].hex()
                break
        sectors.append(sector)
        readable = sum(data is not None for data in sector.data)
        progress(
            f"Sector {index:02}: {readable}/{count - 1} data blocks; "
            + ("complete" if sector.complete else "incomplete data/security fields")
        )
    card.check_identity()
    return Dump(card.card_type, card.uid.hex(), card.atr.hex(), sectors)
