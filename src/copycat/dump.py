"""Versioned, private card dumps. Unknown bytes are never represented as zeros."""

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

FORMAT = "copycat-classic-v1"
CARD_TYPES = {"classic-1k": 16, "classic-4k": 40}
DEFAULT_KEY = "ffffffffffff"
DEFAULT_ACCESS = "ff078069"


class CopycatError(Exception):
    """A user-facing error that contains no credential material."""


def layout(sector: int) -> tuple[int, int]:
    """Return (first block, number of blocks), including 4K's large sectors."""
    return (sector * 4, 4) if sector < 32 else (128 + (sector - 32) * 16, 16)


def access_conditions(access: str) -> list[tuple[int, int, int]]:
    b6, b7, b8, _ = bytes.fromhex(access)
    c1, c2, c3 = b7 >> 4, b8 & 15, b8 >> 4
    if (b6 & 15, b6 >> 4, b7 & 15) != ((~c1) & 15, (~c2) & 15, (~c3) & 15):
        raise CopycatError("Invalid sector access-bit complements")
    return [((c1 >> i) & 1, (c2 >> i) & 1, (c3 >> i) & 1) for i in range(4)]


def key_b_readable(access: str) -> bool:
    return access_conditions(access)[3] in {(0, 0, 0), (0, 0, 1), (0, 1, 0)}


def checked_hex(
    value: object, size: int, name: str, optional: bool = False
) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) != size * 2:
        raise CopycatError(f"Invalid {name} length")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise CopycatError(f"Invalid {name} encoding") from None
    if len(result) != size:
        raise CopycatError(f"Invalid {name} length")
    return result.hex()


@dataclass
class Sector:
    data: list[str | None]
    access: str | None = None
    key_a: str | None = None
    key_b: str | None = None

    @property
    def complete(self) -> bool:
        return all(
            value is not None
            for value in [*self.data, self.access, self.key_a, self.key_b]
        )

    def trailer(self) -> bytes:
        if not self.complete:
            raise CopycatError("Sector is incomplete; cannot reconstruct its trailer")
        return bytes.fromhex(self.key_a + self.access + self.key_b)


@dataclass
class Dump:
    card_type: str
    uid: str
    atr: str
    sectors: list[Sector]

    @property
    def complete(self) -> bool:
        return all(sector.complete for sector in self.sectors)

    @property
    def nonblank(self) -> bool:
        for index, sector in enumerate(self.sectors):
            application = sector.data[1:] if index == 0 else sector.data
            if any(value is None or any(bytes.fromhex(value)) for value in application):
                return True
            if (sector.access, sector.key_a, sector.key_b) != (
                DEFAULT_ACCESS,
                DEFAULT_KEY,
                DEFAULT_KEY,
            ):
                return True
        return False

    def require_complete(self) -> None:
        if not self.complete:
            raise CopycatError(
                "Dump is incomplete (unreadable data or unknown keys); refusing to write"
            )
        for sector in self.sectors:
            conditions = access_conditions(sector.access)
            if any(
                condition == (1, 1, 1)
                or (
                    condition in {(0, 1, 1), (1, 0, 1)}
                    and key_b_readable(sector.access)
                )
                for condition in conditions[:3]
            ):
                raise CopycatError(
                    "Dump access settings would prevent complete read-back verification"
                )
        manufacturer = bytes.fromhex(self.sectors[0].data[0])
        if (
            manufacturer[:4].hex() != self.uid
            or manufacturer[4]
            != manufacturer[0] ^ manufacturer[1] ^ manufacturer[2] ^ manufacturer[3]
        ):
            raise CopycatError(
                "Manufacturer block does not match the dump's UID/check byte"
            )


def load_dump(path: Path) -> Dump:
    try:
        obj = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeError):
        raise CopycatError("Invalid dump JSON") from None
    if not isinstance(obj, dict) or obj.get("format") != FORMAT:
        raise CopycatError(
            "Unsupported dump format; create a fresh dump with 'copycat read'"
        )
    card_type = obj.get("card_type")
    if not isinstance(card_type, str) or card_type not in CARD_TYPES:
        raise CopycatError("Unsupported card type in dump")
    uid = checked_hex(obj.get("uid"), 4, "UID")
    atr = checked_hex(obj.get("atr"), 20, "ATR")
    expected_id = "0001" if card_type == "classic-1k" else "0002"
    if atr[14:24] != "a000000306" or atr[24:26] != "03" or atr[26:30] != expected_id:
        raise CopycatError("ATR does not match the dump's card type")
    raw_sectors = obj.get("sectors")
    if not isinstance(raw_sectors, list) or len(raw_sectors) != CARD_TYPES[card_type]:
        raise CopycatError("Invalid sector count")
    sectors = []
    for index, raw in enumerate(raw_sectors):
        if not isinstance(raw, dict):
            raise CopycatError("Invalid sector record")
        data = raw.get("data")
        if not isinstance(data, list) or len(data) != layout(index)[1] - 1:
            raise CopycatError("Invalid sector data-block count")
        sector = Sector(
            data=[checked_hex(value, 16, "block", optional=True) for value in data],
            access=checked_hex(raw.get("access"), 4, "access bytes", optional=True),
            key_a=checked_hex(raw.get("key_a"), 6, "Key A", optional=True),
            key_b=checked_hex(raw.get("key_b"), 6, "Key B", optional=True),
        )
        if sector.access is not None:
            access_conditions(sector.access)
        sectors.append(sector)
    return Dump(card_type, uid, atr, sectors)


def save_dump(path: Path, dump: Dump) -> None:
    """Never overwrite another dump, follow a symlink, or create a world-readable file."""
    content = json.dumps({"format": FORMAT, **asdict(dump)}, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
