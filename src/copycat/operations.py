"""Plan writes before touching a card, then verify logical memory after reset."""

from dataclasses import dataclass

from smartcard.Exceptions import SmartcardException

from copycat.dump import (
    CopycatError,
    Dump,
    Sector,
    access_conditions,
    key_b_readable,
    layout,
)
from copycat.reader import Card, capture


@dataclass
class Write:
    sector: int
    block: int
    data: bytes
    key_type: str
    key: bytes


def write_key(sector: Sector, offset: int, count: int) -> tuple[str, bytes]:
    conditions = access_conditions(sector.access)
    if offset == count - 1:
        # Require permission to write all fields, not just part of the trailer.
        allowed = {(0, 0, 1): ("a",), (0, 1, 1): ("b",)}.get(conditions[3], ())
    else:
        group = offset if count == 4 else offset // 5
        allowed = {
            (0, 0, 0): ("a", "b"),
            (1, 0, 0): ("b",),
            (1, 1, 0): ("b",),
            (0, 1, 1): ("b",),
        }.get(conditions[group], ())
    for key_type in allowed:
        if key_type == "b" and key_b_readable(sector.access):
            continue  # A readable Key B is data, not an authentication key.
        key = getattr(sector, "key_" + key_type)
        if key is not None:
            return key_type, bytes.fromhex(key)
    raise CopycatError("Target access settings do not permit a safe complete write")


def plan_writes(source: Dump, target: Dump) -> list[Write]:
    source.require_complete()
    target.require_complete()
    if source.card_type != target.card_type:
        raise CopycatError("Source and target card capacities/types must match")
    writes = []
    for index, (new, old) in enumerate(zip(source.sectors, target.sectors)):
        first, count = layout(index)
        # Data before its trailer; new keys/access settings take effect last.
        for offset, (new_data, old_data) in enumerate(zip(new.data, old.data)):
            if new_data != old_data:
                key_type, key = write_key(old, offset, count)
                writes.append(
                    Write(index, first + offset, bytes.fromhex(new_data), key_type, key)
                )
        if new.trailer() != old.trailer():
            key_type, key = write_key(old, count - 1, count)
            writes.append(Write(index, first + count - 1, new.trailer(), key_type, key))
    # Test ordinary CUID block-0 writing before modifying other blocks. No
    # proprietary unlock/backdoor commands and no automatic retries are used.
    return sorted(writes, key=lambda item: item.block != 0)


def restore(
    card: Card, source: Dump, target: Dump, writes: list[Write], progress=lambda _: None
):
    if card.uid.hex() != target.uid:
        raise CopycatError("Target identity changed before restore")
    checked = set()
    for item in writes:
        identity = (item.sector, item.key_type, item.key)
        if identity not in checked:
            if not card.authenticate(item.sector, item.key, item.key_type):
                raise CopycatError(
                    "Pre-write authentication failed; no writes attempted"
                )
            checked.add(identity)
    started = False
    try:
        for item in writes:
            if not card.authenticate(item.sector, item.key, item.key_type):
                raise CopycatError("Authentication failed before a planned write")
            started = True
            card.write(item.block, item.data)
            if item.block == 0:
                card.reset(bytes.fromhex(source.uid))
                if not card.authenticate(item.sector, item.key, item.key_type):
                    raise CopycatError(
                        "Authentication failed after manufacturer-block write"
                    )
            if (
                item.block != layout(item.sector)[0] + layout(item.sector)[1] - 1
                and card.read(item.block) != item.data
            ):
                raise CopycatError(f"Immediate read-back failed at block {item.block}")
            progress(f"Wrote block {item.block}")
        card.reset(bytes.fromhex(source.uid))
        keys = list(
            dict.fromkeys(
                bytes.fromhex(key)
                for sector in source.sectors
                for key in (sector.key_a, sector.key_b)
            )
        )
        observed = capture(card, keys)
        if observed.uid != source.uid or observed.sectors != source.sectors:
            raise CopycatError("Final UID/data/security verification failed")
        if observed.atr != source.atr:
            progress(
                "Warning: ATR differs; logical memory matches but chip behavior may differ"
            )
    except (CopycatError, SmartcardException) as error:
        if started:
            reason = (
                str(error)
                if isinstance(error, CopycatError)
                else "PC/SC communication failed"
            )
            raise CopycatError(
                "Restore stopped; the card may be partially changed. "
                f"{reason}. Keep the pre-write backup; no automatic rollback was attempted."
            ) from error
        raise
