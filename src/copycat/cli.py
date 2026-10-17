"""The two user-facing modes: read and write."""

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from smartcard.Exceptions import NoCardException, SmartcardException

from copycat.dump import CopycatError, checked_hex, load_dump, save_dump
from copycat.operations import plan_writes, restore
from copycat.reader import DEFAULT_KEYS, Card, capture


def candidate_keys(path: Path | None) -> list[bytes]:
    keys = []
    if path is not None:
        for line in path.read_text().splitlines():
            value = line.partition("#")[0].strip()
            if value:
                keys.append(bytes.fromhex(checked_hex(value, 6, "key-file entry")))
    return list(dict.fromkeys([*keys, *DEFAULT_KEYS]))


def backup_path() -> Path:
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    directory = root / "copycat/cards"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return directory / f"before-write-{timestamp}.json"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read/restore authorized MIFARE Classic 1K/4K cards."
    )
    modes = parser.add_subparsers(dest="mode", required=True)
    for name, help_text in (
        ("read", "Save readable memory and known keys to a private JSON dump"),
        ("write", "Restore a complete dump and verify the target"),
    ):
        mode = modes.add_parser(name, help=help_text)
        mode.add_argument(
            "file", type=Path, help="Dump path (read never overwrites an existing file)"
        )
        mode.add_argument(
            "--keys",
            type=Path,
            help="Additional known keys: one 12-hex-digit key per line",
        )
    args = parser.parse_args(argv)
    try:
        keys = candidate_keys(args.keys)
        if args.mode == "read":
            if args.file.exists() or args.file.is_symlink():
                raise CopycatError("Output already exists; choose a new filename")
            with Card() as card:
                dump = capture(card, keys, print)
            save_dump(args.file, dump)
            print(f"Saved private dump: {args.file}")
            if not dump.complete:
                print(
                    "Incomplete: unknown data/keys are marked null. This dump cannot be written."
                )
                return 2
            dump.require_complete()
            print(
                "Complete logical-memory dump, including sector keys. Keep it private."
            )
            return 0

        source = load_dump(args.file)
        source.require_complete()  # Reject malformed/incomplete input before opening a reader.
        keys = list(
            dict.fromkeys(
                [
                    *(
                        bytes.fromhex(key)
                        for sector in source.sectors
                        for key in (sector.key_a, sector.key_b)
                    ),
                    *keys,
                ]
            )
        )
        with Card() as card:
            if card.card_type != source.card_type:
                raise CopycatError("Source and target card capacities/types must match")
            target = capture(card, keys, print)
            if target.nonblank:
                print(
                    "WARNING: target contains application data, nondefault security settings, or unreadable fields."
                )
            target.require_complete()
            writes = plan_writes(source, target)
            if not writes:
                print("UID and logical memory already match; no writes needed.")
                return 0
            if any(item.block == 0 for item in writes):
                print(
                    "Will copy UID/manufacturer block. Requires a compatible CUID-writable card;"
                )
                print("incompatible identification bytes can make the target unusable.")
            print(
                f"Planned writes: {len(writes)} blocks. Failure may leave a partial copy."
            )
            if (
                target.nonblank
                and input("Type WRITE to overwrite this card: ").strip() != "WRITE"
            ):
                print("Cancelled; no card writes performed.")
                return 1
            backup = backup_path()
            save_dump(backup, target)
            print(f"Private pre-write backup: {backup}")
            restore(card, source, target, writes, print)
        print("Verified UID and all logical data/security fields after reset.")
        print(
            "This does not guarantee identical silicon behavior or acceptance by an access system."
        )
        return 0
    except NoCardException:
        print(
            "Error: no card detected. Place one card flat on the ACR122U.",
            file=sys.stderr,
        )
    except SmartcardException:
        print(
            "Error: PC/SC communication failed. Check the reader, card and pcscd.",
            file=sys.stderr,
        )
    except (CopycatError, OSError, UnicodeError) as error:
        # Key/dump validation errors never echo input values or key material.
        print(f"Error: {error}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print(
            "Stopped. If writing had started, the card may be partially changed.",
            file=sys.stderr,
        )
    return 1
