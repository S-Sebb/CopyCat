import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from copycat import cli
from copycat.dump import (
    CARD_TYPES,
    DEFAULT_ACCESS,
    DEFAULT_KEY,
    CopycatError,
    Dump,
    Sector,
    access_conditions,
    key_b_readable,
    layout,
    load_dump,
    save_dump,
)
from copycat.operations import plan_writes, restore
from copycat.reader import Card, capture


def access(groups):
    c1 = sum(group[0] << i for i, group in enumerate(groups))
    c2 = sum(group[1] << i for i, group in enumerate(groups))
    c3 = sum(group[2] << i for i, group in enumerate(groups))
    return bytes(
        [((~c2 & 15) << 4) | (~c1 & 15), (c1 << 4) | (~c3 & 15), (c3 << 4) | c2, 0x69]
    ).hex()


def image(card_type="classic-1k", uid=b"\x01\x02\x03\x04"):
    atr = bytearray.fromhex(
        "3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A"
    )
    if card_type == "classic-4k":
        atr[14] = 2
        atr[-1] ^= 3
    sectors = [
        Sector(
            [bytes(16).hex()] * (layout(i)[1] - 1),
            DEFAULT_ACCESS,
            DEFAULT_KEY,
            DEFAULT_KEY,
        )
        for i in range(CARD_TYPES[card_type])
    ]
    bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
    sectors[0].data[0] = (uid + bytes([bcc, 8, 4, 0]) + bytes(8)).hex()
    return Dump(card_type, uid.hex(), atr.hex(), sectors)


class FakeReader:
    """PC/SC fake with real key masking, ACLs and reset/authentication state."""

    def __init__(self, dump, writable_uid=True):
        self.memory = []
        for sector in dump.sectors:
            self.memory.extend(bytes.fromhex(data) for data in sector.data)
            self.memory.append(sector.trailer())
        self.atr = bytes.fromhex(dump.atr)
        self.connected = False
        self.auth = None
        self.key = None
        self.writes = []
        self.commands = []
        self.writable_uid = writable_uid
        self.fail_block = None
        self.refuse_read = None
        self.alternate_uid = None
        self.fail_after_trailer = False

    def __str__(self):
        return "ACS ACR122U PICC Interface 00 00"

    def createConnection(self):
        return self

    def connect(self, disposition=None):
        self.connected = True
        self.auth = None

    def disconnect(self):
        self.connected = False
        self.auth = None

    def getATR(self):
        return list(self.atr)

    @staticmethod
    def location(block):
        sector = block // 4 if block < 128 else 32 + (block - 128) // 16
        first, count = layout(sector)
        return sector, first, count, block - first

    def transmit(self, apdu):
        self.commands.append(apdu)
        if not self.connected:
            raise AssertionError("Command on disconnected reader")
        ins = apdu[1]
        if ins == 0xCA:
            return list(self.alternate_uid or self.memory[0][:4]), 0x90, 0
        if ins == 0x82:
            self.key = bytes(apdu[5:])
            return [], 0x90, 0
        if ins == 0x86:
            sector, first, count, _ = self.location(apdu[7])
            trailer = self.memory[first + count - 1]
            kind = "a" if apdu[8] == 0x60 else "b"
            expected = trailer[:6] if kind == "a" else trailer[10:]
            if self.key != expected or (
                kind == "b" and key_b_readable(trailer[6:10].hex())
            ):
                self.auth = None
                return [], 0x63, 0
            self.auth = sector, kind
            return [], 0x90, 0
        block = apdu[3]
        sector, first, count, offset = self.location(block)
        if self.auth is None or self.auth[0] != sector:
            return [], 0x69, 0x82
        kind = self.auth[1]
        trailer = self.memory[first + count - 1]
        conditions = access_conditions(trailer[6:10].hex())
        group = offset if count == 4 else offset // 5
        if ins == 0xB0:
            if block == self.refuse_read:
                self.auth = None  # Some hardware invalidates auth on denied reads.
                return [], 0x63, 0
            if offset == count - 1:
                allowed = "a" if key_b_readable(trailer[6:10].hex()) else "ab"
                if kind not in allowed:
                    return [], 0x69, 0x82
                data = bytes(6) + trailer[6:10]
                data += (
                    trailer[10:]
                    if kind == "a" and key_b_readable(trailer[6:10].hex())
                    else bytes(6)
                )
            else:
                permitted = {
                    (0, 0, 0): "ab",
                    (0, 1, 0): "ab",
                    (1, 0, 0): "ab",
                    (1, 1, 0): "ab",
                    (0, 0, 1): "ab",
                    (0, 1, 1): "b",
                    (1, 0, 1): "b",
                    (1, 1, 1): "",
                }
                if kind not in permitted[conditions[group]]:
                    self.auth = None
                    return [], 0x69, 0x82
                data = self.memory[block]
            return list(data), 0x90, 0
        if ins == 0xD6:
            if block == self.fail_block or (block == 0 and not self.writable_uid):
                return [], 0x63, 0
            if offset == count - 1:
                allowed = {(0, 0, 1): "a", (0, 1, 1): "b"}.get(conditions[3], "")
            else:
                allowed = {
                    (0, 0, 0): "ab",
                    (1, 0, 0): "b",
                    (1, 1, 0): "b",
                    (0, 1, 1): "b",
                }.get(conditions[group], "")
            if kind not in allowed:
                return [], 0x69, 0x82
            self.memory[block] = bytes(apdu[5:])
            self.writes.append(block)
            if self.fail_after_trailer and offset == count - 1:
                self.memory[block] = bytes(16)
            return [], 0x90, 0
        raise AssertionError("Unexpected APDU")


class DumpTests(unittest.TestCase):
    def test_layout(self):
        self.assertEqual(layout(31), (124, 4))
        self.assertEqual(layout(32), (128, 16))
        self.assertEqual(layout(39), (240, 16))

    def test_access_bit_round_trip(self):
        for value in range(8):
            group = (value >> 2, (value >> 1) & 1, value & 1)
            self.assertEqual(access_conditions(access([group] * 4)), [group] * 4)
        self.assertEqual(
            access_conditions(DEFAULT_ACCESS), [(0, 0, 0)] * 3 + [(0, 0, 1)]
        )
        with self.assertRaises(CopycatError):
            access_conditions("00000000")

    def test_private_round_trip_and_no_overwrite(self):
        for kind in CARD_TYPES:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "card.json"
                original = image(kind)
                save_dump(path, original)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(load_dump(path), original)
                with self.assertRaises(FileExistsError):
                    save_dump(path, original)

    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "link.json"
            destination = Path(tmp) / "missing.json"
            path.symlink_to(destination)
            with self.assertRaises(FileExistsError):
                save_dump(path, image())
            self.assertFalse(destination.exists())

    def test_null_is_incomplete_not_zero(self):
        dump = image()
        dump.sectors[1].data[0] = None
        self.assertFalse(dump.complete)
        self.assertTrue(dump.nonblank)
        with self.assertRaises(CopycatError):
            dump.require_complete()

    def test_bad_uid_or_bcc_rejected(self):
        dump = image()
        dump.uid = "11223344"
        with self.assertRaises(CopycatError):
            dump.require_complete()

    def test_unverifiable_access_settings_rejected(self):
        for group in ((1, 1, 1), (0, 1, 1), (1, 0, 1)):
            dump = image()
            dump.sectors[1].access = access([group] * 3 + [(0, 0, 1)])
            with self.assertRaisesRegex(CopycatError, "read-back verification"):
                dump.require_complete()

    def test_nonblank_excludes_manufacturer(self):
        dump = image()
        self.assertFalse(dump.nonblank)
        dump.sectors[2].data[1] = "01" * 16
        self.assertTrue(dump.nonblank)
        dump = image()
        dump.sectors[0].key_b = "00" * 6
        self.assertTrue(dump.nonblank)

    def test_malformed_dump_rejected_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "card.json"
            save_dump(path, image())
            base = json.loads(path.read_text())
            mutations = [
                lambda obj: obj.update(format="old"),
                lambda obj: obj.update(card_type=[]),
                lambda obj: obj.update(uid="sensitive-invalid-value"),
                lambda obj: obj.update(atr="00" * 20),
                lambda obj: obj.update(sectors=[]),
                lambda obj: obj["sectors"][0].update(key_a="sensitive-invalid-value"),
                lambda obj: obj["sectors"][0].update(data=[]),
                lambda obj: obj["sectors"][0].update(access="00000000"),
            ]
            for mutate in mutations:
                obj = copy.deepcopy(base)
                mutate(obj)
                path.write_text(json.dumps(obj))
                with self.assertRaises(CopycatError) as raised:
                    load_dump(path)
                self.assertNotIn("sensitive", str(raised.exception))


class CardTests(unittest.TestCase):
    def use_card(self, fake):
        return patch("copycat.reader.readers", return_value=[fake])

    def test_complete_capture_never_writes_and_masks_key_a(self):
        dump = image()
        fake = FakeReader(dump)
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertEqual(result, dump)
        self.assertFalse(fake.writes)
        self.assertTrue(all(apdu[1] != 0xD6 for apdu in fake.commands))

    def test_unknown_sector_stays_unknown(self):
        dump = image()
        dump.sectors[1].key_a = "010203040506"
        fake = FakeReader(dump)
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertEqual(result.sectors[1].data, [None] * 3)
        self.assertIsNone(result.sectors[1].key_b)
        self.assertFalse(result.complete)
        self.assertFalse(fake.writes)

    def test_key_b_authentication_does_not_invent_key_a(self):
        dump = image()
        dump.sectors[1].key_a = "010203040506"
        dump.sectors[1].access = access([(0, 0, 0)] * 3 + [(0, 1, 1)])
        fake = FakeReader(dump)
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        sector = result.sectors[1]
        self.assertEqual(sector.data, dump.sectors[1].data)
        self.assertIsNone(sector.key_a)
        self.assertEqual(sector.key_b, DEFAULT_KEY)
        self.assertFalse(sector.complete)

    def test_masked_key_b_not_saved_as_zero(self):
        dump = image()
        dump.sectors[1].access = access([(0, 0, 0)] * 3 + [(0, 1, 1)])
        dump.sectors[1].key_b = "010203040506"
        fake = FakeReader(dump)
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertIsNone(result.sectors[1].key_b)

    def test_denied_read_does_not_hide_later_blocks(self):
        fake = FakeReader(image())
        fake.refuse_read = 4
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertIsNone(result.sectors[1].data[0])
        self.assertEqual(result.sectors[1].data[1:], ["00" * 16] * 2)

    def test_4k_large_sectors(self):
        dump = image("classic-4k")
        dump.sectors[39].data[14] = "a5" * 16
        fake = FakeReader(dump)
        with self.use_card(fake), Card() as card:
            result = capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertEqual(result, dump)
        self.assertTrue(any(apdu[1:4] == [0xB0, 0, 254] for apdu in fake.commands))

    def test_card_swap_stops_capture(self):
        fake = FakeReader(image())
        with self.use_card(fake), Card() as card:
            fake.alternate_uid = b"\x04\x03\x02\x01"
            with self.assertRaises(CopycatError):
                capture(card, [bytes.fromhex(DEFAULT_KEY)])
        self.assertFalse(fake.writes)

    def test_restore_uid_data_and_keys_then_verify(self):
        target = image()
        source = image(uid=b"\x04\x03\x02\x01")
        source.sectors[0].data[1] = "5a" * 16
        source.sectors[0].key_a = "010203040506"
        source.sectors[0].key_b = "102030405060"
        fake = FakeReader(target)
        with self.use_card(fake), Card() as card:
            restore(card, source, target, plan_writes(source, target))
        self.assertEqual(fake.writes, [0, 1, 3])
        self.assertEqual(fake.memory[0][:4].hex(), source.uid)
        self.assertEqual(fake.memory[3], source.sectors[0].trailer())

    def test_ordinary_card_rejects_uid_before_other_changes(self):
        target = image()
        source = image(uid=b"\x04\x03\x02\x01")
        source.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(target, writable_uid=False)
        with (
            self.use_card(fake),
            Card() as card,
            self.assertRaisesRegex(CopycatError, "partially changed"),
        ):
            restore(card, source, target, plan_writes(source, target))
        self.assertFalse(fake.writes)
        self.assertEqual(sum(apdu[1] == 0xD6 for apdu in fake.commands), 1)

    def test_failed_write_is_not_retried(self):
        target = image()
        source = image()
        source.sectors[0].data[1:3] = ["5a" * 16, "a5" * 16]
        fake = FakeReader(target)
        fake.fail_block = 1
        with self.use_card(fake), Card() as card, self.assertRaises(CopycatError):
            restore(card, source, target, plan_writes(source, target))
        self.assertEqual(sum(apdu[1] == 0xD6 for apdu in fake.commands), 1)

    def test_incomplete_or_mismatched_type_cannot_be_planned(self):
        source = image()
        source.sectors[0].key_a = None
        with self.assertRaises(CopycatError):
            plan_writes(source, image())
        with self.assertRaises(CopycatError):
            plan_writes(image(), image("classic-4k"))

    def test_readonly_target_refused_before_writing(self):
        target = image()
        target.sectors[0].access = access([(0, 1, 0)] * 3 + [(0, 0, 1)])
        source = copy.deepcopy(target)
        source.sectors[0].data[1] = "5a" * 16
        with self.assertRaisesRegex(CopycatError, "access settings"):
            plan_writes(source, target)

    def test_key_b_write_and_trailer_update(self):
        target = image()
        target.sectors[1].access = access([(0, 1, 1)] * 4)
        target.sectors[1].key_b = "010203040506"
        source = copy.deepcopy(target)
        source.sectors[1].data[0] = "5a" * 16
        source.sectors[1].key_a = "102030405060"
        fake = FakeReader(target)
        writes = plan_writes(source, target)
        self.assertTrue(all(item.key_type == "b" for item in writes))
        with self.use_card(fake), Card() as card:
            restore(card, source, target, writes)
        self.assertEqual(fake.writes, [4, 7])

    def test_authentication_failure_before_writes(self):
        target = image()
        source = image()
        source.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(target)
        with (
            self.use_card(fake),
            Card() as card,
            patch.object(card, "authenticate", return_value=False),
            self.assertRaisesRegex(CopycatError, "no writes attempted"),
        ):
            restore(card, source, target, plan_writes(source, target))
        self.assertFalse(fake.writes)

    def test_readback_failure_stops_further_writes(self):
        target = image()
        source = image()
        source.sectors[0].data[1:3] = ["5a" * 16, "a5" * 16]
        fake = FakeReader(target)
        with (
            self.use_card(fake),
            Card() as card,
            patch.object(card, "read", return_value=bytes(16)),
            self.assertRaisesRegex(CopycatError, "read-back failed"),
        ):
            restore(card, source, target, plan_writes(source, target))
        self.assertEqual(fake.writes, [1])

    def test_large_sector_write_permission_grouping(self):
        target = image("classic-4k")
        target.sectors[32].access = access([(0, 0, 0), (0, 1, 0), (0, 0, 0), (0, 0, 1)])
        source = copy.deepcopy(target)
        source.sectors[32].data[5] = "5a" * 16
        with self.assertRaises(CopycatError):
            plan_writes(source, target)
        source = copy.deepcopy(target)
        source.sectors[32].data[10] = "5a" * 16
        self.assertEqual(plan_writes(source, target)[0].block, 138)

    def test_final_verification_catches_bad_trailer(self):
        target = image()
        source = image()
        source.sectors[15].key_a = "010203040506"
        fake = FakeReader(target)
        fake.fail_after_trailer = True
        with self.use_card(fake), Card() as card, self.assertRaises(CopycatError):
            restore(card, source, target, plan_writes(source, target))


class CliTests(unittest.TestCase):
    def invoke(self, args, fake):
        output = io.StringIO()
        with (
            patch("copycat.reader.readers", return_value=[fake]),
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            code = cli.main(args)
        return code, output.getvalue()

    def test_partial_read_saves_private_dump_and_returns_two(self):
        dump = image()
        dump.sectors[1].key_a = "f1f2f3f4f5f6"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dump.json"
            code, output = self.invoke(["read", str(path)], FakeReader(dump))
            self.assertEqual(code, 2)
            self.assertFalse(load_dump(path).complete)
            self.assertIn("Incomplete", output)
            self.assertNotIn(dump.sectors[1].key_a, output)

    def test_incomplete_source_never_opens_reader(self):
        source = image()
        source.sectors[0].key_b = None
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, source)
            with (
                patch("copycat.reader.readers") as readers,
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cli.main(["write", str(path)]), 1)
            readers.assert_not_called()

    def test_overwrite_declined_without_writes(self):
        target = image()
        target.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(target)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, image())
            with patch("builtins.input", return_value="no"):
                code, output = self.invoke(["write", str(path)], fake)
        self.assertEqual(code, 1)
        self.assertIn("WARNING", output)
        self.assertFalse(fake.writes)

    def test_confirmed_write_backs_up_and_verifies(self):
        target = image()
        target.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(target)
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "source.json"
            backup = Path(tmp) / "backup.json"
            save_dump(source_path, image())
            with (
                patch("builtins.input", return_value="WRITE"),
                patch("copycat.cli.backup_path", return_value=backup),
            ):
                code, output = self.invoke(["write", str(source_path)], fake)
            self.assertEqual(code, 0, output)
            self.assertEqual(load_dump(backup), target)
            self.assertEqual(fake.writes, [1])
            self.assertIn("Verified UID", output)

    def test_backup_failure_prevents_writes(self):
        source = image()
        source.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(image())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, source)
            with patch("copycat.cli.backup_path", return_value=path):
                code, _ = self.invoke(["write", str(path)], fake)
        self.assertEqual(code, 1)
        self.assertFalse(fake.writes)

    def test_additional_key_file_and_no_secret_output(self):
        dump = image()
        dump.sectors[1].key_a = "f1f2f3f4f5f6"
        fake = FakeReader(dump)
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "keys.txt"
            key_file.write_text(dump.sectors[1].key_a + " # known key\n")
            path = Path(tmp) / "dump.json"
            code, output = self.invoke(
                ["read", str(path), "--keys", str(key_file)], fake
            )
        self.assertEqual(code, 0, output)
        self.assertNotIn(dump.sectors[1].key_a, output)

    def test_matching_card_is_noop(self):
        fake = FakeReader(image())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, image())
            with (
                patch("builtins.input") as confirm,
                patch("copycat.cli.backup_path") as backup,
            ):
                code, output = self.invoke(["write", str(path)], fake)
            confirm.assert_not_called()
            backup.assert_not_called()
        self.assertEqual(code, 0, output)
        self.assertIn("no writes needed", output)
        self.assertFalse(fake.writes)

    def test_blank_target_has_backup_without_overwrite_prompt(self):
        source = image()
        source.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(image())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            backup = Path(tmp) / "backup.json"
            save_dump(path, source)
            with (
                patch("builtins.input") as confirm,
                patch("copycat.cli.backup_path", return_value=backup),
            ):
                code, output = self.invoke(["write", str(path)], fake)
            confirm.assert_not_called()
            self.assertTrue(backup.exists())
        self.assertEqual(code, 0, output)
        self.assertEqual(fake.writes, [1])

    def test_unreadable_target_warns_and_refuses_writes(self):
        target = image()
        target.sectors[1].key_a = "f1f2f3f4f5f6"
        fake = FakeReader(target)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, image())
            code, output = self.invoke(["write", str(path)], fake)
        self.assertEqual(code, 1)
        self.assertIn("WARNING", output)
        self.assertIn("incomplete", output)
        self.assertFalse(fake.writes)

    def test_noninteractive_confirmation_cancels(self):
        target = image()
        target.sectors[0].data[1] = "5a" * 16
        fake = FakeReader(target)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, image())
            with patch("builtins.input", side_effect=EOFError):
                code, _ = self.invoke(["write", str(path)], fake)
        self.assertEqual(code, 1)
        self.assertFalse(fake.writes)

    def test_existing_output_is_not_overwritten_or_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            save_dump(path, image())
            with (
                patch("copycat.reader.readers") as readers,
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cli.main(["read", str(path)]), 1)
            readers.assert_not_called()

    def test_no_card_is_handled(self):
        from smartcard.Exceptions import NoCardException

        fake = FakeReader(image())
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                fake, "connect", side_effect=NoCardException("No card", 0x8010000C)
            ),
        ):
            code, output = self.invoke(["read", str(Path(tmp) / "dump.json")], fake)
        self.assertEqual(code, 1)
        self.assertIn("no card detected", output)
        self.assertFalse(fake.writes)


if __name__ == "__main__":
    unittest.main()
