# CopyCat

Two modes for authorized MIFARE Classic **1K/4K cards with 4-byte UIDs**, using
an ACR122U through PC/SC. Python code lives under `src/copycat`; uv manages the
project environment.

## Setup

```bash
uv sync --locked
uv run copycat --help
```

On Fedora/Nobara, pyscard needs PC/SC build headers and a compiler:

```bash
sudo dnf install pcsc-lite pcsc-lite-ccid pcsc-lite-devel swig gcc
sudo systemctl enable --now pcscd.socket
```

The commands themselves do **not** need sudo. If the USB reader is visible but
PC/SC cannot find it, inspect `journalctl -u pcscd`. The kernel's `pn533_usb`
driver can claim the reader before PC/SC (`LIBUSB_ERROR_BUSY`). Release that
driver and replug/restart PC/SC; a blacklist of `pn533_usb` can prevent recurrence.
This affects other devices using that driver, so do not change it blindly.

## Read a card

Place only the source card on the reader:

```bash
mkdir -p -m 700 ~/.local/share/copycat/cards
uv run copycat read ~/.local/share/copycat/cards/source.json
```

- Tries 24 common/default keys as Key A and Key B. No key recovery or card writes.
- Saves data/manufacturer blocks, access bytes, and known sector keys as versioned
  JSON. Key A is established by authentication, never by assuming masked bytes
  are its value. Key B is authenticated or read only when the access bits allow it.
- Unreadable blocks/unknown keys are `null`, **not** guessed zeros. An incomplete
  dump is still saved, but exits with status **2** and cannot be restored.
- Output files are created exclusively with permissions **0600**. Existing files
  and symlinks are never overwritten. Parent directories must already exist.
- Dumps contain credentials/keys. Keep them outside Git; do not share them or
  paste their contents into logs. CLI progress does not print keys or block data.

For configured sector keys, supply a local text file with one 12-hex-digit key
per line; blank lines and `#` comments are allowed:

```bash
uv run copycat read ~/.local/share/copycat/cards/source-with-keys.json \
  --keys ~/.local/share/copycat/known-keys.txt
```

Keys from that file are tried before the defaults. Protect the key file too.

## Write a dump

Replace the source with the target card, then:

```bash
uv run copycat write ~/.local/share/copycat/cards/source.json
```

Optional `--keys FILE` supplies the target's current keys. The dump's known keys
and the defaults are also tried.

Before writing, CopyCat:

1. Validates the dump, access-bit complements, UID/check byte, and card capacity.
   Refuses incomplete/unsupported dumps and targets it cannot fully inspect.
2. Warns if application data is nonzero, security settings are nondefault, or
   fields are unreadable. A nonblank target requires typing **WRITE**; a cancelled
   or unavailable confirmation causes no writes. Unknown target fields prevent
   writing altogether.
3. Plans only differing blocks, checks current access permissions and keys, and
   saves a full private pre-write backup under
   `$XDG_DATA_HOME/copycat/cards` (normally `~/.local/share/copycat/cards`).
4. If necessary, attempts a standard block-0 write first, to fail early on ordinary
   cards with a read-only manufacturer block. Then writes data before each sector's
   trailer, so changed keys/permissions take effect last. Trailer changes require
   permission to write all security fields; partially writable trailers are refused.
5. Resets the connection and verifies the UID, every data block, access settings,
   and both keys (authentication/readability, not masked bytes).

**Warnings and limits**

- Only use cards you are authorized to read or duplicate. A card with empty
  application storage may still be a live UID-based access credential; “blank”
  here describes memory/settings, not whether a credential is in use.
- Changing UID/manufacturer bytes requires a compatible CUID-writable target.
  Standard commands cannot prove writability without attempting the write.
  Incompatible identification bytes can make the target unusable. No proprietary
  unlock sequences or automatic retries are used.
- Writes are **not atomic**. Communication failures, power loss, or an incompatible
  card can leave a partial copy. Keep the pre-write backup. There is no automatic
  rollback; even a backup cannot repair every hardware/permission failure.
- A matching logical-memory image does not reproduce immutable silicon identity,
  hidden features, or guarantee acceptance by an access system. ATR is checked
  separately and is not a writable dump block.
- Earlier experimental, unversioned JSON dumps are not accepted. Read the source
  again with this CLI; earlier backups are left untouched.
- Exit codes: **0** success/no changes needed, **1** error/cancelled, **2** partial
  read (or an argparse usage error). `python -m copycat` supports the same modes.

## Tests

```bash
uv run python -m unittest discover -s tests -v
```

Tests use an in-memory PC/SC reader to exercise key masking, authentication loss,
1K/4K layouts, private files, partial dumps, overwrite confirmation, write ordering,
UID changes, failure handling, and read-back verification. They never write a
physical card.
