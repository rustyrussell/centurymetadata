#!/usr/bin/env python3
"""Generate python/centurymetadata/constants.py from SPECIFICATION.md.

SPECIFICATION.md's "File Format" section declares the wire-format
constants as plain NAME=value lines ("constants defined for
implementation convenience") -- so rather than hand-copy them into the
Python package, this extracts them directly. That leaves exactly one
place where the wire format's byte layout is written down.

Run from the repository root, or from python/ (both resolve the same paths):

    uv run --project python python tools/generate_constants.py

Also invoked by `make python/centurymetadata/constants.py` (see ../Makefile).
"""
import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "SPECIFICATION.md"
OUT_PATH = REPO_ROOT / "python" / "centurymetadata" / "constants.py"

# CMDATA-SPEC/File Format: The following constants are defined for
# implementation convenience
_CONST_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$", re.MULTILINE)

STRING_CONSTS = ("VERSION_HEADER_STRING", "PREAMBLE_HEADER_STRING")
INT_CONSTS = (
    "DATA_LENGTH", "SIGNATURE_LENGTH", "PUBKEY_LENGTH", "READER_ID_LENGTH",
    "GENERATION_LENGTH", "MLKEM_CT_LENGTH", "AES_TAG_LENGTH",
)

# STRING_CONSTS are written on one logical line, so they use backslash
# escapes like a C/Python string literal: '\n' for a real newline, '\\'
# for a literal backslash (needed so e.g. PREAMBLE_HEADER_STRING's own
# '\0' two-character markers -- not NUL bytes -- survive as '\\0').
_ESCAPE_RE = re.compile(r"\\\\|\\n")


def _unescape(value: str) -> str:
    return _ESCAPE_RE.sub(lambda m: "\\" if m.group() == "\\\\" else "\n", value)


def parse_wire_format(spec_text: str) -> dict:
    consts = dict(_CONST_RE.findall(spec_text))
    missing = [name for name in STRING_CONSTS + INT_CONSTS if name not in consts]
    if missing:
        raise ValueError(
            "SPECIFICATION.md is missing constants: {}".format(", ".join(missing))
        )

    version_header = _unescape(consts["VERSION_HEADER_STRING"])
    preamble_header = _unescape(consts["PREAMBLE_HEADER_STRING"])

    verheader = version_header.encode("ascii") + b"\x00"
    preamble = verheader + preamble_header.encode("ascii") + b"\x00"

    widths = {name: int(consts[name]) for name in INT_CONSTS}

    # CMDATA-SPEC/File Format: Cryptograhic header (1705 bytes =
    # SIGNATURE_LENGTH + PUBKEY_LENGTH + READER_ID_LENGTH +
    # GENERATION_LENGTH + MLKEM_CT_LENGTH).
    crypto_header_length = (
        widths["SIGNATURE_LENGTH"] + widths["PUBKEY_LENGTH"]
        + widths["READER_ID_LENGTH"] + widths["GENERATION_LENGTH"]
        + widths["MLKEM_CT_LENGTH"]
    )
    data_length = widths["DATA_LENGTH"]
    aes_length = data_length - crypto_header_length
    plaintext_length = aes_length - widths["AES_TAG_LENGTH"]

    return {
        "verheader": verheader,
        "preamble": preamble,
        "data_length": data_length,
        "mlkem_ct_length": widths["MLKEM_CT_LENGTH"],
        "aes_length": aes_length,
        "plaintext_length": plaintext_length,
    }


def render(wf: dict) -> str:
    return '''\
"""Wire-format constants, generated from SPECIFICATION.md's "File Format"
section by ../../tools/generate_constants.py -- do not edit by hand.
"""

verheader = {verheader!r}
preamble = {preamble!r}

DATA_LENGTH = {data_length}
MLKEM_CT_LENGTH = {mlkem_ct_length}
PLAINTEXT_LENGTH = {plaintext_length}
AES_LENGTH = {aes_length}
RECORD_LENGTH = len(preamble) + DATA_LENGTH
# BIP340 tag excludes final \\0
bip340tag = verheader[:-1]
'''.format(**wf)


def main() -> int:
    spec_text = SPEC_PATH.read_text()
    wf = parse_wire_format(spec_text)
    OUT_PATH.write_text(render(wf))
    print("Written {}".format(OUT_PATH), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
