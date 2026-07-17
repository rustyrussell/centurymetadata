#!/usr/bin/env python3
"""Generate python/centurymetadata/constants.py from SPECIFICATION.md.

SPECIFICATION.md's "File Format" section embeds the literal header
verbatim, byte-for-byte, in its own fenced code block -- so rather than
hand-copy it (and the field widths it declares) into the Python package,
this extracts both directly from that block. That leaves exactly one place
where the wire format's byte layout is written down.

Run from the repository root, or from python/ (both resolve the same paths):

    uv run --project python python tools/generate_constants.py

Also invoked by `make python/centurymetadata/constants.py` (see ../Makefile).
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "SPECIFICATION.md"
OUT_PATH = REPO_ROOT / "python" / "centurymetadata" / "constants.py"

FIELDS = ("SIG", "WRITER_PUBKEY", "READER_ID", "GEN", "MLKEM_CT", "AES")

_FIELD_LINE_RE = re.compile(
    r"^centurymetadata v1\\0"
    + r"\|".join(r"{}\[(\d+)\]".format(name) for name in FIELDS)
    + r"$"
)


def _extract_header_block(spec_text: str) -> str:
    """Return the raw text of the fenced ``` block under '## File Format'."""
    # CMDATA-SPEC/File Format: The file header (below) is embedded verbatim,
    # byte-for-byte, at the start of every file.
    section_start = spec_text.index("## File Format")
    fence_start = spec_text.index("\n```\n", section_start) + len("\n```\n")
    fence_end = spec_text.index("\n```", fence_start)
    return spec_text[fence_start:fence_end]


def parse_wire_format(spec_text: str) -> dict:
    block = _extract_header_block(spec_text)

    first_line = block.split("\n", 1)[0]
    m = _FIELD_LINE_RE.match(first_line)
    if not m:
        raise ValueError(
            "SPECIFICATION.md's File Format header line doesn't match the "
            "expected 'centurymetadata v1\\0{}' shape:\n{!r}".format(
                "|".join("{}[N]".format(name) for name in FIELDS), first_line
            )
        )
    widths = dict(zip(FIELDS, (int(g) for g in m.groups())))

    # CMDATA-SPEC/File Format: It contains exactly two real NUL bytes: the
    # 19th byte (ending `centurymetadata v1`) and the final byte.
    # CMDATA-SPEC/File Format: Every other `\0` shown below is literal
    # two-character notation (backslash, zero) marking where NUL-separators
    # fall in `DATA`
    first_nul = block.index("\\0")
    last_nul = block.rindex("\\0")
    if first_nul == last_nul:
        raise ValueError("expected two distinct '\\0' markers in the header block")
    preamble = (
        block[:first_nul].encode("ascii") + b"\x00"
        + block[first_nul + 2:last_nul].encode("ascii") + b"\x00"
        + block[last_nul + 2:].encode("ascii")
    )
    verheader = preamble[:preamble.index(b"\x00") + 1]

    full_length = sum(widths.values())
    mlkem_ct_length = widths["MLKEM_CT"]
    # CMDATA-SPEC/Writer Requirements: MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-encrypt
    # the padded, compressed stream, using a 12-byte all-zero nonce, and
    # append the 16-byte authentication tag.

    # The AES[N] field on the wire holds ciphertext + a 16-byte GCM tag, so
    # the zlib-padded plaintext it's built from is 16 bytes shorter.
    GCM_TAG_LENGTH = 16
    aes_length = widths["AES"]
    data_length = aes_length - GCM_TAG_LENGTH

    return {
        "verheader": verheader,
        "preamble": preamble,
        "full_length": full_length,
        "mlkem_ct_length": mlkem_ct_length,
        "aes_length": aes_length,
        "data_length": data_length,
    }


def render(wf: dict) -> str:
    return '''\
"""Wire-format constants, generated from SPECIFICATION.md's "File Format"
section by ../../tools/generate_constants.py -- do not edit by hand.
"""

verheader = {verheader!r}
preamble = {preamble!r}

FULL_LENGTH = {full_length}
MLKEM_CT_LENGTH = {mlkem_ct_length}
DATA_LENGTH = {data_length}
AES_LENGTH = {aes_length}
RECORD_LENGTH = len(preamble) + FULL_LENGTH
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
