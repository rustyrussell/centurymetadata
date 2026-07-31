#!/usr/bin/env python3
"""Generate a prepopulated centurymetadata server "mirror" tree of test
vectors, exercising as much of SPECIFICATION.md as a stored record can
express.

This writes real files directly into the on-disk layout
python/centurymetadata/server/server.py expects
(BASEDIR/<dirmin>-<dirmax>/<bmin>-<bmax>/<reader_id>+<writer>/<gen_hex>),
bypassing the server's HTTP API entirely -- unlike the test suite, which
always goes through authorize/update -- so we have full control to
produce both spec-compliant *and* deliberately non-compliant records:
many SPECIFICATION.md bullets are literally "MUST fail parsing if...",
and the server's own /update would refuse to store those.

Identities: every vector's reader_id comes from the "known keys" scheme
(see centurymetadata.server.known_keys / README.md's "Known Test Keys"):
a BIP-39 mnemonic of the same word repeated 12 times. Every deliberately
invalid (can't-decode) vector shares the *same* reader_id, derived from
"illegal"x12; every vector meant to actually decode uses one of the
"margin"-onward known words (the second half of known_words.txt,
reserved by convention for the test server's own example data), one
word per category, with individual sub-cases distinguished by writer
pubkey. Vectors are self-verified (built, then actually decoded, with
the outcome asserted) before being written to disk.

Run from the python/ subdirectory (which has the venv and dependencies):

    cd python && uv run python ../tools/gen_test_vectors.py <directory>
"""
import argparse
import hashlib
import json
import os
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, PublicKey

import centurymetadata
from centurymetadata import CenturyMetadata, CMDataErrorCode, Identity, NEXT_DERIVATION_TYPE
from centurymetadata.bip39 import bip39_to_seed, derive_cm_keys
from centurymetadata.server.known_keys import known_words

# ── Layout constants ──────────────────────────────────────────────────────────

SKELETON_DIR = "00-ff"
SKELETON_BUNDLE = "00-ff"

# Offsets within the DATA_LENGTH-byte post-preamble blob (the file
# content stored per-record in the mirror): matches PREAMBLE_HEADER's
# SIG[64]|WRITER_PUBKEY[33]|READER_ID[32]|GEN[8]|MLKEM_CT[1568]|AES[14679].
SIG_OFF, SIG_LEN = 0, 64
WKEY_OFF, WKEY_LEN = 64, 33
RID_OFF, RID_LEN = 97, 32
GEN_OFF, GEN_LEN = 129, 8
MLKEM_CT_OFF = 137
AES_OFF = MLKEM_CT_OFF + centurymetadata.MLKEM_CT_LENGTH

WORDS = known_words()
HALF = len(WORDS) // 2
assert WORDS[HALF] == "margin"

ILLEGAL_WORD = "illegal"
assert WORDS.index(ILLEGAL_WORD) < HALF, "illegal must be a known word"


# ── Identity helpers ───────────────────────────────────────────────────────────

def identity_for_word(word: str, writer_privkey: Optional[PrivateKey] = None, n: int = 0) -> Identity:
    """The standard known-keys derivation for `word`x12 at derivation
    slot `n` (see known_keys._build_identities, which always uses n=0 --
    n>0 here is for chained-file vectors, following the same one-seed,
    many-slots scheme as a real "to-self" chain). If writer_privkey is
    omitted, this is the self-authored identity (writer key == this
    identity's own)."""
    seed = bip39_to_seed(" ".join([word] * 12))
    w_secp, r_secp, _w_mlkem_seed, r_mlkem_seed = derive_cm_keys(seed, n=n)
    own_writer_privkey = PrivateKey(w_secp)
    reader_secp_privkey = PrivateKey(r_secp)
    reader_mlkem_pubkey, reader_mlkem_privkey = centurymetadata.derive_mlkem_keypair(r_mlkem_seed)
    return Identity(writer_privkey or own_writer_privkey, reader_secp_privkey,
                    reader_mlkem_pubkey, reader_mlkem_privkey)


def illegal_identity(writer_word: str) -> Identity:
    """The fixed "illegal" reader_id, signed with a foreign writer key
    derived from `writer_word`'s own mnemonic -- a distinct word per
    vector lets many vectors share one reader_id while still getting
    distinct <reader_id>+<writer> mirror directories, and lets the
    manifest name the writer as a mnemonic word instead of raw hex."""
    return identity_for_word(ILLEGAL_WORD, identity_for_word(writer_word).writer_privkey)


def deterministic_filler(label: str, n: int) -> bytes:
    """n deterministic pseudo-random bytes -- reproducible across runs
    (unlike os.urandom()), so a filler record's exact compressed size
    (and thus whether it forces a chain split) is stable from run to
    run rather than merely probable."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256("{} {}".format(label, counter).encode()).digest()
        counter += 1
    return bytes(out[:n])


# ── Low-level record building (mirrors encode.py's pipeline, but lets us
#    isolate exactly one deliberately-wrong field at a time) ──────────────────

def raw_compress(raw_tuples_bytes: bytes) -> bytes:
    """Like centurymetadata.compress(), but takes already-joined
    TYPE\\0NAME\\0CONTENTS\\0... bytes directly, bypassing its per-field
    validation -- for deliberately malformed plaintexts (oversize NAME,
    invalid UTF-8, truncated tuples)."""
    return zlib.compress(raw_tuples_bytes, level=9).ljust(centurymetadata.PLAINTEXT_LENGTH, bytes(1))


def build_after_pre(identity: Identity, gen: int, padded_compressed: bytes) -> bytes:
    """Same crypto pipeline as centurymetadata.encode(), starting from
    already-compressed-and-padded (PLAINTEXT_LENGTH) bytes, and signing
    with the identity's real writer key -- so the signature is always
    genuinely valid unless the caller deliberately corrupts it
    afterwards. Returns exactly what the mirror stores (preamble
    already stripped)."""
    ecdh_secret = centurymetadata.get_ecdh_secret(identity.writer_privkey, identity.reader_secp_pubkey)
    mlkem_secret, mlkem_ct = ML_KEM_1024.encaps(identity.reader_mlkem_pubkey)
    aeskey = centurymetadata.get_aeskey(ecdh_secret, mlkem_secret, gen)
    encrypted = centurymetadata.aes(aeskey, padded_compressed)
    return build_signed(identity, gen, mlkem_ct, encrypted)


def build_signed(identity: Identity, gen: int, mlkem_ct: bytes, aes_data: bytes) -> bytes:
    """Build after_pre bytes with a genuinely-valid signature over
    whatever (possibly deliberately wrong) fields are given."""
    cont = centurymetadata.contents(identity.writer_privkey.pubkey, identity.reader_id, gen, mlkem_ct, aes_data)
    sig = centurymetadata.sign(identity.writer_privkey, cont)
    return sig + cont


def encode_after_pre(identity: Identity, gen: int, *triples: Tuple[str, str, str]) -> bytes:
    """A normal, fully valid record (preamble stripped)."""
    full = centurymetadata.encode(identity.writer_privkey, identity.reader_secp_pubkey,
                                  identity.reader_mlkem_pubkey, gen, *triples)
    return full[len(centurymetadata.preamble):]


def text_record(purpose: str) -> Tuple[str, str, str]:
    """The purpose-marker record embedded in every vector that decodes
    at all (see tools/generate_test_vectors.py for the same bare,
    unprefixed "text" convention)."""
    return ("text", "purpose", purpose)


# ── Manifest / storage ────────────────────────────────────────────────────────

@dataclass
class ManifestEntry:
    category: str
    name: str
    description: str
    spec_bullets: List[str]
    path: str
    reader: str
    n: int
    gen: int
    records: object  # List[Dict[str, str]] if valid tuples, else a plain str fallback
    writer: Optional[str] = None
    invalid: Optional[str] = None


class VectorSet:
    """Accumulates manifest entries and writes files into the mirror tree."""

    def __init__(self, basedir: Path) -> None:
        self.basedir = basedir
        self.bundle_dir = basedir / SKELETON_DIR / SKELETON_BUNDLE
        self.manifest: List[ManifestEntry] = []
        # In-memory only (never written to manifest.json, which is meant
        # to be a plain, publishable index -- not a place to persist
        # private key material): lets a test independently re-derive and
        # decode() each vector straight from disk without needing to
        # know which internal label/word produced it.
        self.identities: Dict[Tuple[str, str], Identity] = {}

    def store(self, category: str, name: str, description: str, spec_bullets: List[str],
              word: str, n: int, identity: Identity, gen: int, after_pre: bytes,
              invalid: Optional[str] = None,
              records: Optional[List[Tuple[str, str, str]]] = None,
              plaintext: Optional[bytes] = None,
              writer: Optional[str] = None) -> None:
        """records is the record's TYPE/NAME/CONTENTS tuples, when they're
        well-formed (the common case -- most vectors are built from an
        actual triples list, even the crypto-broken ones, since we know
        what was intended even though a reader never recovers it).
        plaintext is the fallback for the handful of vectors whose
        deliberately malformed plaintext doesn't parse into tuples at
        all (truncated/invalid-UTF8 tuples, or garbage standing in for
        a broken zlib stream): the raw decrypted-and-decompressed (or
        would-be) bytes, decoded best-effort. At most one of the two;
        omitting both (e.g. a multi-megabyte oversize-zlib payload) is
        fine too. writer is the mnemonic word for the foreign writer key
        actually embedded in this record, when it's not this identity's
        own self-authored writer key -- omit it for the common
        self-authored case."""
        assert len(after_pre) == centurymetadata.DATA_LENGTH
        assert records is None or plaintext is None
        reader_id_hex = identity.reader_id.hex()
        writer_hex = identity.writer_privkey.pubkey.serialize().hex()
        record_dir = self.bundle_dir / (reader_id_hex + "+" + writer_hex)
        record_dir.mkdir(parents=True, exist_ok=True)
        gen_hex = gen.to_bytes(8, "big").hex()
        (record_dir / gen_hex).write_bytes(after_pre)
        self.identities[(reader_id_hex, writer_hex)] = identity

        path = "{}/{}/{}+{}/{}".format(SKELETON_DIR, SKELETON_BUNDLE, reader_id_hex, writer_hex, gen_hex)

        records_json: object = None
        if records is not None:
            records_json = [{"type": t, "name": nm, "contents": c} for t, nm, c in records]
        elif plaintext is not None:
            records_json = plaintext.decode("utf-8", errors="backslashreplace")

        self.manifest.append(ManifestEntry(
            category=category, name=name, description=description, spec_bullets=spec_bullets,
            path=path, reader=word, n=n, gen=gen, records=records_json,
            writer=writer, invalid=invalid))

    def write_manifest(self) -> None:
        data = []
        for e in self.manifest:
            d = {
                "path": e.path,
                "category": e.category,
                "name": e.name,
                "reader": e.reader,
                "n": e.n,
                "gen": e.gen,
            }
            if e.writer is not None:
                d["writer"] = e.writer
            if e.invalid is not None:
                d["invalid"] = e.invalid
            if e.records is not None:
                d["records"] = e.records
            d["description"] = e.description
            d["spec_bullets"] = e.spec_bullets
            data.append(d)
        (self.basedir / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")


# ── Extra identity helper ──────────────────────────────────────────────────────

def own_writer_pubkey(word: str) -> PublicKey:
    """The pubkey decode() needs for "to-self" detection: `word`'s own
    derived writer key, regardless of what writer key a specific vector
    was actually signed with."""
    return identity_for_word(word).writer_privkey.pubkey


# ── Self-verification ──────────────────────────────────────────────────────────

def verify_clean(identity: Identity, own_pub: PublicKey, after_pre: bytes,
                 expect_triples: List[Tuple[str, str, str]]) -> None:
    full = centurymetadata.preamble + after_pre
    errors, triples = centurymetadata.decode(
        identity.reader_secp_privkey, identity.reader_mlkem_privkey,
        identity.reader_mlkem_pubkey, own_pub, full)
    assert not any(e.fatal for e in errors), "expected clean decode, got fatal errors: {}".format(errors)
    for t in expect_triples:
        assert t in triples, "expected triple {!r} missing from decoded triples {!r}".format(t, triples)


def verify_error(identity: Identity, own_pub: PublicKey, after_pre: bytes, code: CMDataErrorCode) -> None:
    full = centurymetadata.preamble + after_pre
    errors, triples = centurymetadata.decode(
        identity.reader_secp_privkey, identity.reader_mlkem_privkey,
        identity.reader_mlkem_pubkey, own_pub, full)
    assert errors and errors[0].code == code, "expected {}, got {}".format(code, errors)


# ── Category 1: baseline ───────────────────────────────────────────────────────

def gen_category_baseline(vs: VectorSet) -> None:
    identity = identity_for_word("margin")
    triples = [text_record("Baseline: the simplest possible valid centurymetadata file "
                           "-- one text record, GEN 0.")]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, triples)
    vs.store(
        "baseline", "single-record", "Simplest valid file: one text record, self-authored.",
        ["MUST begin the file with the literal header.",
         "SHOULD set GEN to 0."],
        "margin", 0, identity, 0, after_pre, records=triples)


# ── Category 2: GEN ordering ────────────────────────────────────────────────────

def gen_category_gen_ordering(vs: VectorSet) -> None:
    identity = identity_for_word("melody")
    cases = [
        (0, "First file for this WRITER_PUBKEY/READER_ID pair."),
        (5,
         "A later update: GEN must be greater than all previous GENs for this pair "
         "(the mirror can hold both simultaneously; a fetcher takes the latest -- "
         "see server.py's assemble_bundle())."),
    ]
    for gen, note in cases:
        triples = [text_record("GEN ordering example: {}".format(note))]
        after_pre = encode_after_pre(identity, gen, *triples)
        verify_clean(identity, identity.writer_privkey.pubkey, after_pre, triples)
        vs.store(
            "gen-ordering", "gen-{}".format(gen), note,
            ["SHOULD set GEN to 0."] if gen == 0 else
            ["MUST set GEN to a number greater than all previous such files."],
            "melody", 0, identity, gen, after_pre, records=triples)


# ── Category 3: wire/crypto-layer Reader Requirement failures ─────────────────
#
# One vector per centurymetadata.decode.CMDataErrorCode that can actually be
# represented in the mirror layout (BAD_HEADER and BAD_LENGTH cannot: both
# are about the literal preamble / overall file length, which the mirror
# never stores per-record -- see plan notes). All share the "illegal"
# reader_id, one writer key per case; each is its own function so mypy
# doesn't pin a single `after_pre` name's type across the whole category.

def _wire_bad_wkey(vs: VectorSet, own_pub: PublicKey) -> None:
    # WRITER_PUBKEY bytes aren't a valid compressed secp256k1 point --
    # can't be verified as a signer, so this is the same requirement the
    # reference decode() checks via schnorr_verify.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `SIG` is not a valid [BIP-340](#ref-bip340) signature by `WRITER_PUBKEY` over
    #   SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    identity = illegal_identity("quantum")
    triples = [text_record("n/a: fails before decrypt")]
    mutable = bytearray(encode_after_pre(identity, 0, *triples))
    mutable[WKEY_OFF:WKEY_OFF + 1] = b'\x00'  # 0x00 is not a valid compressed-point prefix
    after_pre = bytes(mutable)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_WKEY)
    vs.store(
        "wire-errors", "bad-wkey", "WRITER_PUBKEY is not a valid compressed secp256k1 point.",
        ["MUST fail parsing if `SIG` is not a valid BIP-340 signature by `WRITER_PUBKEY`..."],
        ILLEGAL_WORD, 0, identity, 0, after_pre, invalid="CMDataErrorCode.BAD_WKEY", records=triples,
        writer="quantum")


def _wire_bad_reader_id(vs: VectorSet, own_pub: PublicKey) -> None:
    # Genuinely valid file for a *different* reader, stored under
    # "illegal"'s directory -- illegal's own keys won't match the
    # embedded READER_ID.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `READER_ID` does not equal [SHA256](#ref-sha256)(`READER_SECP_PUBKEY`|`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to.
    other = identity_for_word("rebel")
    triples = [text_record("n/a: encoded for a different reader")]
    after_pre = encode_after_pre(other, 0, *triples)
    identity = illegal_identity("rebel")
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_READER_ID)
    vs.store(
        "wire-errors", "bad-reader-id",
        "READER_ID in the file belongs to a different reader than the one fetching it.",
        ["MUST fail parsing if `READER_ID` does not equal SHA256(`READER_SECP_PUBKEY`|"
         "`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to."],
        ILLEGAL_WORD, 0, identity, 0, after_pre, invalid="CMDataErrorCode.BAD_READER_ID", records=triples,
        writer="rebel")


def _wire_bad_signature(vs: VectorSet, own_pub: PublicKey) -> None:
    # SIG bytes corrupted after a genuinely valid build.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `SIG` is not a valid [BIP-340](#ref-bip340) signature by `WRITER_PUBKEY` over
    #   SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    identity = illegal_identity("quiz")
    triples = [text_record("n/a: fails before decrypt")]
    mutable = bytearray(encode_after_pre(identity, 0, *triples))
    mutable[SIG_OFF] ^= 0xFF
    after_pre = bytes(mutable)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_SIGNATURE)
    vs.store(
        "wire-errors", "bad-signature", "SIG does not verify against WRITER_PUBKEY.",
        ["MUST fail parsing if `SIG` is not a valid BIP-340 signature by `WRITER_PUBKEY` "
         "over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`)."],
        ILLEGAL_WORD, 0, identity, 0, after_pre, invalid="CMDataErrorCode.BAD_SIGNATURE", records=triples,
        writer="quiz")


def _wire_bad_aes_tag(vs: VectorSet, own_pub: PublicKey) -> None:
    # AES/GCM tag corrupted, then genuinely re-signed (since we hold the
    # real writer key) so only the tag check fails.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the trailing 16-byte authentication tag does not verify.
    identity = illegal_identity("rebuild")
    gen = 0
    triples = [text_record("n/a: fails before decompress")]
    comp = centurymetadata.compress(triples)
    ecdh_secret = centurymetadata.get_ecdh_secret(identity.writer_privkey, identity.reader_secp_pubkey)
    mlkem_secret, mlkem_ct = ML_KEM_1024.encaps(identity.reader_mlkem_pubkey)
    aeskey = centurymetadata.get_aeskey(ecdh_secret, mlkem_secret, gen)
    mutable = bytearray(centurymetadata.aes(aeskey, comp))
    mutable[-1] ^= 0xFF  # corrupt the last byte of the 16-byte GCM tag
    after_pre = build_signed(identity, gen, mlkem_ct, bytes(mutable))
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_AES_TAG)
    vs.store(
        "wire-errors", "bad-aes-tag", "AES-GCM authentication tag does not verify.",
        ["MUST fail parsing if the trailing 16-byte authentication tag does not verify."],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.BAD_AES_TAG", records=triples,
        writer="rebuild")


def _wire_bad_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # Decrypted plaintext isn't a valid zlib stream at all.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
    identity = illegal_identity("rescue")
    gen = 0
    padded = os.urandom(centurymetadata.PLAINTEXT_LENGTH)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_ZLIB)
    vs.store(
        "wire-errors", "bad-zlib", "Decrypted DATA is not a valid zlib stream.",
        ["MUST fail parsing if the decrypted bytes do not contain a valid zlib stream."],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.BAD_ZLIB",
        writer="rescue")


def _wire_truncated_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # A real zlib stream, cut short before its end marker. decode.py has
    # no *separate* quote for this: the reference implementation treats
    # truncation as the same requirement as an outright-invalid stream.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
    identity = illegal_identity("rival")
    gen = 0
    raw = b"text\x00note\x00enough content that truncating it is unambiguous, not accidentally valid\x00"
    comp_full = zlib.compress(raw, level=9)
    # Cutting only the trailing Adler32 checksum (4 bytes) isn't enough:
    # decode.py hands zlib the *whole* zero-padded PLAINTEXT_LENGTH
    # buffer, so a 4-byte cut lets the padding's zeros complete a
    # (wrong) checksum and raise zlib.error instead of leaving the
    # stream genuinely incomplete -- verified empirically, 5+ bytes is
    # reliably clean.
    comp_trunc = comp_full[:-6]
    padded = comp_trunc.ljust(centurymetadata.PLAINTEXT_LENGTH, bytes(1))
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.TRUNCATED_ZLIB)
    vs.store(
        "wire-errors", "truncated-zlib", "Decrypted DATA is a zlib stream cut short of its end marker.",
        ["MUST fail parsing if the decrypted bytes do not contain a valid zlib stream."],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.TRUNCATED_ZLIB",
        plaintext=raw, writer="rival")


def _wire_oversize_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # Valid, small zlib stream that decompresses past 1MB.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decompressed size would exceed 1048576 bytes.
    identity = illegal_identity("rocket")
    gen = 0
    huge = bytes(2_000_000)
    comp = zlib.compress(huge, level=9)
    assert len(comp) <= centurymetadata.PLAINTEXT_LENGTH
    padded = comp.ljust(centurymetadata.PLAINTEXT_LENGTH, bytes(1))
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.OVERSIZE_ZLIB)
    vs.store(
        "wire-errors", "oversize-zlib", "Decompressed size would exceed 1048576 bytes.",
        ["MUST fail parsing if the decompressed size would exceed 1048576 bytes."],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.OVERSIZE_ZLIB",
        writer="rocket")


def _wire_truncated_tuple(vs: VectorSet, own_pub: PublicKey) -> None:
    # A complete tuple followed by a dangling incomplete one.
    # CMDATA-SPEC/Reader Requirements:
    #   - MUST stop processing (keeping all tuples already parsed) upon reaching a tuple for which fewer than three
    #     NUL-terminated fields remaing.
    identity = illegal_identity("salmon")
    gen = 0
    raw = (b"text\x00note\x00a complete tuple first\x00"
           b"text\x00dangling incomplete tuple missing its final NUL")
    padded = raw_compress(raw)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.TRUNCATED_TUPLE)
    vs.store(
        "wire-errors", "truncated-tuple", "Final tuple is missing one or more NUL-terminated fields.",
        ["MUST stop processing (keeping all tuples already parsed) upon reaching a tuple "
         "for which fewer than three NUL-terminated fields remaing."],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.TRUNCATED_TUPLE",
        plaintext=raw, writer="salmon")


def _wire_invalid_utf8(vs: VectorSet, own_pub: PublicKey) -> None:
    # CONTENTS field contains invalid UTF-8 bytes.
    # CMDATA-SPEC/Reader Requirements:
    #   - If any of `TYPE`, `NAME` or `CONTENTS` are not a valid, complete UTF-8 string:
    #     - MUST fail to parse this record
    identity = illegal_identity("satisfy")
    gen = 0
    raw = b"text\x00note\x00" + b'\xff\xfe\xfd' + b"\x00"
    padded = raw_compress(raw)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.INVALID_UTF8)
    vs.store(
        "wire-errors", "invalid-utf8", "CONTENTS field is not valid, complete UTF-8.",
        ["If any of `TYPE`, `NAME` or `CONTENTS` are not a valid, complete UTF-8 string: "
         "MUST fail to parse this record"],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.INVALID_UTF8",
        plaintext=raw, writer="satisfy")


def _wire_overlength_name(vs: VectorSet, own_pub: PublicKey) -> None:
    # NAME field over 255 bytes.
    # CMDATA-SPEC/Reader Requirements:
    #   - Otherwise, if `NAME` is greater than 255 bytes:
    #     - MUST fail to parse this record
    identity = illegal_identity("scatter")
    gen = 0
    raw = b"text\x00" + b"n" * 300 + b"\x00overlength name test\x00"
    padded = raw_compress(raw)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.OVERLENGTH_NAME)
    vs.store(
        "wire-errors", "overlength-name", "NAME field exceeds 255 bytes.",
        ["Otherwise, if `NAME` is greater than 255 bytes: MUST fail to parse this record"],
        ILLEGAL_WORD, 0, identity, gen, after_pre, invalid="CMDataErrorCode.OVERLENGTH_NAME",
        plaintext=raw, writer="scatter")


def gen_category_wire_errors(vs: VectorSet) -> None:
    own_pub = own_writer_pubkey(ILLEGAL_WORD)
    for vector_fn in (_wire_bad_wkey, _wire_bad_reader_id, _wire_bad_signature, _wire_bad_aes_tag,
                      _wire_bad_zlib, _wire_truncated_zlib, _wire_oversize_zlib,
                      _wire_truncated_tuple, _wire_invalid_utf8, _wire_overlength_name):
        vector_fn(vs, own_pub)


# ── Category 4: `next cmdata derivation path` ──────────────────────────────────
#
# All four vectors decode cleanly at the wire layer (decode.py has no
# special handling of this TYPE at all -- it's just another triple);
# the behaviors being tested live in CenturyMetadata.load(), which is
# where SPECIFICATION.md's chain-following semantics are actually
# implemented. So each gets its own "margin"-onward identity plus an
# embedded text record, same as any other decodable vector.

def _next_derivation_valid_chain(vs: VectorSet) -> None:
    word = "mom"
    id0 = identity_for_word(word, n=0)
    id1 = identity_for_word(word, n=1)

    # CMDATA-SPEC:
    # - MUST set `CONTENTS` to the derivation path `N` for the next file, as the ASCII representation of a decimal number.
    # CMDATA-SPEC:
    # - MUST choose `N` for the next file greater than this one.
    triples0 = [
        text_record("First file of a 2-file chain; the second is at derivation slot N=1."),
        (NEXT_DERIVATION_TYPE, "", "1"),
    ]
    after_pre0 = encode_after_pre(id0, 0, *triples0)
    triples1 = [text_record("Second (final) file of the chain, reached via N=0's "
                            "`next cmdata derivation path` record.")]
    after_pre1 = encode_after_pre(id1, 0, *triples1)

    doc = CenturyMetadata()
    # CMDATA-SPEC:
    # - SHOULD fetch the file for that `N` value and continue processing records from that after this file.
    errors0, next_n = doc.load(id0, 0, centurymetadata.preamble + after_pre0)
    assert not any(e.fatal for e in errors0)
    assert next_n == 1
    errors1, next_n2 = doc.load(id1, 1, centurymetadata.preamble + after_pre1)
    assert not any(e.fatal for e in errors1)
    assert next_n2 is None
    assert len(doc.records) == 2

    vs.store(
        "next-derivation", "valid-chain-n0", "First file of a valid 2-file chain (N=0 -> N=1).",
        ["MUST set `CONTENTS` to the derivation path `N` for the next file, as the ASCII "
         "representation of a decimal number.",
         "MUST choose `N` for the next file greater than this one."],
        word, 0, id0, 0, after_pre0, records=triples0)
    vs.store(
        "next-derivation", "valid-chain-n1", "Second file of the chain, at N=1.",
        ["SHOULD fetch the file for that `N` value and continue processing records from "
         "that after this file."],
        word, 1, id1, 1, after_pre1, records=triples1)


def _next_derivation_bad_contents_not_decimal(vs: VectorSet) -> None:
    word = "more"
    identity = identity_for_word(word)
    # CMDATA-SPEC:
    # - MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is not greater than
    #   `N` for this file.
    triples = [
        text_record("`next cmdata derivation path` CONTENTS is not a valid decimal number "
                    "-- the file still decodes fine; only the (would-be) chain link is dropped."),
        (NEXT_DERIVATION_TYPE, "", "not-a-number"),
    ]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, [triples[0]])
    doc = CenturyMetadata()
    errors, next_n = doc.load(identity, 0, centurymetadata.preamble + after_pre)
    assert not any(e.fatal for e in errors)
    assert next_n is None
    vs.store(
        "next-derivation", "bad-contents-not-decimal",
        "`next cmdata derivation path` CONTENTS is not a valid decimal number.",
        ["MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is "
         "not greater than `N` for this file."],
        word, 0, identity, 0, after_pre,
        invalid="`next cmdata derivation path` CONTENTS is not a valid decimal number "
                "(that record must fail to parse; the rest of the file is unaffected).",
        records=triples)


def _next_derivation_bad_contents_not_greater(vs: VectorSet) -> None:
    word = "morning"
    identity = identity_for_word(word, n=0)
    # CMDATA-SPEC:
    # - MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is not greater than
    #   `N` for this file.
    triples = [
        text_record("`next cmdata derivation path` CONTENTS (0) is not greater than this "
                    "file's own N (0) -- the file still decodes fine; only the chain link is dropped."),
        (NEXT_DERIVATION_TYPE, "", "0"),
    ]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, [triples[0]])
    doc = CenturyMetadata()
    errors, next_n = doc.load(identity, 0, centurymetadata.preamble + after_pre)
    assert not any(e.fatal for e in errors)
    assert next_n is None
    vs.store(
        "next-derivation", "bad-contents-not-greater",
        "`next cmdata derivation path` CONTENTS equals this file's own N, not greater.",
        ["MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is "
         "not greater than `N` for this file."],
        word, 0, identity, 0, after_pre,
        invalid="`next cmdata derivation path` CONTENTS is not greater than N (that record "
                "must fail to parse; the rest of the file is unaffected).",
        records=triples)


def _next_derivation_duplicate_records(vs: VectorSet) -> None:
    word = "nation"
    identity = identity_for_word(word)
    # CMDATA-SPEC:
    # - MUST NOT follow multiple `next cmdata derivation path` records in the same file.
    triples = [
        text_record("Two `next cmdata derivation path` records in one file -- only the first "
                    "is followed."),
        (NEXT_DERIVATION_TYPE, "", "1"),
        (NEXT_DERIVATION_TYPE, "", "2"),
    ]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, [triples[0]])
    doc = CenturyMetadata()
    errors, next_n = doc.load(identity, 0, centurymetadata.preamble + after_pre)
    assert not any(e.fatal for e in errors)
    assert next_n == 1  # first one wins, second is ignored
    vs.store(
        "next-derivation", "duplicate-records",
        "Two `next cmdata derivation path` records in the same file.",
        ["MUST NOT follow multiple `next cmdata derivation path` records in the same file."],
        word, 0, identity, 0, after_pre,
        invalid="file contains two `next cmdata derivation path` records (writer MUST NOT "
                "create more than one); reader must ignore all but the first.",
        records=triples)


def gen_category_next_derivation(vs: VectorSet) -> None:
    _next_derivation_valid_chain(vs)
    _next_derivation_bad_contents_not_decimal(vs)
    _next_derivation_bad_contents_not_greater(vs)
    _next_derivation_duplicate_records(vs)


# ── Category 5: priority ordering & chain splitting ────────────────────────────
#
# Built via the real CenturyMetadata class (add()/authorize_slot()/save()),
# not the low-level encode() path used elsewhere -- this exercises the
# actual production write path, same as the test suite does. One
# consequence: CenturyMetadata.add() only accepts recognized types or
# "_"-prefixed ones, so these vectors can't carry the usual bare "text"
# purpose record (add() would reject it) -- their purpose lives only in
# the manifest.

def _priority_ordering(vs: VectorSet) -> None:
    from centurymetadata import DescriptorRecord, PsbtRecord, TransactionRecord, WalletLabelsRecord

    word = "neck"
    identity = identity_for_word(word)
    doc = CenturyMetadata()
    # Added out of priority order deliberately, to prove save() writes in
    # decreasing-priority order regardless of add() order. CONTENTS here
    # is placeholder text, not semantically valid PSBT/descriptor/tx --
    # see category 8 for realistic per-type CONTENTS.
    doc.add(WalletLabelsRecord('{"ref": "placeholder", "label": "not semantically validated here", "type": "tx"}\n',
                               "Demo Wallet"))
    doc.add(PsbtRecord("cHNidP8AplaceholderNotARealPSBT==", ""))
    doc.add(DescriptorRecord("pkh(placeholder-not-a-real-descriptor)", "Demo Wallet"))
    doc.add(TransactionRecord("00" * 32, name=""))
    doc.authorize_slot(0)

    # CMDATA-SPEC/Writer Requirements:
    # - MUST write tuples in decreasing priority order (see [Suggested Type Priorities](#suggested-type-priorities)).
    files, need_more = doc.save(lambda n: identity)
    assert not need_more
    assert len(files) == 1
    _n, data = files[0]
    after_pre = data[len(centurymetadata.preamble):]

    errors, triples = centurymetadata.decode(
        identity.reader_secp_privkey, identity.reader_mlkem_privkey,
        identity.reader_mlkem_pubkey, identity.writer_privkey.pubkey, data)
    assert not any(e.fatal for e in errors)
    types_in_order = [t for t, _, _ in triples]
    assert types_in_order == [
        "bitcoin output script descriptor", "bitcoin psbt", "bitcoin transaction", "bitcoin wallet labels",
    ], types_in_order

    vs.store(
        "priority-ordering", "mixed-types",
        "Four record types added out of order; save() writes them in decreasing priority "
        "order (descriptor, psbt/transaction, wallet labels).",
        ["MUST write tuples in decreasing priority order (see [Suggested Type Priorities]"
         "(#suggested-type-priorities))."],
        word, 0, identity, 0, after_pre, records=triples)


def _priority_split_chain(vs: VectorSet) -> None:
    from centurymetadata import DescriptorRecord, TransactionRecord

    word = "neglect"
    id0 = identity_for_word(word, n=0)
    id1 = identity_for_word(word, n=1)

    doc = CenturyMetadata()
    doc.add(DescriptorRecord("pkh(placeholder-small-descriptor)", "Demo Wallet"))
    # Filler forces a split: hex-of-random-bytes still compresses (each
    # byte becomes two hex nibbles from a 16-symbol alphabet, which
    # zlib can exploit even though the underlying bytes are random), so
    # this needs to be big enough to still exceed PLAINTEXT_LENGTH once
    # compressed alongside the descriptor and a next-derivation-path
    # tail, even though it fits (just) on its own -- verified
    # empirically against the real compress() pipeline; deterministic
    # so that fact doesn't depend on which random bytes a given run
    # happens to draw.
    doc.add(TransactionRecord(deterministic_filler("priority-split-filler", 12550).hex(), name=""))
    doc.authorize_slot(0)
    doc.authorize_slot(1)

    # CMDATA-SPEC/Writer Requirements:
    # - Add a `next cmdata derivation path` type record and place the remaining tuples in the next century metadata file.
    files, need_more = doc.save(lambda n: id0 if n == 0 else id1)
    assert not need_more
    assert len(files) == 2

    doc2 = CenturyMetadata()
    errors0, next_n = doc2.load(id0, 0, files[0][1])
    assert not any(e.fatal for e in errors0)
    assert next_n == 1
    errors1, next_n2 = doc2.load(id1, 1, files[1][1])
    assert not any(e.fatal for e in errors1)
    assert next_n2 is None
    assert len(doc2.records) == 2

    for n, data in files:
        after_pre = data[len(centurymetadata.preamble):]
        file_identity = id0 if n == 0 else id1
        errors, triples = centurymetadata.decode(
            file_identity.reader_secp_privkey, file_identity.reader_mlkem_privkey,
            file_identity.reader_mlkem_pubkey, file_identity.writer_privkey.pubkey, data)
        assert not any(e.fatal for e in errors)
        # Confirm content actually landed on *this* file, not just that
        # the pair adds up to 2 records overall (decode() -- unlike
        # CenturyMetadata.load() -- still returns the next-derivation-path
        # tuple itself, so exclude it before counting real content).
        real_records = [t for t in triples if t[0] != NEXT_DERIVATION_TYPE]
        assert len(real_records) == 1, "expected exactly 1 real record on file N={}, got {}".format(
            n, real_records)
        vs.store(
            "priority-ordering", "oversized-split-n{}".format(n),
            "Part of a 2-file chain: an oversized record set split across derivation "
            "slots N=0 and N=1 (this is file N={}).".format(n),
            ["Add a `next cmdata derivation path` type record and place the remaining "
             "tuples in the next century metadata file."],
            word, n, file_identity, n, after_pre, records=triples)


def gen_category_priority_and_split(vs: VectorSet) -> None:
    _priority_ordering(vs)
    _priority_split_chain(vs)


# ── Category 6: unknown-type round-trip ────────────────────────────────────────

def gen_category_unknown_type(vs: VectorSet) -> None:
    from centurymetadata import UnknownRecord

    # A non-standard, "_"-prefixed type round-trips through
    # CenturyMetadata untouched -- the reference implementation's
    # equivalent of "reader ignores it, writer preserves it".
    #
    # CMDATA-SPEC/Writer Requirements:
    # - If it uses a `TYPE` not defined in this specification:
    #   - MUST begin the type string with `_`.
    # [NOTE: the converse -- CenturyMetadata.add() rejecting a
    # [NOTE: non-"_"-prefixed unrecognized TYPE -- has no on-disk vector
    # [NOTE: to show: add() raises ValueError at construction time, so
    # [NOTE: there's no file to store (see centurymetadata.py's add()).]
    word = "never"
    identity = identity_for_word(word)
    doc = CenturyMetadata()
    doc.add(UnknownRecord("_experimental widget",
                          name="Widget label",
                          contents="Some future, non-standard record type this implementation "
                                   "doesn't recognize but must still preserve."))
    doc.authorize_slot(0)
    files, need_more = doc.save(lambda n: identity)
    assert not need_more
    assert len(files) == 1
    _n, data = files[0]
    after_pre = data[len(centurymetadata.preamble):]

    # Round-trip: load it back and confirm the unknown record survived
    # untouched.
    doc2 = CenturyMetadata()
    errors, _next_n = doc2.load(identity, 0, data)
    assert not any(e.fatal for e in errors)
    unknowns = doc2.unknown_records()
    assert len(unknowns) == 1
    assert unknowns[0].rtype == "_experimental widget"
    assert unknowns[0].contents == ("Some future, non-standard record type this "
                                    "implementation doesn't recognize but must still preserve.")
    triples = [(u.rtype, u.name, u.contents) for u in unknowns]

    vs.store(
        "unknown-type", "underscore-prefixed",
        "A non-standard `_experimental widget` type record, which must round-trip "
        "untouched even though this implementation doesn't recognize it.",
        ["If it uses a `TYPE` not defined in this specification: MUST begin the type "
         "string with `_`."],
        word, 0, identity, 0, after_pre, records=triples)


# ── Category 7: to-self vs not-to-self error recovery ──────────────────────────
#
# The exact same malformed (invalid-UTF8) middle tuple, sandwiched
# between two valid ones, encoded twice: once with WRITER_PUBKEY equal
# to the reader's own derived writer key ("to-self" -- trusted, so
# decode() must keep going), once with an unrelated writer ("not-to-self"
# -- untrusted, so decode() may stop). Combines the per-record-error and
# to-self rules from category 3 and 4's simpler, single-rule vectors.

def gen_category_to_self_vs_not(vs: VectorSet) -> None:
    word = "noble"
    raw = (b"text\x00before\x00valid tuple before the error\x00"
           + b"text\x00bad\x00" + b'\xff\xfe' + b"\x00"
           + b"text\x00after\x00valid tuple after the error\x00")
    padded = raw_compress(raw)
    before_triple = ("text", "before", "valid tuple before the error")
    after_triple = ("text", "after", "valid tuple after the error")

    # CMDATA-SPEC/Reader Requirements:
    #   - If this record "fails to parse" (defined below):
    #     - If this is a "to-self" file:
    #       - MUST continue parsing remaining tuples
    #     - Otherwise (not a "to-self" file):
    #       - MAY continue parsing remaining tuples
    to_self_identity = identity_for_word(word)
    to_self_after_pre = build_after_pre(to_self_identity, 0, padded)
    to_self_full = centurymetadata.preamble + to_self_after_pre
    errors, triples = centurymetadata.decode(
        to_self_identity.reader_secp_privkey, to_self_identity.reader_mlkem_privkey,
        to_self_identity.reader_mlkem_pubkey, to_self_identity.writer_privkey.pubkey, to_self_full)
    assert not any(e.fatal for e in errors)
    assert any(e.code == CMDataErrorCode.INVALID_UTF8 for e in errors)
    assert before_triple in triples
    assert after_triple in triples
    vs.store(
        "to-self-vs-not", "to-self-continues",
        "to-self file: an invalid-UTF8 tuple in the middle is skipped, and parsing "
        "continues to later valid tuples.",
        ["If this is a \"to-self\" file: MUST continue parsing remaining tuples"],
        word, 0, to_self_identity, 0, to_self_after_pre,
        invalid="middle tuple has invalid UTF-8 bytes in CONTENTS (per-record failure); "
                "to-self file, so the reader must continue past it.",
        plaintext=raw)

    foreign_writer = identity_for_word("scorpion").writer_privkey
    not_self_identity = identity_for_word(word, writer_privkey=foreign_writer)
    not_self_after_pre = build_after_pre(not_self_identity, 0, padded)
    not_self_full = centurymetadata.preamble + not_self_after_pre
    errors2, triples2 = centurymetadata.decode(
        not_self_identity.reader_secp_privkey, not_self_identity.reader_mlkem_privkey,
        not_self_identity.reader_mlkem_pubkey, own_writer_pubkey(word), not_self_full)
    assert not any(e.fatal for e in errors2)
    assert any(e.code == CMDataErrorCode.INVALID_UTF8 for e in errors2)
    assert before_triple in triples2
    assert after_triple not in triples2
    vs.store(
        "to-self-vs-not", "not-to-self-may-stop",
        "not-to-self file: the same invalid-UTF8 tuple, but written by an unrelated "
        "party -- the reference implementation stops there rather than keep processing "
        "an untrusted file.",
        ["Otherwise (not a \"to-self\" file): MAY continue parsing remaining tuples"],
        word, 0, not_self_identity, 0, not_self_after_pre,
        invalid="middle tuple has invalid UTF-8 bytes in CONTENTS (per-record failure); "
                "not-to-self file, so the reader may stop there (this reference "
                "implementation does).",
        plaintext=raw, writer="scorpion")


# ── Category 8: per-type CONTENTS semantics ─────────────────────────────────────
#
# The most complex category: realistic CONTENTS built with embit (already
# a project dependency, via centurymetadata.validate), checked two ways --
# centurymetadata.decode() (wire layer: none of these types are special
# to decode.py, so "invalid content" vectors still decode cleanly) and
# centurymetadata.validate.validate_triples() (content layer: this is
# where "MUST fail to parse the record" for a bad PSBT/tx/descriptor/
# labels actually gets enforced -- decode.py and CenturyMetadata's
# per-type Record classes don't validate CONTENTS semantics at all).
#
# [NOTE: validate.py is stricter than the spec in two ways relevant
# [NOTE: here: it requires non-empty NAME for every type (spec allows
# [NOTE: empty NAME for psbt/transaction), and it rejects a wallet-labels
# [NOTE: record outright if *any* line has an unknown `type` field
# [NOTE: (spec says a reader MUST ignore just that one JSONL line and
# [NOTE: keep processing the rest). The valid-content vectors below use
# [NOTE: non-empty NAME throughout to stay compatible with validate.py;
# [NOTE: the unknown-type-field vector is checked only via decode(), with
# [NOTE: the validate.py gap called out explicitly in its manifest entry.]

def _sample_transaction_hex() -> str:
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    tx = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(1000, Script(bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])))])
    return tx.serialize().hex()


def _sample_psbt_base64() -> str:
    from embit.psbt import PSBT
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    tx = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(1000, Script(bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])))])
    return PSBT(tx).to_string()


def _sample_descriptor(seed: bytes) -> str:
    from embit.descriptor.checksum import checksum as descriptor_checksum
    pub = PrivateKey(seed).pubkey.serialize().hex()
    body = "wpkh({})".format(pub)
    return "{}#{}".format(body, descriptor_checksum(body))


def _content_vector(vs: VectorSet, word: str, rtype: str, name: str, contents: str,
                    purpose: str, category_name: str, spec_bullets: List[str],
                    expect_valid: bool) -> None:
    from centurymetadata import validate

    identity = identity_for_word(word)
    triples = [text_record(purpose), (rtype, name, contents)]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, [triples[1]])
    err = validate.validate_triples([triples[1]])
    if expect_valid:
        assert err is None, err
        invalid = None
    else:
        assert err is not None
        invalid = "validate.validate_triples() rejects the CONTENTS: {}".format(err)
    vs.store("per-type-contents", category_name, purpose, spec_bullets, word, 0, identity, 0, after_pre,
             invalid=invalid, records=triples)


def gen_category_per_type_contents(vs: VectorSet) -> None:
    # CMDATA-SPEC:
    # - MUST set `CONTENTS` to a valid base-64 encoded PSBT ([version 0](#ref-psbt) or [version 2](#ref-psbt2)).
    _content_vector(
        vs, "obvious", "bitcoin psbt", "Demo PSBT", _sample_psbt_base64(),
        "A real (if minimal) PSBT, constructed and verified via embit.", "psbt-valid",
        ["MUST set `CONTENTS` to a valid base-64 encoded PSBT ([version 0](#ref-psbt) or "
         "[version 2](#ref-psbt2))."], expect_valid=True)
    # CMDATA-SPEC:
    # - If `CONTENTS` is not a valid base-64 encoded PSBT, or an unknown PSBT version:
    #   - MUST fail to parse the record.
    _content_vector(
        vs, "ocean", "bitcoin psbt", "Demo PSBT", "not-a-real-psbt-at-all",
        "CONTENTS is not a valid base64-encoded PSBT.", "psbt-invalid",
        ["If `CONTENTS` is not a valid base-64 encoded PSBT, or an unknown PSBT version: "
         "MUST fail to parse the record."], expect_valid=False)

    # CMDATA-SPEC:
    # - MUST set `CONTENTS` to a valid hex-encoded bitcoin transaction.
    _content_vector(
        vs, "oil", "bitcoin transaction", "Demo Transaction", _sample_transaction_hex(),
        "A real (if minimal) transaction, constructed and verified via embit.", "transaction-valid",
        ["MUST set `CONTENTS` to a valid hex-encoded bitcoin transaction."], expect_valid=True)
    # CMDATA-SPEC:
    # - If `CONTENTS` is not a valid hex-encoded bitcoin transaction:
    #   - MUST fail to parse the record.
    _content_vector(
        vs, "orphan", "bitcoin transaction", "Demo Transaction", "not-hex-at-all",
        "CONTENTS is not a valid hex-encoded transaction.", "transaction-invalid",
        ["If `CONTENTS` is not a valid hex-encoded bitcoin transaction: MUST fail to "
         "parse the record."], expect_valid=False)

    # CMDATA-SPEC:
    # - MUST place a valid script BIP-380 descriptor describing the wallet format in the `CONTENTS` field.
    _content_vector(
        vs, "oxygen", "bitcoin output script descriptor", "Demo Wallet",
        _sample_descriptor(hashlib.sha256(b"gen_test_vectors descriptor oxygen").digest()),
        "A real wpkh() descriptor with a correct checksum, constructed and verified via embit.",
        "descriptor-valid",
        ["MUST place a valid script BIP-380 descriptor describing the wallet format in "
         "the `CONTENTS` field."], expect_valid=True)
    # CMDATA-SPEC:
    # - If `CONTENTS` is not a valid output script descriptor, OR contains a checksum which does not match:
    #   - MUST fail to parse the record.
    good_desc = _sample_descriptor(hashlib.sha256(b"gen_test_vectors descriptor pause").digest())
    bad_checksum_desc = good_desc[:-1] + ("0" if good_desc[-1] != "0" else "1")
    _content_vector(
        vs, "pause", "bitcoin output script descriptor", "Demo Wallet", bad_checksum_desc,
        "A wpkh() descriptor whose trailing checksum doesn't match its body.",
        "descriptor-bad-checksum",
        ["If `CONTENTS` is not a valid output script descriptor, OR contains a checksum "
         "which does not match: MUST fail to parse the record."], expect_valid=False)
    # CMDATA-SPEC:
    # - If `CONTENTS` contains unknown or unsupported script expressions:
    #   - MUST fail to parse the record.
    _content_vector(
        vs, "peasant", "bitcoin output script descriptor", "Demo Wallet",
        "futuredescriptorfn(deadbeef)",
        "A descriptor using a script expression this implementation (and BIP-380) "
        "doesn't define -- e.g. a hypothetical future extension.",
        "descriptor-unsupported-expression",
        ["If `CONTENTS` contains unknown or unsupported script expressions: MUST fail "
         "to parse the record."], expect_valid=False)

    labels_txid = hashlib.sha256(b"gen_test_vectors demo txid").hexdigest()
    # CMDATA-SPEC:
    # - MUST set `CONTENTS` to the JSONL encoding of the wallet labels as per BIP-329.
    _content_vector(
        vs, "permit", "bitcoin wallet labels", "Demo Wallet",
        '{{"type": "tx", "ref": "{}", "label": "Coffee"}}\n'.format(labels_txid),
        "A single valid BIP-329 label line.", "wallet-labels-valid",
        ["MUST set `CONTENTS` to the JSONL encoding of the wallet labels as per "
         "[BIP-329](#ref-bip329)."], expect_valid=True)
    # CMDATA-SPEC:
    # - If `CONTENTS` is not valid JSONL:
    #   - MUST fail to parse the record.
    _content_vector(
        vs, "piano", "bitcoin wallet labels", "Demo Wallet", '{"type": "tx", "ref": "not closed',
        "CONTENTS is not valid JSONL (unterminated JSON object).", "wallet-labels-invalid-json",
        ["If `CONTENTS` is not valid JSONL: MUST fail to parse the record."], expect_valid=False)

    # This one is checked only via decode(), not validate.validate_triples():
    # validate.py rejects the whole record for one unknown `type` line (see
    # this category's opening [NOTE:]), stricter than the spec below.
    # CMDATA-SPEC:
    # - If `CONTENTS` contains an unknown `type` field:
    #   - MUST ignore that object.
    identity = identity_for_word("proof")
    contents = ('{{"type": "future_label_type", "ref": "irrelevant"}}\n'
                '{{"type": "tx", "ref": "{}", "label": "Coffee"}}\n').format(labels_txid)
    triples = [text_record("One line has an unknown `type` field; a compliant reader "
                           "ignores just that line and keeps the rest."),
               ("bitcoin wallet labels", "Demo Wallet", contents)]
    after_pre = encode_after_pre(identity, 0, *triples)
    verify_clean(identity, identity.writer_privkey.pubkey, after_pre, [triples[1]])
    from centurymetadata import validate
    err = validate.validate_triples([triples[1]])
    assert err is not None  # the documented validate.py-vs-spec gap
    vs.store(
        "per-type-contents", "wallet-labels-unknown-type-field",
        "One JSONL line has an unknown `type` field alongside one valid line -- spec "
        "says a reader ignores just that line; validate.py (stricter) rejects the whole "
        "record ({}).".format(err),
        ["If `CONTENTS` contains an unknown `type` field: MUST ignore that object."],
        "proof", 0, identity, 0, after_pre, records=triples)


# ── Driver ──────────────────────────────────────────────────────────────────────

CATEGORIES = [
    gen_category_baseline,
    gen_category_gen_ordering,
    gen_category_wire_errors,
    gen_category_next_derivation,
    gen_category_priority_and_split,
    gen_category_unknown_type,
    gen_category_to_self_vs_not,
    gen_category_per_type_contents,
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="BASEDIR to populate (must not already exist)")
    args = parser.parse_args()

    if args.directory.exists():
        print("{} already exists; refusing to overwrite".format(args.directory), file=sys.stderr)
        sys.exit(1)
    (args.directory / SKELETON_DIR / SKELETON_BUNDLE).mkdir(parents=True)

    vs = VectorSet(args.directory)
    for category in CATEGORIES:
        category(vs)
    vs.write_manifest()

    print("Wrote {} vectors to {}".format(len(vs.manifest), args.directory), file=sys.stderr)


if __name__ == "__main__":
    main()
