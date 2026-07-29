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
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

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


def writer_privkey_for(label: str) -> PrivateKey:
    """A deterministic, distinct writer keypair for `label` -- lets many
    vectors share one reader_id while still getting distinct
    <reader_id>+<writer> mirror directories."""
    return PrivateKey(hashlib.sha256(b"gen_test_vectors writer " + label.encode()).digest())


def illegal_identity(label: str) -> Identity:
    """The fixed "illegal" reader_id, with a fresh writer key per label --
    used for every deliberately-invalid (can't/shouldn't decode) vector."""
    return identity_for_word(ILLEGAL_WORD, writer_privkey_for("illegal/" + label))


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
    expected_outcome: str
    reader_id: str
    writer_pubkey: str
    gens: List[int] = field(default_factory=list)


class VectorSet:
    """Accumulates manifest entries and writes files into the mirror tree."""

    def __init__(self, basedir: Path) -> None:
        self.basedir = basedir
        self.bundle_dir = basedir / SKELETON_DIR / SKELETON_BUNDLE
        self.manifest: List[ManifestEntry] = []

    def store(self, category: str, name: str, description: str, spec_bullets: List[str],
              expected_outcome: str, identity: Identity, gen: int, after_pre: bytes) -> None:
        assert len(after_pre) == centurymetadata.DATA_LENGTH
        reader_id_hex = identity.reader_id.hex()
        writer_hex = identity.writer_privkey.pubkey.serialize().hex()
        record_dir = self.bundle_dir / (reader_id_hex + "+" + writer_hex)
        record_dir.mkdir(parents=True, exist_ok=True)
        gen_hex = gen.to_bytes(8, "big").hex()
        (record_dir / gen_hex).write_bytes(after_pre)

        for entry in self.manifest:
            if entry.reader_id == reader_id_hex and entry.writer_pubkey == writer_hex:
                entry.gens.append(gen)
                return
        self.manifest.append(ManifestEntry(
            category=category, name=name, description=description, spec_bullets=spec_bullets,
            expected_outcome=expected_outcome, reader_id=reader_id_hex, writer_pubkey=writer_hex,
            gens=[gen]))

    def write_manifest(self) -> None:
        data = [
            {
                "category": e.category,
                "name": e.name,
                "description": e.description,
                "spec_bullets": e.spec_bullets,
                "expected_outcome": e.expected_outcome,
                "reader_id": e.reader_id,
                "writer_pubkey": e.writer_pubkey,
                "gens": e.gens,
                "path": "{}/{}/{}+{}".format(SKELETON_DIR, SKELETON_BUNDLE, e.reader_id, e.writer_pubkey),
            }
            for e in self.manifest
        ]
        (self.basedir / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")


# ── Extra identity helper ──────────────────────────────────────────────────────

def throwaway_identity(label: str) -> Identity:
    """A fully valid, but not "known", identity for scenarios that just
    need *some* distinct reader/writer keys -- e.g. a file legitimately
    encoded for a different reader than the one storing/fetching it."""
    def key(salt: bytes) -> bytes:
        return hashlib.sha256(salt + label.encode()).digest()
    writer_privkey = PrivateKey(key(b"writer"))
    reader_secp_privkey = PrivateKey(key(b"reader-secp"))
    reader_mlkem_pubkey, reader_mlkem_privkey = centurymetadata.derive_mlkem_keypair(key(b"reader-mlkem"))
    return Identity(writer_privkey, reader_secp_privkey, reader_mlkem_pubkey, reader_mlkem_privkey)


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
        "decodes cleanly to exactly one triple", identity, 0, after_pre)


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
            "decodes cleanly", identity, gen, after_pre)


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
    identity = illegal_identity("bad_wkey")
    mutable = bytearray(encode_after_pre(identity, 0, text_record("n/a: fails before decrypt")))
    mutable[WKEY_OFF:WKEY_OFF + 1] = b'\x00'  # 0x00 is not a valid compressed-point prefix
    after_pre = bytes(mutable)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_WKEY)
    vs.store(
        "wire-errors", "bad-wkey", "WRITER_PUBKEY is not a valid compressed secp256k1 point.",
        ["MUST fail parsing if `SIG` is not a valid BIP-340 signature by `WRITER_PUBKEY`..."],
        "CMDataErrorCode.BAD_WKEY", identity, 0, after_pre)


def _wire_bad_reader_id(vs: VectorSet, own_pub: PublicKey) -> None:
    # Genuinely valid file for a *different* reader, stored under
    # "illegal"'s directory -- illegal's own keys won't match the
    # embedded READER_ID.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `READER_ID` does not equal [SHA256](#ref-sha256)(`READER_SECP_PUBKEY`|`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to.
    other = throwaway_identity("bad-reader-id/other-party")
    after_pre = encode_after_pre(other, 0, text_record("n/a: encoded for a different reader"))
    identity = illegal_identity("bad_reader_id")
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_READER_ID)
    vs.store(
        "wire-errors", "bad-reader-id",
        "READER_ID in the file belongs to a different reader than the one fetching it.",
        ["MUST fail parsing if `READER_ID` does not equal SHA256(`READER_SECP_PUBKEY`|"
         "`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to."],
        "CMDataErrorCode.BAD_READER_ID", identity, 0, after_pre)


def _wire_bad_signature(vs: VectorSet, own_pub: PublicKey) -> None:
    # SIG bytes corrupted after a genuinely valid build.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `SIG` is not a valid [BIP-340](#ref-bip340) signature by `WRITER_PUBKEY` over
    #   SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    identity = illegal_identity("bad_signature")
    mutable = bytearray(encode_after_pre(identity, 0, text_record("n/a: fails before decrypt")))
    mutable[SIG_OFF] ^= 0xFF
    after_pre = bytes(mutable)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_SIGNATURE)
    vs.store(
        "wire-errors", "bad-signature", "SIG does not verify against WRITER_PUBKEY.",
        ["MUST fail parsing if `SIG` is not a valid BIP-340 signature by `WRITER_PUBKEY` "
         "over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`)."],
        "CMDataErrorCode.BAD_SIGNATURE", identity, 0, after_pre)


def _wire_bad_aes_tag(vs: VectorSet, own_pub: PublicKey) -> None:
    # AES/GCM tag corrupted, then genuinely re-signed (since we hold the
    # real writer key) so only the tag check fails.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the trailing 16-byte authentication tag does not verify.
    identity = illegal_identity("bad_aes_tag")
    gen = 0
    comp = centurymetadata.compress([text_record("n/a: fails before decompress")])
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
        "CMDataErrorCode.BAD_AES_TAG", identity, gen, after_pre)


def _wire_bad_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # Decrypted plaintext isn't a valid zlib stream at all.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
    identity = illegal_identity("bad_zlib")
    gen = 0
    padded = os.urandom(centurymetadata.PLAINTEXT_LENGTH)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.BAD_ZLIB)
    vs.store(
        "wire-errors", "bad-zlib", "Decrypted DATA is not a valid zlib stream.",
        ["MUST fail parsing if the decrypted bytes do not contain a valid zlib stream."],
        "CMDataErrorCode.BAD_ZLIB", identity, gen, after_pre)


def _wire_truncated_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # A real zlib stream, cut short before its end marker. decode.py has
    # no *separate* quote for this: the reference implementation treats
    # truncation as the same requirement as an outright-invalid stream.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
    identity = illegal_identity("truncated_zlib")
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
        "CMDataErrorCode.TRUNCATED_ZLIB", identity, gen, after_pre)


def _wire_oversize_zlib(vs: VectorSet, own_pub: PublicKey) -> None:
    # Valid, small zlib stream that decompresses past 1MB.
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decompressed size would exceed 1048576 bytes.
    identity = illegal_identity("oversize_zlib")
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
        "CMDataErrorCode.OVERSIZE_ZLIB", identity, gen, after_pre)


def _wire_truncated_tuple(vs: VectorSet, own_pub: PublicKey) -> None:
    # A complete tuple followed by a dangling incomplete one.
    # CMDATA-SPEC/Reader Requirements:
    #   - MUST stop processing (keeping all tuples already parsed) upon reaching a tuple for which fewer than three
    #     NUL-terminated fields remaing.
    identity = illegal_identity("truncated_tuple")
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
        "CMDataErrorCode.TRUNCATED_TUPLE", identity, gen, after_pre)


def _wire_invalid_utf8(vs: VectorSet, own_pub: PublicKey) -> None:
    # CONTENTS field contains invalid UTF-8 bytes.
    # CMDATA-SPEC/Reader Requirements:
    #   - If any of `TYPE`, `NAME` or `CONTENTS` are not a valid, complete UTF-8 string:
    #     - MUST fail to parse this record
    identity = illegal_identity("invalid_utf8")
    gen = 0
    raw = b"text\x00note\x00" + b'\xff\xfe\xfd' + b"\x00"
    padded = raw_compress(raw)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.INVALID_UTF8)
    vs.store(
        "wire-errors", "invalid-utf8", "CONTENTS field is not valid, complete UTF-8.",
        ["If any of `TYPE`, `NAME` or `CONTENTS` are not a valid, complete UTF-8 string: "
         "MUST fail to parse this record"],
        "CMDataErrorCode.INVALID_UTF8", identity, gen, after_pre)


def _wire_overlength_name(vs: VectorSet, own_pub: PublicKey) -> None:
    # NAME field over 255 bytes.
    # CMDATA-SPEC/Reader Requirements:
    #   - Otherwise, if `NAME` is greater than 255 bytes:
    #     - MUST fail to parse this record
    identity = illegal_identity("overlength_name")
    gen = 0
    raw = b"text\x00" + b"n" * 300 + b"\x00overlength name test\x00"
    padded = raw_compress(raw)
    after_pre = build_after_pre(identity, gen, padded)
    verify_error(identity, own_pub, after_pre, CMDataErrorCode.OVERLENGTH_NAME)
    vs.store(
        "wire-errors", "overlength-name", "NAME field exceeds 255 bytes.",
        ["Otherwise, if `NAME` is greater than 255 bytes: MUST fail to parse this record"],
        "CMDataErrorCode.OVERLENGTH_NAME", identity, gen, after_pre)


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
        "decodes cleanly; CenturyMetadata.load() reports next_n=1", id0, 0, after_pre0)
    vs.store(
        "next-derivation", "valid-chain-n1", "Second file of the chain, at N=1.",
        ["SHOULD fetch the file for that `N` value and continue processing records from "
         "that after this file."],
        "decodes cleanly; chain ends here (no further next-derivation record)", id1, 1, after_pre1)


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
        "decodes cleanly overall; CenturyMetadata.load() reports next_n=None", identity, 0, after_pre)


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
        "decodes cleanly overall; CenturyMetadata.load() reports next_n=None", identity, 0, after_pre)


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
        "decodes cleanly; CenturyMetadata.load() follows only the first (next_n=1)",
        identity, 0, after_pre)


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
        "decodes cleanly; on-wire TYPE order is descriptor, psbt, transaction, wallet-labels",
        identity, 0, after_pre)


def _priority_split_chain(vs: VectorSet) -> None:
    from centurymetadata import DescriptorRecord, TransactionRecord

    word = "neglect"
    id0 = identity_for_word(word, n=0)
    id1 = identity_for_word(word, n=1)

    doc = CenturyMetadata()
    doc.add(DescriptorRecord("pkh(placeholder-small-descriptor)", "Demo Wallet"))
    # Incompressible filler forces a split: this won't fit alongside the
    # descriptor once a next-derivation-path tail is reserved.
    doc.add(TransactionRecord(os.urandom(8000).hex(), name=""))
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
        vs.store(
            "priority-ordering", "oversized-split-n{}".format(n),
            "Part of a 2-file chain: an oversized record set split across derivation "
            "slots N=0 and N=1 (this is file N={}).".format(n),
            ["Add a `next cmdata derivation path` type record and place the remaining "
             "tuples in the next century metadata file."],
            "decodes cleanly; the 2 files round-trip via CenturyMetadata.load() to the "
            "original 2 records", id0 if n == 0 else id1, n, after_pre)


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

    vs.store(
        "unknown-type", "underscore-prefixed",
        "A non-standard `_experimental widget` type record, which must round-trip "
        "untouched even though this implementation doesn't recognize it.",
        ["If it uses a `TYPE` not defined in this specification: MUST begin the type "
         "string with `_`."],
        "decodes cleanly; round-trips through CenturyMetadata.load() unchanged",
        identity, 0, after_pre)


# ── Driver ──────────────────────────────────────────────────────────────────────

CATEGORIES = [
    gen_category_baseline,
    gen_category_gen_ordering,
    gen_category_wire_errors,
    gen_category_next_derivation,
    gen_category_priority_and_split,
    gen_category_unknown_type,
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
