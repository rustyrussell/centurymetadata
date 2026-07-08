#!/usr/bin/env python3
"""
Generate implementation-independent test vectors for centurymetadata v1.

Each vector separates "provided values" (mnemonic, choices, test constants)
from "results" (all derived/computed fields), using the exact field names
from the centurymetadata v1 preamble.  Every entry carries a description so
the file is self-explanatory without reading the spec.

Run from the python/ subdirectory (which has the venv and dependencies):

    cd python && uv run python ../tools/generate_test_vectors.py

Three test cases:
  1. "abandon abandon ... about", N=0
  2. "abandon abandon ... about", N=1
  3. "zoo zoo ... abstract",      N=2^31-1  (max hardened BIP-32 index)

All three use: TYPE="text", NAME="note", CONTENTS="This is a test string", GEN=0.

Determinism notes (test-vector-only choices, not protocol requirements):
  GZIP_MTIME=0          suppress embedded timestamp in gzip header
  SCHNORR_AUX_RAND=0*32 deterministic BIP-340 Schnorr nonce
  MLKEM_ENCAPS_TAG      tag used to derive a deterministic ML-KEM encaps seed
"""

import gzip
import hashlib
import hmac as hmaclib
import json
import sys
from pathlib import Path

from Cryptodome.Cipher import AES as AESCipher
from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, ffi, lib, secp256k1_ctx

REPO_ROOT = Path(__file__).parent.parent
VECTORS_PATH = REPO_ROOT / "test_vectors.json"

# ── Protocol constants ────────────────────────────────────────────────────────

PURPOSE = 0x44315441         # BIP-32 purpose field: bytes spell 'D','1','T','A'
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FULL_LENGTH = 8192
MLKEM_CT_LENGTH = 1568
DATA_LENGTH = FULL_LENGTH - (64 + 33 + 32 + 8 + MLKEM_CT_LENGTH)  # 6487
VERSION_STR = "centurymetadata v1"   # 18 bytes, no NUL

# Preamble must match centurymetadata/constants.py exactly.
PREAMBLE = (
    VERSION_STR.encode() + b"\x00"
    + b"SIG[64]|WRITER_PUBKEY[33]|READER_ID[32]|GEN[8]|MLKEM_CT[1568]|AES[6487]\n\n"
    + b"SIG: BIP-340 SHA256(TAG|TAG|WRITER_PUBKEY|READER_ID|GEN|MLKEM_CT|AES)\n"
    + b"WRITER_PUBKEY: BIP-32 0x44315441'/N'/0'\n"
    + b"READER_SECP_PRIVKEY: BIP-32 0x44315441'/N'/1'\n"
    + b"READER_SECP_PUBKEY: G*READER_SECP_PRIVKEY\n"
    + b"READER_MLKEM_SEED_D: BIP-32 0x44315441'/N'/3'\n"
    + b"READER_MLKEM_SEED_Z: BIP-340 SHA256(MLKEM_Z_TAG|MLKEM_Z_TAG|READER_MLKEM_SEED_D)\n"
    + b'MLKEM_Z_TAG: SHA256("centurymetadata v1 mlkem-z"[26])\n'
    + b"READER_MLKEM_PRIVKEY, READER_MLKEM_PUBKEY: ML-KEM.KeyGen(d=READER_MLKEM_SEED_D,z=READER_MLKEM_SEED_Z)\n"
    + b"READER_ID: SHA256(READER_SECP_PUBKEY|READER_MLKEM_PUBKEY)\n"
    + b'TAG: SHA256("centurymetadata v1"[18])\n'
    + b"MLKEM_CT: ML-KEM-1024 (FIPS 203) ciphertext encapsulated to reader's ML-KEM key\n"
    + b"MLKEM_SECRET: ML-KEM-1024.Decaps(MLKEM_CT, READER_MLKEM_PRIVKEY)\n"
    + b"ECDH_SECRET: EC Diffie-Hellman of WRITER_PUBKEY and READER_SECP_PRIVKEY\n"
    + b"AESKEY: SHA256(ECDH_SECRET|MLKEM_SECRET)\n"
    + b"AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA\n"
    + b"DATA: gzip([TYPE\\0NAME\\0CONTENTS\\0]+), padded with 0 bytes to 6487\x00"
)

# ── Test case definitions ─────────────────────────────────────────────────────

CASES = [
    (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about",
        0,
    ),
    (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about",
        1,
    ),
    (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract",
        2**31 - 1,
    ),
]

TYPE = "text"
NAME = "note"
CONTENTS = "This is a test string"
GEN = 0

# ── BIP-32 / BIP-39 primitives ────────────────────────────────────────────────

def _bip39_to_seed(mnemonic: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048)


def _bip32_master(seed: bytes):
    h = hmaclib.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]


def _bip32_child_hardened(privkey: bytes, chaincode: bytes, index: int):
    idx = (0x80000000 | index).to_bytes(4, "big")
    h = hmaclib.new(chaincode, b"\x00" + privkey + idx, hashlib.sha512).digest()
    il, ir = h[:32], h[32:]
    child = (
        (int.from_bytes(il, "big") + int.from_bytes(privkey, "big")) % SECP256K1_N
    ).to_bytes(32, "big")
    return child, ir


def _bip340_tagged_hash(tag_str: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag_str.encode("utf-8")).digest()
    return hashlib.sha256(t + t + data).digest()


def _mlkem_keygen_seeded(d: bytes, z: bytes):
    buf = iter([d, z])
    orig = ML_KEM_1024.random_bytes
    ML_KEM_1024.random_bytes = lambda n: next(buf)
    try:
        pk, sk = ML_KEM_1024.keygen()
    finally:
        ML_KEM_1024.random_bytes = orig
    return pk, sk


def _mlkem_encaps_seeded(pk: bytes, seed: bytes):
    buf = iter([seed])
    orig = ML_KEM_1024.random_bytes
    ML_KEM_1024.random_bytes = lambda n: next(buf)
    try:
        secret, ct = ML_KEM_1024.encaps(pk)
    finally:
        ML_KEM_1024.random_bytes = orig
    return secret, ct


def _schnorr_sign(writer_priv: bytes, msg_hash: bytes, aux_rand: bytes) -> bytes:
    key = PrivateKey(writer_priv)
    sig_buf = ffi.new("char [64]")
    aux_buf = ffi.new("char [32]")
    ffi.buffer(aux_buf)[:] = aux_rand
    lib.secp256k1_schnorrsig_sign(secp256k1_ctx, sig_buf, msg_hash, key.keypair, aux_buf)
    return bytes(ffi.buffer(sig_buf, 64))


# ── Helpers for building the output dict ─────────────────────────────────────

def _pv(description: str, value) -> dict:
    """Provided-value entry (description optional when obvious)."""
    return {"description": description, "value": value}


def _pv_bare(value) -> dict:
    """Provided-value entry without a description."""
    return {"value": value}


def _r(description: str, value) -> dict:
    """Result entry."""
    return {"description": description, "value": value}


# ── Vector generator ──────────────────────────────────────────────────────────

def generate_vector(mnemonic: str, n: int) -> dict:
    # ── Provided values ───────────────────────────────────────────────────────
    # These are input choices or test-vector-specific constants.

    schnorr_aux_rand = bytes(32)
    mlkem_encaps_tag_str = "centurymetadata v1 mlkem-encaps-test"

    provided = {
        "MNEMONIC": _pv_bare(mnemonic),
        "N": _pv(
            "Key-set index - the N in BIP-32 path 0x44315441'/N'/...",
            n),
        "GEN": _pv(
            "Record generation counter (8-byte big-endian in the wire format).",
            GEN),
        "TYPE": _pv(
            "Record type, encoded as UTF-8 followed by a NUL byte in DATA.",
            TYPE),
        "NAME": _pv(
            "Record name, encoded as UTF-8 followed by a NUL byte in DATA.",
            NAME),
        "CONTENTS": _pv(
            "Record body, encoded as UTF-8 followed by a NUL byte in DATA.",
            CONTENTS),
        "GZIP_MTIME": _pv(
            "gzip header mtime field (bytes 4-7 of the stream). "
            "Set to 0 for deterministic output; gzip normally embeds the "
            "current timestamp here.",
            0),
        "SCHNORR_AUX_RAND": _pv(
            "aux_rand32 input to BIP-340 Schnorr signing (see BIP-340 'Signing', step 2). "
            "Set to 32 zero bytes for deterministic test vectors; "
            "real implementations must use cryptographically random bytes.",
            schnorr_aux_rand.hex()),
        "MLKEM_ENCAPS_TAG": _pv(
            "Tag string used to derive MLKEM_ENCAPS_SEED. "
            "Test-vector-only - not part of the protocol. "
            "Real implementations pass random bytes to ML-KEM encapsulation.",
            mlkem_encaps_tag_str),
    }

    # ── Computed results ───────────────────────────────────────────────────────
    results = {}

    # BIP-39 seed
    bip39_seed = _bip39_to_seed(mnemonic)
    results["BIP39_SEED"] = _r(
        'PBKDF2(HMAC-SHA512, MNEMONIC as UTF-8, b"mnemonic", 2048 iterations). '
        "64 bytes. Standard BIP-39 seed derivation.",
        bip39_seed.hex())

    # BIP-32 master key
    master_priv, master_chain = _bip32_master(bip39_seed)
    results["BIP32_MASTER_PRIVKEY"] = _r(
        'HMAC-SHA512(key=b"Bitcoin seed", data=BIP39_SEED), bytes [0:32]. '
        "BIP-32 master private key.",
        master_priv.hex())
    results["BIP32_MASTER_CHAINCODE"] = _r(
        'HMAC-SHA512(key=b"Bitcoin seed", data=BIP39_SEED), bytes [32:64]. '
        "BIP-32 master chain code.",
        master_chain.hex())

    # m/PURPOSE'
    purpose_priv, purpose_chain = _bip32_child_hardened(
        master_priv, master_chain, PURPOSE)
    results["BIP32_PURPOSE_PRIVKEY"] = _r(
        f"BIP-32 hardened child of master at index 0x{PURPOSE:08X} "
        f"= {PURPOSE} (ASCII 'D','1','T','A'). "
        f"Hardened index = 0x{0x80000000 | PURPOSE:08X}. "
        "parse256(IL) + master_privkey mod n, where IL = HMAC-SHA512(master_chaincode, "
        f"0x00 || master_privkey || 0x{0x80000000 | PURPOSE:08X})[0:32].",
        purpose_priv.hex())
    results["BIP32_PURPOSE_CHAINCODE"] = _r(
        f"Same HMAC-SHA512 as BIP32_PURPOSE_PRIVKEY, bytes [32:64].",
        purpose_chain.hex())

    # m/PURPOSE'/N'
    n_priv, n_chain = _bip32_child_hardened(purpose_priv, purpose_chain, n)
    results["BIP32_N_PRIVKEY"] = _r(
        f"BIP-32 hardened child of PURPOSE key at index N={n} "
        f"(hardened index 0x{0x80000000 | n:08X}). Path m/0x44315441'/{n}'.",
        n_priv.hex())
    results["BIP32_N_CHAINCODE"] = _r(
        f"Chain code at path m/0x44315441'/{n}'.",
        n_chain.hex())

    # Writer secp: m/PURPOSE'/N'/0'
    writer_secp_priv, _ = _bip32_child_hardened(n_priv, n_chain, 0)
    writer_key = PrivateKey(writer_secp_priv)
    writer_pub = writer_key.pubkey.serialize()
    results["WRITER_SECP_PRIVKEY"] = _r(
        f"BIP-32 hardened child at index 0. Full path m/0x44315441'/{n}'/0'. "
        "secp256k1 private key used to sign records.",
        writer_secp_priv.hex())
    results["WRITER_PUBKEY"] = _r(
        '"WRITER_PUBKEY: secp256k1 33-byte pubkey". '
        "Compressed public key G*WRITER_SECP_PRIVKEY. Stored verbatim in the record.",
        writer_pub.hex())

    # Reader secp: m/PURPOSE'/N'/1'
    reader_secp_priv, _ = _bip32_child_hardened(n_priv, n_chain, 1)
    reader_key = PrivateKey(reader_secp_priv)
    reader_secp_pub = reader_key.pubkey.serialize()
    results["READER_SECP_PRIVKEY"] = _r(
        '"READER_SECP_PRIVKEY: BIP-32 0x44315441\'/N\'/1\'". '
        f"Full path m/0x44315441'/{n}'/1'.",
        reader_secp_priv.hex())
    results["READER_SECP_PUBKEY"] = _r(
        '"READER_SECP_PUBKEY: G*READER_SECP_PRIVKEY". '
        "secp256k1 33-byte compressed public key.",
        reader_secp_pub.hex())

    # Reader ML-KEM seed: m/PURPOSE'/N'/3'
    reader_mlkem_seed_d, _ = _bip32_child_hardened(n_priv, n_chain, 3)
    results["READER_MLKEM_SEED_D"] = _r(
        '"READER_MLKEM_SEED_D: BIP-32 0x44315441\'/N\'/3\'". '
        f"Full path m/0x44315441'/{n}'/3'. "
        "32 bytes used as seed d in ML-KEM-1024 KeyGen.",
        reader_mlkem_seed_d.hex())

    mlkem_z_tag = hashlib.sha256(b"centurymetadata v1 mlkem-z").digest()
    results["MLKEM_Z_TAG"] = _r(
        '"MLKEM_Z_TAG: SHA256(\\"centurymetadata v1 mlkem-z\\"[26])". '
        "SHA256 of the 26-byte ASCII string. Fixed constant.",
        mlkem_z_tag.hex())

    reader_mlkem_seed_z = _bip340_tagged_hash(
        "centurymetadata v1 mlkem-z", reader_mlkem_seed_d)
    results["READER_MLKEM_SEED_Z"] = _r(
        '"READER_MLKEM_SEED_Z: BIP-340 SHA256(MLKEM_Z_TAG|MLKEM_Z_TAG|READER_MLKEM_SEED_D)". '
        "SHA256(MLKEM_Z_TAG || MLKEM_Z_TAG || READER_MLKEM_SEED_D). "
        "32 bytes used as seed z (implicit rejection value) in ML-KEM KeyGen.",
        reader_mlkem_seed_z.hex())

    reader_mlkem_pk, reader_mlkem_sk = _mlkem_keygen_seeded(
        reader_mlkem_seed_d, reader_mlkem_seed_z)
    results["READER_MLKEM_PUBKEY"] = _r(
        '"READER_MLKEM_PRIVKEY, READER_MLKEM_PUBKEY: '
        'ML-KEM.KeyGen(d=READER_MLKEM_SEED_D,z=READER_MLKEM_SEED_Z)". '
        "ML-KEM-1024 (FIPS 203) public key. KeyGen is called with random_bytes "
        "seeded: first call returns d=READER_MLKEM_SEED_D, second returns "
        "z=READER_MLKEM_SEED_Z. 1568 bytes.",
        reader_mlkem_pk.hex())
    results["READER_MLKEM_PRIVKEY"] = _r(
        "ML-KEM-1024 (FIPS 203) private key from the same KeyGen(d, z). 3168 bytes.",
        reader_mlkem_sk.hex())

    # READER_ID
    reader_id = hashlib.sha256(reader_secp_pub + reader_mlkem_pk).digest()
    results["READER_ID"] = _r(
        '"READER_ID: SHA256(READER_SECP_PUBKEY|READER_MLKEM_PUBKEY)". '
        "32 bytes. Identifies the reader/record slot. Stored verbatim in the record.",
        reader_id.hex())

    # TAG
    tag_val = hashlib.sha256(VERSION_STR.encode()).digest()
    results["TAG"] = _r(
        '"TAG: SHA256(\\"centurymetadata v1\\"[18])". '
        "SHA256 of the 18-byte version string. Fixed constant used as BIP-340 signing tag.",
        tag_val.hex())

    # ECDH
    ecdh_secret = reader_key.pubkey.ecdh(writer_secp_priv)
    results["ECDH_SECRET"] = _r(
        '"ECDH_SECRET: EC Diffie-Hellman of WRITER_PUBKEY and READER_SECP_PRIVKEY". '
        "SHA256(compressed(WRITER_SECP_PRIVKEY * READER_SECP_PUBKEY)) via secp256k1_ecdh. "
        "32 bytes. Symmetric: writer computes with (WRITER_SECP_PRIVKEY, READER_SECP_PUBKEY); "
        "reader computes with (READER_SECP_PRIVKEY, WRITER_PUBKEY) - same shared point.",
        ecdh_secret.hex())

    # ML-KEM encapsulation
    encaps_tag_hash = hashlib.sha256(mlkem_encaps_tag_str.encode()).digest()
    mlkem_encaps_seed = hashlib.sha256(
        encaps_tag_hash + encaps_tag_hash + writer_secp_priv + reader_mlkem_pk
    ).digest()
    results["MLKEM_ENCAPS_SEED"] = _r(
        "Test-vector-only. BIP-340 tagged hash: "
        "SHA256(SHA256(MLKEM_ENCAPS_TAG) | SHA256(MLKEM_ENCAPS_TAG) | "
        "WRITER_SECP_PRIVKEY | READER_MLKEM_PUBKEY). "
        "32 bytes supplied to ML_KEM_1024.random_bytes during encapsulation.",
        mlkem_encaps_seed.hex())

    mlkem_secret, mlkem_ct = _mlkem_encaps_seeded(reader_mlkem_pk, mlkem_encaps_seed)
    results["MLKEM_CT"] = _r(
        '"MLKEM_CT: ML-KEM-1024 (FIPS 203) ciphertext encapsulated to reader\'s ML-KEM key". '
        "1568 bytes. In test vectors, ML_KEM_1024.random_bytes is seeded with "
        "MLKEM_ENCAPS_SEED for determinism.",
        mlkem_ct.hex())
    results["MLKEM_SECRET"] = _r(
        '"MLKEM_SECRET: ML-KEM-1024.Decaps(MLKEM_CT, READER_MLKEM_PRIVKEY)". '
        "32-byte shared secret. Verify: decaps(READER_MLKEM_PRIVKEY, MLKEM_CT) == this value.",
        mlkem_secret.hex())

    # AESKEY
    aeskey = hashlib.sha256(ecdh_secret + mlkem_secret).digest()
    results["AESKEY"] = _r(
        '"AESKEY: SHA256(ECDH_SECRET|MLKEM_SECRET)". 32-byte AES-256 encryption key.',
        aeskey.hex())

    # DATA
    raw_plaintext = (
        TYPE.encode("utf-8") + b"\x00"
        + NAME.encode("utf-8") + b"\x00"
        + CONTENTS.encode("utf-8") + b"\x00"
    )
    compressed = gzip.compress(raw_plaintext, mtime=0)
    # See centurymetadata.encode.compress(): force the OS byte so DATA
    # is reproducible regardless of the local zlib build.
    compressed = compressed[:9] + b"\xff" + compressed[10:]
    data_padded = compressed + b"\x00" * (DATA_LENGTH - len(compressed))
    assert len(data_padded) == DATA_LENGTH
    results["DATA"] = _r(
        f'"DATA: gzip([TYPE\\0NAME\\0CONTENTS\\0]+), padded with 0 bytes to {DATA_LENGTH}". '
        f"gzip(TYPE||NUL||NAME||NUL||CONTENTS||NUL, mtime=0) = {len(compressed)} bytes, "
        f"zero-padded to {DATA_LENGTH}. This is the AES plaintext.",
        data_padded.hex())

    # AES
    cipher = AESCipher.new(key=aeskey, mode=AESCipher.MODE_CTR, nonce=bytes(8))
    aes_field = cipher.encrypt(data_padded)
    results["AES"] = _r(
        '"AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA". '
        "AES-256-CTR with 8-byte nonce=0x00*8 and counter starting at 0 "
        f"(full 16-byte IV = 0x00*16). {DATA_LENGTH} bytes. Stored in the record.",
        aes_field.hex())

    # SIG
    gen_bytes = GEN.to_bytes(8, "big")
    content = writer_pub + reader_id + gen_bytes + mlkem_ct + aes_field
    assert len(content) == FULL_LENGTH - 64

    sig_hash = hashlib.sha256(tag_val + tag_val + content).digest()
    sig = _schnorr_sign(writer_secp_priv, sig_hash, schnorr_aux_rand)
    results["SIG"] = _r(
        '"SIG: BIP-340 SHA256(TAG|TAG|WRITER_PUBKEY|READER_ID|GEN|MLKEM_CT|AES)". '
        "64-byte BIP-340 Schnorr signature with aux_rand=SCHNORR_AUX_RAND. "
        "Signed message = SHA256(TAG||TAG||WRITER_PUBKEY||READER_ID||GEN[8]||MLKEM_CT||AES). "
        "Prepended to the record after the preamble.",
        sig.hex())

    # RECORD
    record = PREAMBLE + sig + content
    assert len(record) == len(PREAMBLE) + FULL_LENGTH
    results["RECORD"] = _r(
        f"Complete file: preamble ({len(PREAMBLE)} bytes) "
        "|| SIG[64] || WRITER_PUBKEY[33] || READER_ID[32] || GEN[8] "
        f"|| MLKEM_CT[{MLKEM_CT_LENGTH}] || AES[{DATA_LENGTH}]. "
        f"Total {len(record)} bytes. "
        "Verify: centurymetadata.decode(READER_SECP_PRIVKEY, READER_MLKEM_PRIVKEY, RECORD) "
        f'== [("{TYPE}", "{NAME}", "{CONTENTS}")].',
        record.hex())

    mnemonic_short = mnemonic[:18] + "..." if len(mnemonic) > 18 else mnemonic
    return {
        "description": f'mnemonic="{mnemonic_short}", N={n}',
        "provided_values": provided,
        "results": results,
    }


def generate_all() -> list:
    return [generate_vector(mnemonic, n) for mnemonic, n in CASES]


if __name__ == "__main__":
    vectors = generate_all()
    VECTORS_PATH.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"Written {len(vectors)} vectors to {VECTORS_PATH}", file=sys.stderr)
