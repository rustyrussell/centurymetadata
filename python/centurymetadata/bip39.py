"""BIP-39 wordlist, checksum validation, and BIP-32 key derivation."""
import hashlib
import hmac
from pathlib import Path
from typing import List, Tuple

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CM_PURPOSE = 0x44315441

_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "english.txt"

WORDLIST: List[str] = _WORDLIST_PATH.read_text().split()
WORD_INDEX = {word: i for i, word in enumerate(WORDLIST)}

assert len(WORDLIST) == 2048

VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


def checksum_valid(words: List[str]) -> bool:
    """Check a mnemonic's words against the standard BIP-39 checksum.

    Each word contributes 11 bits (its wordlist index); the final
    len(words)//3 bits of that concatenation must equal the leading bits
    of SHA256(entropy), where entropy is everything before the checksum.
    """
    n = len(words)
    if n not in VALID_WORD_COUNTS:
        return False

    indices = []
    for word in words:
        idx = WORD_INDEX.get(word)
        if idx is None:
            return False
        indices.append(idx)

    checksum_bits = n // 3
    entropy_bits = n * 11 - checksum_bits

    value = 0
    for idx in indices:
        value = (value << 11) | idx

    entropy_int = value >> checksum_bits
    checksum_int = value & ((1 << checksum_bits) - 1)

    entropy_bytes = entropy_int.to_bytes(entropy_bits // 8, "big")
    digest = hashlib.sha256(entropy_bytes).digest()
    expected_int = int.from_bytes(digest, "big") >> (256 - checksum_bits)

    return checksum_int == expected_int


def bip39_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39: derive 64-byte seed from mnemonic (no wordlist validation)."""
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.strip().encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
    )


def _bip32_master(seed: bytes) -> Tuple[bytes, bytes]:
    """BIP32 master key. Returns (privkey_bytes, chain_code_bytes)."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def _bip32_child_h(privkey: bytes, chain: bytes, index: int) -> Tuple[bytes, bytes]:
    """BIP32 hardened child (index must already have 0x80000000 set)."""
    data = b"\x00" + privkey + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    ki = (int.from_bytes(digest[:32], "big") + int.from_bytes(privkey, "big")) % SECP256K1_ORDER
    return ki.to_bytes(32, "big"), digest[32:]


def _H(i: int) -> int:
    return i | 0x80000000


def derive_cm_keys(seed: bytes, n: int = 0) -> Tuple[bytes, bytes, bytes, bytes]:
    """Derive centurymetadata keys for slot N.
    Path: m / 0x44315441' / N' / {0,1,2,3}'
      0' = writer secp256k1   1' = reader secp256k1
      2' = writer ML-KEM seed 3' = reader ML-KEM seed
    Returns (writer_secp_bytes, reader_secp_bytes, writer_mlkem_seed, reader_mlkem_seed).
    """
    k, c = _bip32_master(seed)
    k, c = _bip32_child_h(k, c, _H(CM_PURPOSE))
    k, c = _bip32_child_h(k, c, _H(n))
    w_secp, _ = _bip32_child_h(k, c, _H(0))
    r_secp, _ = _bip32_child_h(k, c, _H(1))
    w_mlkem, _ = _bip32_child_h(k, c, _H(2))
    r_mlkem, _ = _bip32_child_h(k, c, _H(3))
    return w_secp, r_secp, w_mlkem, r_mlkem
