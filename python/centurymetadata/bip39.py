"""BIP-39 wordlist and checksum validation."""
import hashlib
from pathlib import Path
from typing import List

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
