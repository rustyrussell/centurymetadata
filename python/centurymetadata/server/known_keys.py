"""Known reader identities for the test server's known-keys enforcement.

A reader identity is "known" if it's derived from a BIP-39 mnemonic
consisting of the same word repeated 12 times whose checksum happens to
be valid (see centurymetadata.bip39.checksum_valid) -- roughly 1 in 16
of the 2048-word wordlist. No secret list is stored: known_words.txt is
just that list of words (regenerate with tools/generate_known_words.py
if the wordlist or checksum logic ever changes); the actual keys are
derived fresh from it on every import.

Ordered by wordlist index, the first half are the "normal" case: the
record's WRITER_PUBKEY must match that same identity's own derived
writer key (self-authored). The second half are reserved for the test
server's own pre-populated example data, and may use other writers.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from secp256k1 import PrivateKey, PublicKey

from .. import derive_mlkem_keypair, get_reader_id
from ..bip39 import bip39_to_seed, derive_cm_keys

_WORDS_PATH = Path(__file__).parent / "known_words.txt"


@dataclass
class KnownIdentity:
    word: str
    self_authored: bool
    reader_secp_privkey: PrivateKey
    reader_mlkem_privkey: bytes
    writer_pubkey: PublicKey  # this identity's own derived writer key


def known_words() -> List[str]:
    """Wordlist-ordered list of words whose 12x-repeated mnemonic checksums."""
    return _WORDS_PATH.read_text().split()


def _build_identities() -> Dict[bytes, KnownIdentity]:
    words = known_words()
    half = len(words) // 2
    identities: Dict[bytes, KnownIdentity] = {}
    for i, word in enumerate(words):
        seed = bip39_to_seed(" ".join([word] * 12))
        w_secp, r_secp, _w_mlkem_seed, r_mlkem_seed = derive_cm_keys(seed, n=0)
        writer_privkey = PrivateKey(w_secp)
        reader_secp_privkey = PrivateKey(r_secp)
        reader_mlkem_pubkey, reader_mlkem_privkey = derive_mlkem_keypair(r_mlkem_seed)
        reader_id = get_reader_id(reader_secp_privkey.pubkey, reader_mlkem_pubkey)
        identities[reader_id] = KnownIdentity(
            word=word,
            self_authored=(i < half),
            reader_secp_privkey=reader_secp_privkey,
            reader_mlkem_privkey=reader_mlkem_privkey,
            writer_pubkey=writer_privkey.pubkey,
        )
    return identities


_IDENTITIES: Dict[bytes, KnownIdentity] = _build_identities()


def known_reader_ids() -> Set[bytes]:
    return set(_IDENTITIES.keys())


def required_writer_pubkey(reader_id: bytes) -> Optional[PublicKey]:
    """The writer pubkey a self-authored (first-half) reader must use, else None."""
    identity = _IDENTITIES.get(reader_id)
    if identity is None or not identity.self_authored:
        return None
    return identity.writer_pubkey


def reader_privkeys(reader_id: bytes) -> Optional[Tuple[PrivateKey, bytes]]:
    """(reader_secp_privkey, reader_mlkem_privkey) for any known reader, else None."""
    identity = _IDENTITIES.get(reader_id)
    if identity is None:
        return None
    return identity.reader_secp_privkey, identity.reader_mlkem_privkey
