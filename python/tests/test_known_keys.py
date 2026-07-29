#! /usr/bin/env python3
from secp256k1 import PrivateKey

import centurymetadata
from centurymetadata.bip39 import checksum_valid
from centurymetadata.server import known_keys


def test_known_words_count_and_checksum() -> None:
    words = known_keys.known_words()
    # ~1/16 of the 2048-word wordlist
    assert 100 < len(words) < 160
    for word in words:
        assert checksum_valid([word] * 12)


def test_reader_ids_match_word_count() -> None:
    assert len(known_keys.known_reader_ids()) == len(known_keys.known_words())


def test_first_half_requires_self_authored_writer() -> None:
    words = known_keys.known_words()
    half = len(words) // 2
    ids = list(known_keys._IDENTITIES.items())

    first_half = [rid for rid, ident in ids if ident.self_authored]
    second_half = [rid for rid, ident in ids if not ident.self_authored]
    assert len(first_half) == half
    assert len(second_half) == len(words) - half

    for reader_id in first_half:
        assert known_keys.required_writer_pubkey(reader_id) is not None
    for reader_id in second_half:
        assert known_keys.required_writer_pubkey(reader_id) is None


def test_known_words_file_matches_fresh_derivation() -> None:
    """known_words.txt must not drift from what checksum_valid() selects.

    Regenerate with: cd python && uv run python3 ../tools/generate_known_words.py
    """
    from centurymetadata.bip39 import WORDLIST
    fresh = [word for word in WORDLIST if checksum_valid([word] * 12)]
    assert known_keys.known_words() == fresh


def test_unknown_reader_is_unknown() -> None:
    fake_reader_id = bytes(32)
    assert fake_reader_id not in known_keys.known_reader_ids()
    assert known_keys.reader_privkeys(fake_reader_id) is None
    assert known_keys.required_writer_pubkey(fake_reader_id) is None


def test_known_identity_round_trips_encode_decode() -> None:
    """A known reader's cached privkeys must actually decrypt data sent to it."""
    reader_id, identity = next(iter(known_keys._IDENTITIES.items()))
    privkeys = known_keys.reader_privkeys(reader_id)
    assert privkeys is not None
    reader_secp_privkey, reader_mlkem_privkey = privkeys

    # Recover the reader's ML-KEM pubkey the same way known_keys derived it.
    from centurymetadata.bip39 import bip39_to_seed, derive_cm_keys
    seed = bip39_to_seed(" ".join([identity.word] * 12))
    _w_secp, _r_secp, _w_mlkem, r_mlkem_seed = derive_cm_keys(seed, n=0)
    reader_mlkem_pubkey, _ = centurymetadata.derive_mlkem_keypair(r_mlkem_seed)

    reader_secp_pubkey = reader_secp_privkey.pubkey
    assert centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey) == reader_id

    writer_privkey = PrivateKey(bytes([7] * 32))
    record = centurymetadata.encode(writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey,
                                    0, ('t', 'n', 'known-keys round trip'))
    # Not a to-self record: the writer key here is unrelated to the reader's own.
    other_writer_pubkey = PrivateKey(bytes([1] * 32)).pubkey
    errors, decoded = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey, reader_mlkem_pubkey,
                                             other_writer_pubkey, record)
    assert errors == [], f"decode failed: {errors}"
    assert decoded == [('t', 'n', 'known-keys round trip')]
