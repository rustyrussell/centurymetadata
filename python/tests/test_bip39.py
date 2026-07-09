#! /usr/bin/env python3
from centurymetadata.bip39 import WORDLIST, checksum_valid


def test_wordlist_size() -> None:
    assert len(WORDLIST) == 2048
    assert WORDLIST[0] == 'abandon'
    assert WORDLIST[-1] == 'zoo'


def test_known_vectors() -> None:
    # BIP-39 spec test vectors (trezor python-mnemonic vectors.json)
    assert checksum_valid(['abandon'] * 11 + ['about'])
    assert checksum_valid(
        'legal winner thank year wave sausage worth useful legal winner thank yellow'.split())
    assert checksum_valid(['zoo'] * 11 + ['wrong'])


def test_bad_checksum() -> None:
    assert not checksum_valid(['abandon'] * 12)
    assert not checksum_valid(['zoo'] * 12)


def test_unknown_word() -> None:
    assert not checksum_valid(['notaword'] * 12)


def test_wrong_length() -> None:
    assert not checksum_valid(['abandon'] * 11)
    assert not checksum_valid(['abandon'] * 13)
