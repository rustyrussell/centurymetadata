#! /usr/bin/env python3
from Cryptodome.Cipher import AES
from centurymetadata import compress, aes, get_aeskey, sign, encode, DATA_LENGTH
from centurymetadata.key import compute_xonly_pubkey
from centurymetadata.constants import preamble
import gzip
import pytest
import random
import string


def test_compress() -> None:
    pairs = [('a', 'b')]
    ret = compress(pairs)
    assert len(ret) == DATA_LENGTH
    assert gzip.decompress(ret) == bytes((0x61, 0, 0x62, 0))

    pairs = [('a', 'b'), ('c', 'd')]
    ret = compress(pairs)
    assert len(ret) == DATA_LENGTH
    assert gzip.decompress(ret) == bytes((0x61, 0, 0x62, 0, 0x63, 0, 0x64, 0))

    # This compresses well
    pairs = [('a', 'b'), ('c', 'd' * 90000)]
    ret = compress(pairs)
    assert len(ret) == DATA_LENGTH
    assert gzip.decompress(ret) == bytes((0x61, 0, 0x62, 0, 0x63, 0)) + bytes("d", encoding="utf8") * 90000 + bytes(1)

    # Test too-long pairs.
    pairs = [('a', ''.join(random.choices(string.printable, k=90000)))]
    with pytest.raises(ValueError, match="length too great"):
        compress(pairs)


def test_aes() -> None:
    data = bytes((1,) * DATA_LENGTH)
    aeskey = bytes((2,) * 32)
    enc = aes(aeskey, data)

    decrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))
    assert decrypter.decrypt(enc) == data


def test_get_aeskey() -> None:
    # random.randbytes only in 3.9+
    secret1 = bytes([random.choice(range(256)) for _ in range(32)])
    secret2 = bytes([random.choice(range(256)) for _ in range(32)])

    pubkey1, _ = compute_xonly_pubkey(secret1)
    pubkey2, _ = compute_xonly_pubkey(secret2)

    assert get_aeskey(secret1, pubkey2) == get_aeskey(secret2, pubkey1)


def test_sign() -> None:
    secret1 = bytes([random.choice(range(256)) for _ in range(32)])
    secret2 = bytes([random.choice(range(256)) for _ in range(32)])

    pubkey1, _ = compute_xonly_pubkey(secret1)
    pubkey2, _ = compute_xonly_pubkey(secret2)

    data = bytes((2,) * DATA_LENGTH)

    ret = sign(secret1, pubkey2, 1, data)
    assert len(ret) == 8192
    # Writer
    assert ret[64:64 + 32] == pubkey1
    # Reader
    assert ret[64 + 32:64 + 32 + 32] == pubkey2
    # Generation
    assert ret[64 + 32 + 32:64 + 32 + 32 + 8] == bytes((0,) * 7 + (1,))
    # AES
    assert ret[64 + 32 + 32 + 8:] == data


def test_encode_complete() -> None:
    secret1 = bytes([random.choice(range(256)) for _ in range(32)])
    secret2 = bytes([random.choice(range(256)) for _ in range(32)])

    pubkey1, _ = compute_xonly_pubkey(secret1)
    pubkey2, _ = compute_xonly_pubkey(secret2)

    complete = encode(secret1, pubkey2, 0, ['a', 'aaaaaa'], ['b', 'bbbbbb'])
    assert len(complete) == len(preamble) + 8192
    assert complete.startswith(preamble)
