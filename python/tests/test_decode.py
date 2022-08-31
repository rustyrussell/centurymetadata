#! /usr/bin/env python3
from centurymetadata import encode, decode
from secp256k1 import PrivateKey
import random


def test_decode_complete() -> None:
    secret1 = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    secret2 = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))

    pubkey2 = secret2.pubkey

    complete = encode(secret1, pubkey2, 0, ['a', 'aaaaaa'], ['b', 'bbbbbb'])
    assert decode(secret2, complete) == [('a', 'aaaaaa'), ('b', 'bbbbbb')]
