#! /usr/bin/env python3
from centurymetadata import encode, decode
from centurymetadata.key import compute_xonly_pubkey
import random


def test_decode_complete() -> None:
    secret1 = bytes([random.choice(range(256)) for _ in range(32)])
    secret2 = bytes([random.choice(range(256)) for _ in range(32)])

    pubkey1, _ = compute_xonly_pubkey(secret1)
    pubkey2, _ = compute_xonly_pubkey(secret2)

    complete = encode(secret1, pubkey2, 0, ['a', 'aaaaaa'], ['b', 'bbbbbb'])
    assert decode(secret2, complete) == [('a', 'aaaaaa'), ('b', 'bbbbbb')]
