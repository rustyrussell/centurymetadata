#! /usr/bin/env python3
from kyber_py.kyber import Kyber1024
from centurymetadata import encode, decode
from secp256k1 import PrivateKey
import random


def test_decode_complete() -> None:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_kyber_pubkey, reader_kyber_privkey = Kyber1024.keygen()

    complete = encode(writer_privkey, reader_secp_privkey.pubkey, reader_kyber_pubkey, 0,
                      ['a', 'aaaaaa'], ['b', 'bbbbbb'])
    assert decode(reader_secp_privkey, reader_kyber_privkey, complete) == [('a', 'aaaaaa'), ('b', 'bbbbbb')]
