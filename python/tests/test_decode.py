#! /usr/bin/env python3
from kyber_py.ml_kem import ML_KEM_1024
from centurymetadata import encode, decode
from secp256k1 import PrivateKey
import random


def test_decode_complete() -> None:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_mlkem_pubkey, reader_mlkem_privkey = ML_KEM_1024.keygen()

    complete = encode(writer_privkey, reader_secp_privkey.pubkey, reader_mlkem_pubkey, 0,
                      ['a', 'name-a', 'aaaaaa'], ['b', 'name-b', 'bbbbbb'])
    assert decode(reader_secp_privkey, reader_mlkem_privkey, complete) == [('a', 'name-a', 'aaaaaa'), ('b', 'name-b', 'bbbbbb')]
