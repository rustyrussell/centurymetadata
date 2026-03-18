#! /usr/bin/env python3
from Cryptodome.Cipher import AES
from kyber_py.ml_kem import ML_KEM_1024
from centurymetadata import compress, aes, derive_mlkem_keypair, get_ecdh_secret, get_reader_id, get_aeskey, contents, encode, DATA_LENGTH, MLKEM_CT_LENGTH
from centurymetadata.constants import preamble
from secp256k1 import PrivateKey
import gzip
import hashlib
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


def test_get_ecdh_secret() -> None:
    # ECDH is symmetric: DH(a, B) == DH(b, A)
    secret1 = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    secret2 = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))

    assert get_ecdh_secret(secret1, secret2.pubkey) == get_ecdh_secret(secret2, secret1.pubkey)


def test_get_reader_id() -> None:
    secret = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    mlkem_pk, _ = ML_KEM_1024.keygen()

    reader_id = get_reader_id(secret.pubkey, mlkem_pk)
    assert len(reader_id) == 32
    assert reader_id == hashlib.sha256(secret.pubkey.serialize() + mlkem_pk).digest()


def test_get_aeskey() -> None:
    ecdh_secret = bytes([random.choice(range(256)) for _ in range(32)])
    mlkem_secret = bytes([random.choice(range(256)) for _ in range(32)])

    aeskey = get_aeskey(ecdh_secret, mlkem_secret)
    assert len(aeskey) == 32
    assert aeskey == hashlib.sha256(ecdh_secret + mlkem_secret).digest()


def test_contents() -> None:
    secret1 = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_id = bytes([random.choice(range(256)) for _ in range(32)])
    mlkem_ct = bytes([random.choice(range(256)) for _ in range(MLKEM_CT_LENGTH)])
    data = bytes((2,) * DATA_LENGTH)

    ret = contents(secret1.pubkey, reader_id, 1, mlkem_ct, data)

    assert len(ret) == 8192 - 64
    assert ret[0:33] == secret1.pubkey.serialize()
    assert ret[33:33 + 32] == reader_id
    assert ret[33 + 32:33 + 32 + 8] == bytes((0,) * 7 + (1,))
    assert ret[33 + 32 + 8:33 + 32 + 8 + MLKEM_CT_LENGTH] == mlkem_ct
    assert ret[33 + 32 + 8 + MLKEM_CT_LENGTH:] == data


def test_derive_mlkem_keypair() -> None:
    privkey = bytes([random.choice(range(256)) for _ in range(32)])

    # Deterministic: same input gives same output
    pk1, sk1 = derive_mlkem_keypair(privkey)
    pk2, sk2 = derive_mlkem_keypair(privkey)
    assert pk1 == pk2
    assert sk1 == sk2

    # Correct sizes
    assert len(pk1) == 1568
    assert len(sk1) == 3168

    # Different inputs give different outputs
    privkey2 = bytes([random.choice(range(256)) for _ in range(32)])
    pk3, _ = derive_mlkem_keypair(privkey2)
    assert pk1 != pk3

    # Derived keypair works for encaps/decaps
    key, ct = ML_KEM_1024.encaps(pk1)
    assert ML_KEM_1024.decaps(sk1, ct) == key

    # Leaves ML_KEM_1024 random_bytes intact (not the seeded version)
    pk4, _ = ML_KEM_1024.keygen()
    pk5, _ = ML_KEM_1024.keygen()
    assert pk4 != pk5  # would fail if DRBG were left seeded


def test_encode_complete() -> None:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_mlkem_pubkey, _ = ML_KEM_1024.keygen()

    complete = encode(writer_privkey, reader_secp_privkey.pubkey, reader_mlkem_pubkey, 0,
                      ['a', 'aaaaaa'], ['b', 'bbbbbb'])
    assert len(complete) == len(preamble) + 8192
    assert complete.startswith(preamble)
