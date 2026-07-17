#! /usr/bin/env python3
from kyber_py.ml_kem import ML_KEM_1024
from centurymetadata import encode, decode, decompress
from centurymetadata.decode import MAX_DECOMPRESSED_LENGTH
from secp256k1 import PrivateKey
import random
import zlib


def test_decode_complete() -> None:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_mlkem_pubkey, reader_mlkem_privkey = ML_KEM_1024.keygen()

    complete = encode(writer_privkey, reader_secp_privkey.pubkey, reader_mlkem_pubkey, 0,
                      ['a', 'name-a', 'aaaaaa'], ['b', 'name-b', 'bbbbbb'])
    assert decode(reader_secp_privkey, reader_mlkem_privkey, complete) == [('a', 'name-a', 'aaaaaa'), ('b', 'name-b', 'bbbbbb')]


def test_decompress_ignores_trailing_padding() -> None:
    raw = bytes((0x61, 0, 0x62, 0, 0x63, 0))
    # Explicit padding after the zlib stream, as compress() produces.
    comp = zlib.compress(raw) + bytes(1) * 500
    assert decompress(comp) == [('a', 'b', 'c')]


def test_decompress_invalid_stream_returns_none() -> None:
    assert decompress(bytes(100)) is None


def test_decompress_truncated_stream_returns_none() -> None:
    raw = bytes((0x61, 0, 0x62, 0, 0x63, 0))
    comp = zlib.compress(raw)
    assert decompress(comp[:-1]) is None


def test_decompress_oversized_returns_none() -> None:
    # Highly compressible, but decompresses to more than the 1MB cap.
    comp = zlib.compress(bytes(MAX_DECOMPRESSED_LENGTH + 1))
    assert decompress(comp) is None


def test_decompress_exactly_at_cap_succeeds() -> None:
    # 'a' NUL 'b' NUL <padding> NUL: exactly MAX_DECOMPRESSED_LENGTH bytes
    # once decompressed, so it must not be treated as "too big".
    padding = b'x' * (MAX_DECOMPRESSED_LENGTH - len(b'a\0b\0\0'))
    raw = b'a\0b\0' + padding + b'\0'
    assert len(raw) == MAX_DECOMPRESSED_LENGTH
    comp = zlib.compress(raw)
    triples = decompress(comp)
    assert triples is not None
    assert triples[0][:2] == ('a', 'b')
