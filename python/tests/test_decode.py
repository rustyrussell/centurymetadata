#! /usr/bin/env python3
from kyber_py.ml_kem import ML_KEM_1024
from centurymetadata import encode, decode, decompress
from centurymetadata.decode import deconstruct, CMDataErrorCode
from secp256k1 import PrivateKey
import random
import zlib


def test_decode_complete() -> None:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_mlkem_pubkey, reader_mlkem_privkey = ML_KEM_1024.keygen()

    # A non-zero, asymmetric GEN so a big/little-endian mixup would
    # actually change the derived AESKEY and break decoding -- GEN=0
    # encodes identically either way and wouldn't catch that.
    generation = 0x0102030405060708

    complete = encode(writer_privkey, reader_secp_privkey.pubkey, reader_mlkem_pubkey, generation,
                      ['a', 'name-a', 'aaaaaa'], ['b', 'name-b', 'bbbbbb'])
    errors, triples = decode(reader_secp_privkey, reader_mlkem_privkey, reader_mlkem_pubkey,
                             writer_privkey.pubkey, complete)
    assert errors == []
    assert triples == [('a', 'name-a', 'aaaaaa'), ('b', 'name-b', 'bbbbbb')]

    # CMDATA-SPEC/Writer Requirements: MUST encode `GEN` as an 8-byte
    # little-endian unsigned integer.
    _, _, decoded_gen, after_preamble = deconstruct(complete)
    assert decoded_gen == generation
    gen_off = 64 + 33 + 32
    assert after_preamble[gen_off:gen_off + 8] == generation.to_bytes(8, "little")


def test_decompress_ignores_trailing_padding() -> None:
    raw = bytes((0x61, 0, 0x62, 0, 0x63, 0))
    # Explicit padding after the zlib stream, as compress() produces.
    comp = zlib.compress(raw) + bytes(1) * 500
    errors, triples = decompress(comp, False)
    assert errors == []
    assert triples == [('a', 'b', 'c')]


def test_decompress_invalid_stream_fails() -> None:
    errors, triples = decompress(bytes(100), False)
    assert len(errors) == 1
    assert errors[0].fatal
    assert errors[0].stopped
    assert errors[0].code == CMDataErrorCode.BAD_ZLIB
    assert triples == []


def test_decompress_truncated_stream_fails() -> None:
    raw = bytes((0x61, 0, 0x62, 0, 0x63, 0))
    comp = zlib.compress(raw)
    errors, triples = decompress(comp[:-1], False)
    assert len(errors) == 1
    assert errors[0].fatal
    assert errors[0].stopped
    assert errors[0].code == CMDataErrorCode.TRUNCATED_ZLIB
    assert triples == []


# CMDATA-SPEC/Reader Requirements:
# - MUST fail parsing if the decompressed size would exceed 1048576 bytes.
MAX_DECOMPRESSED_LENGTH = 1048576


def test_decompress_oversized_fails() -> None:
    # Highly compressible, but decompresses to more than the 1MB cap.
    comp = zlib.compress(bytes(MAX_DECOMPRESSED_LENGTH + 1))
    errors, triples = decompress(comp, False)
    assert len(errors) == 1
    assert errors[0].fatal
    assert errors[0].stopped
    assert errors[0].code == CMDataErrorCode.OVERSIZE_ZLIB
    assert triples == []


def test_decompress_exactly_at_cap_succeeds() -> None:
    # 'a' NUL 'b' NUL <padding> NUL: exactly MAX_DECOMPRESSED_LENGTH bytes
    # once decompressed, so it must not be treated as "too big".
    padding = b'x' * (MAX_DECOMPRESSED_LENGTH - len(b'a\0b\0\0'))
    raw = b'a\0b\0' + padding + b'\0'
    assert len(raw) == MAX_DECOMPRESSED_LENGTH
    comp = zlib.compress(raw)
    errors, triples = decompress(comp, False)
    assert errors == []
    assert triples[0][:2] == ('a', 'b')


def test_decompress_overlength_name_skips_record_but_continues_for_to_self() -> None:
    bad_name = b'x' * 256
    raw = b'a\0' + bad_name + b'\0c\0' + b'd\0e\0f\0'
    comp = zlib.compress(raw)

    # To-self: not fatal (some triples came out), and not stopped (we
    # kept parsing past the bad record and recovered the next one).
    errors, triples = decompress(comp, True)
    assert len(errors) == 1
    assert errors[0].fatal is False
    assert errors[0].stopped is False
    assert errors[0].code == CMDataErrorCode.OVERLENGTH_NAME
    assert errors[0].record_index == 0
    assert triples == [('d', 'e', 'f')]

    # Not a to-self file: we choose to stop at the first bad record
    # (the spec only says MAY continue), so nothing after it is parsed.
    errors, triples = decompress(comp, False)
    assert len(errors) == 1
    assert errors[0].fatal is False
    assert errors[0].stopped is True
    assert errors[0].record_index == 0
    assert triples == []


def test_decompress_invalid_utf8_skips_record() -> None:
    raw = b'a\0\xff\xfe\0c\0' + b'd\0e\0f\0'
    comp = zlib.compress(raw)

    errors, triples = decompress(comp, True)
    assert len(errors) == 1
    assert errors[0].fatal is False
    assert errors[0].stopped is False
    assert errors[0].code == CMDataErrorCode.INVALID_UTF8
    assert errors[0].record_index == 0
    assert triples == [('d', 'e', 'f')]


def test_decompress_truncated_tuple_always_stops_even_for_to_self() -> None:
    # Fewer than 3 fields remain -- the spec says MUST stop here,
    # regardless of to-self.
    raw = b'a\0b\0c\0' + b'trailing-partial-tuple'
    comp = zlib.compress(raw)

    errors, triples = decompress(comp, True)
    assert len(errors) == 1
    assert errors[0].fatal is False
    assert errors[0].stopped is True
    assert errors[0].code == CMDataErrorCode.TRUNCATED_TUPLE
    assert errors[0].record_index == 1
    assert triples == [('a', 'b', 'c')]
