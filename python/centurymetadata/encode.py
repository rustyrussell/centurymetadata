from Cryptodome.Cipher import AES
import gzip
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, preamble, DATA_LENGTH
from typing import Iterable, Tuple, Any


def compress(pairs: Iterable[Tuple[str, str]]) -> bytes:
    """Compress the pairs, padding with zeroes to DATA_LENGTH, raising an exception if the result is too large"""
    raw = bytes()
    for title, contents in pairs:
        raw += bytes(title, encoding="utf8")
        raw += bytes(1)
        raw += bytes(contents, encoding="utf8")
        raw += bytes(1)
    ret = gzip.compress(raw)
    if len(ret) > DATA_LENGTH:
        raise ValueError("Compressed length too great!")

    return ret.ljust(DATA_LENGTH, bytes(1))


def aes(aeskey: bytes, compressed: bytes) -> bytes:
    """Encrypt the compressed data using the given key"""
    assert len(aeskey) == 32
    assert len(compressed) == DATA_LENGTH
    encrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))

    return encrypter.encrypt(compressed)


def get_aeskey(privkey: PrivateKey, pubkey: PublicKey) -> bytes:
    return pubkey.ecdh(privkey.private_key)


def contents(writer: PublicKey, reader: PublicKey, gen: int, aes: bytes) -> bytes:
    return writer.serialize() + reader.serialize() + gen.to_bytes(8, "big") + aes


def sign(writer: PrivateKey, contents: bytes) -> bytes:
    return writer.schnorr_sign(contents, bip340tag)


def encode(secretkey: PrivateKey, readerpubkey: PublicKey, generation: int, *pairs: Any) -> bytes:
    comp = compress(pairs)
    enc = aes(get_aeskey(secretkey, readerpubkey), comp)
    cont = contents(secretkey.pubkey, readerpubkey, generation, enc)
    return preamble + sign(secretkey, cont) + cont
