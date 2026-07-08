from Cryptodome.Cipher import AES
import gzip
import hashlib
from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, preamble, DATA_LENGTH, MLKEM_CT_LENGTH
from typing import Callable, Iterable, Tuple, Any


def compress(triples: Iterable[Tuple[str, str, str]]) -> bytes:
    """Compress the triples, padding with zeroes to DATA_LENGTH, raising an exception if the result is too large"""
    raw = bytes()
    for rtype, name, contents in triples:
        raw += bytes(rtype, encoding="utf8")
        raw += bytes(1)
        raw += bytes(name, encoding="utf8")
        raw += bytes(1)
        raw += bytes(contents, encoding="utf8")
        raw += bytes(1)
    ret = gzip.compress(raw, mtime=0)
    # gzip.compress()'s mtime=0 fast path hands the whole header to zlib,
    # which stamps the OS byte (offset 9) with whatever the local zlib
    # build defaults to (e.g. 3="Unix" vs 255="unknown"). Force it fixed
    # so DATA is byte-for-byte reproducible across platforms.
    ret = ret[:9] + b'\xff' + ret[10:]
    if len(ret) > DATA_LENGTH:
        raise ValueError("Compressed length too great!")

    return ret.ljust(DATA_LENGTH, bytes(1))


def aes(aeskey: bytes, compressed: bytes) -> bytes:
    """Encrypt the compressed data using the given key"""
    assert len(aeskey) == 32
    assert len(compressed) == DATA_LENGTH
    encrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))

    return encrypter.encrypt(compressed)


def bip340_tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) | SHA256(tag) | data)"""
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def derive_mlkem_keypair(bip32_privkey: bytes) -> Tuple[bytes, bytes]:
    """Derive an ML-KEM-1024 (FIPS 203) keypair deterministically from a 32-byte BIP32 private key.

    d = bip32_privkey
    z = BIP340_tagged_hash("centurymetadata v1 mlkem-z", d)

    These are injected as the two random_bytes(32) calls inside ML_KEM_1024.keygen():
    the first uses d, the second uses z as the implicit rejection value.

    Returns (pubkey, privkey).
    """
    assert len(bip32_privkey) == 32
    d = bip32_privkey
    z = bip340_tagged_hash("centurymetadata v1 mlkem-z", d)

    values = iter([d, z])

    def seeded_random(n: int) -> bytes:
        return next(values)

    original_random: Callable[[int], bytes] = ML_KEM_1024.random_bytes
    ML_KEM_1024.random_bytes = seeded_random
    try:
        pk, sk = ML_KEM_1024.keygen()
    finally:
        ML_KEM_1024.random_bytes = original_random
    return pk, sk


def get_ecdh_secret(privkey: PrivateKey, pubkey: PublicKey) -> bytes:
    """Compute ECDH shared secret"""
    return pubkey.ecdh(privkey.private_key)


def get_reader_id(reader_secp_pubkey: PublicKey, reader_mlkem_pubkey: bytes) -> bytes:
    """Compute READER_ID = SHA256(secp_pubkey | mlkem_pubkey)"""
    return hashlib.sha256(reader_secp_pubkey.serialize() + reader_mlkem_pubkey).digest()


def get_aeskey(ecdh_secret: bytes, mlkem_secret: bytes) -> bytes:
    """Derive AES key: SHA256(ECDH_SECRET | MLKEM_SECRET)"""
    return hashlib.sha256(ecdh_secret + mlkem_secret).digest()


def contents(writer: PublicKey, reader_id: bytes, gen: int, mlkem_ct: bytes, aes_data: bytes) -> bytes:
    assert len(reader_id) == 32
    assert len(mlkem_ct) == MLKEM_CT_LENGTH
    return writer.serialize() + reader_id + gen.to_bytes(8, "big") + mlkem_ct + aes_data


def sign(writer: PrivateKey, cont: bytes) -> bytes:
    return writer.schnorr_sign(cont, bip340tag)


def encode(writer_privkey: PrivateKey,
           reader_secp_pubkey: PublicKey,
           reader_mlkem_pubkey: bytes,
           generation: int,
           *triples: Any) -> bytes:
    comp = compress(triples)
    ecdh_secret = get_ecdh_secret(writer_privkey, reader_secp_pubkey)
    mlkem_secret, mlkem_ct = ML_KEM_1024.encaps(reader_mlkem_pubkey)
    aeskey = get_aeskey(ecdh_secret, mlkem_secret)
    encrypted = aes(aeskey, comp)
    reader_id = get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)
    cont = contents(writer_privkey.pubkey, reader_id, generation, mlkem_ct, encrypted)
    return preamble + sign(writer_privkey, cont) + cont
