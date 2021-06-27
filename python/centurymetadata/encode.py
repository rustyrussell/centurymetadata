from Cryptodome.Cipher import AES
import coincurve.keys
import gzip
import hashlib
from .key import compute_xonly_pubkey, sign_schnorr, tweak_add_privkey
from .constants import preamble, DATA_LENGTH
from typing import List, Tuple, Any


def compress(pairs: List[Tuple[str, str]]) -> bytes:
    """Compress the pairs, padding with zeroes to 8056 bytes, raising an exception if the result is > 8056"""
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


def get_aeskey(privkey: bytes, pubkey32: bytes) -> bytes:
    # This inverts if it would make an 03 key... yuck!
    privkey = tweak_add_privkey(privkey, bytes(32))
    priv = coincurve.keys.PrivateKey(secret=privkey)
    pub = coincurve.keys.PublicKey(data=bytes((0x02,)) + pubkey32).format()
    print("ECDH {} x {}".format(coincurve.keys.PublicKey.from_secret(privkey).format(), pub))

    ret = priv.ecdh(pub)
    print("-> {}".format(ret))
    return ret


def sign(writer: bytes, reader: bytes, gen: int, aes: bytes) -> bytes:
    tag = hashlib.sha256(bytes("centurymetadata", encoding="utf8")).digest()
    writer_pub, _ = compute_xonly_pubkey(writer)
    contents = writer_pub + reader + gen.to_bytes(8, "big") + aes
    msg = hashlib.sha256(tag + tag + contents).digest()
    return sign_schnorr(writer, msg) + contents


def encode(secretkey: bytes, readerpubkey: bytes, generation: int, *pairs: Any) -> bytes:
    comp = compress(pairs)
    enc = aes(get_aeskey(secretkey, readerpubkey), comp)
    return preamble + sign(secretkey, readerpubkey, generation, enc)
