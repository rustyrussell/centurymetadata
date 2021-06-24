from Cryptodome.Cipher import AES
import coincurve.keys
import gzip
import hashlib
from .key import compute_xonly_pubkey, sign_schnorr
from .constants import preamble, DATA_LENGTH

def compress(pairs):
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


def aes(aeskey: bytes, compressed: bytes):
    """Encrypt the compressed data using the given key"""
    assert len(aeskey) == 32
    assert len(compressed) == DATA_LENGTH
    encrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))

    return encrypter.encrypt(compressed)


def get_aeskey(privkey: bytes, pubkey: bytes):
    priv = coincurve.keys.PrivateKey(secret=privkey)
    pub = coincurve.keys.PublicKey(data=pubkey).format()

    return priv.ecdh(pub)


def sign(writer: bytes, reader: bytes, gen: int, aes: bytes):
    tag = hashlib.sha256(bytes("centurymetadata", encoding="utf8")).digest()
    writer_pub, _ = compute_xonly_pubkey(writer)
    contents = writer_pub + reader + gen.to_bytes(8, "big") + aes
    msg = hashlib.sha256(tag + tag + contents).digest()
    return sign_schnorr(writer, msg) + contents


def encode(secretkey: bytes, readerpubkey: bytes, generation: int, *pairs):
    comp = compress(pairs)
    # Turn an x-only pubkey into a 33-byte by prepending 0x2.
    enc = aes(get_aeskey(secretkey, bytes((0x2,)) + readerpubkey), comp)
    return preamble + sign(secretkey, readerpubkey, generation, enc)
