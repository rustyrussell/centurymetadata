from Cryptodome.Cipher import AES
import gzip
import hashlib
from .key import compute_xonly_pubkey, verify_schnorr
from .constants import preamble, DATA_LENGTH, FULL_LENGTH
from .encode import get_aeskey
from typing import Tuple, List, Optional


def decompress(comp: bytes) -> Optional[List[Tuple[str, str]]]:
    """Compress into pairs"""
    uncomp = gzip.decompress(comp)
    # Split by 0 byte
    fields = uncomp.split(sep=bytes(1))
    # That gives us a final empty field, which we ignore...
    if len(fields) != 0 and len(fields) % 2 != 1:
        return None

    ret = []
    for i in range(0, len(fields) - 1, 2):
        ret.append((fields[i].decode('utf8'), fields[i + 1].decode('utf8')))
    return ret


def unaes(aeskey: bytes, encrypted: bytes) -> bytes:
    """Decrypt the compressed data using the given key"""
    assert len(aeskey) == 32
    assert len(encrypted) == DATA_LENGTH
    decrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))

    return decrypter.decrypt(encrypted)


def split_parts(after_preamble: bytes) -> Tuple[bytes, bytes, bytes, int, bytes]:
    """Split into sig, writer, reader, gen, aes"""
    return (after_preamble[0:64],
            after_preamble[64:64 + 32],
            after_preamble[64 + 32:64 + 32 + 32],
            int.from_bytes(after_preamble[64 + 32 + 32:64 + 32 + 32 + 8], "big"),
            after_preamble[64 + 32 + 32 + 8:])


def check_sig(after_preamble: bytes) -> bool:
    assert len(after_preamble) == FULL_LENGTH
    sig, wkey, _, _, _ = split_parts(after_preamble)
    tag = hashlib.sha256(bytes("centurymetadata", encoding="utf8")).digest()
    msg = hashlib.sha256(tag + tag + after_preamble[64:]).digest()
    return verify_schnorr(wkey, sig, msg)


def deconstruct(cmetadata: bytes) -> Optional[Tuple[bytes, bytes, bytes]]:
    """Deconstructs a cmetadata into reader, writer and post-preamble"""
    if not cmetadata.startswith(preamble):
        return None
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        return None
    _, wkey, rkey, _, _ = split_parts(after_preamble)
    return wkey, rkey, after_preamble


def decode(secretkey: bytes, cmetadata: bytes) -> Optional[List[Tuple[str, str]]]:
    if not cmetadata.startswith(preamble):
        return None
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        return None
    if not check_sig(after_preamble):
        return None
    expectedkey, _ = compute_xonly_pubkey(secretkey)
    sig, wkey, rkey, gen, aes = split_parts(after_preamble)
    if rkey != expectedkey:
        return None

    comp = unaes(get_aeskey(secretkey, wkey), aes)
    return decompress(comp)
