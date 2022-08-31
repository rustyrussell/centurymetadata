from Cryptodome.Cipher import AES
import gzip
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, preamble, DATA_LENGTH, FULL_LENGTH
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


def split_parts(after_preamble: bytes) -> Tuple[bytes, PublicKey, PublicKey, int, bytes]:
    """Split into sig, writer, reader, gen, aes"""
    try:
        wkey = PublicKey(after_preamble[64:64 + 33], raw=True)
    except Exception:
        # FIXME: secp256k1 should use a decent exception here!
        raise ValueError("Invalid wkey {}".format(after_preamble[64:64 + 33].hex()))

    try:
        rkey = PublicKey(after_preamble[64 + 33:64 + 33 + 33], raw=True)
    except Exception:
        # FIXME: secp256k1 should use a decent exception here!
        raise ValueError("Invalid rkey {}".format(after_preamble[64 + 33:64 + 33 + 33].hex()))
    return (after_preamble[0:64], wkey, rkey,
            int.from_bytes(after_preamble[64 + 33 + 33:64 + 33 + 33 + 8], "big"),
            after_preamble[64 + 33 + 33 + 8:])


def check_sig(after_preamble: bytes) -> bool:
    assert len(after_preamble) == FULL_LENGTH

    try:
        sig, wkey, _, _, _ = split_parts(after_preamble)
    except ValueError:
        return False

    return wkey.schnorr_verify(after_preamble[64:], sig, bip340tag)


def deconstruct(cmetadata: bytes) -> Tuple[PublicKey, PublicKey, int, bytes]:
    """Deconstructs a cmetadata into reader, writer, generation and post-preamble"""
    if not cmetadata.startswith(preamble):
        raise ValueError("Incorrect preamble")
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        raise ValueError("Expected {} bytes after preamble, got {}"
                         .format(FULL_LENGTH, len(after_preamble)))

    _, wkey, rkey, gen, _ = split_parts(after_preamble)
    return wkey, rkey, gen, after_preamble


def decode(secretkey: PrivateKey, cmetadata: bytes) -> Optional[List[Tuple[str, str]]]:
    if not cmetadata.startswith(preamble):
        return None
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        return None
    if not check_sig(after_preamble):
        return None
    sig, wkey, rkey, gen, aes = split_parts(after_preamble)
    # FIXME: secp256k1 != doesn't work like you expect!
    if rkey.serialize() != secretkey.pubkey.serialize():
        return None

    comp = unaes(get_aeskey(secretkey, wkey), aes)
    return decompress(comp)
