from Cryptodome.Cipher import AES
import gzip
from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, preamble, DATA_LENGTH, FULL_LENGTH, MLKEM_CT_LENGTH
from .encode import get_ecdh_secret, get_aeskey
from typing import Tuple, List, Optional


def decompress(comp: bytes) -> Optional[List[Tuple[str, str, str]]]:
    """Decompress into type, name, contents triples"""
    uncomp = gzip.decompress(comp)
    # Split by 0 byte
    fields = uncomp.split(sep=bytes(1))
    # That gives us a final empty field, which we ignore...
    if len(fields) != 0 and len(fields) % 3 != 1:
        return None

    ret = []
    for i in range(0, len(fields) - 1, 3):
        ret.append((fields[i].decode('utf8'), fields[i + 1].decode('utf8'), fields[i + 2].decode('utf8')))
    return ret


def unaes(aeskey: bytes, encrypted: bytes) -> bytes:
    """Decrypt the compressed data using the given key"""
    assert len(aeskey) == 32
    assert len(encrypted) == DATA_LENGTH
    decrypter = AES.new(key=aeskey, mode=AES.MODE_CTR, nonce=bytes(8))

    return decrypter.decrypt(encrypted)


def split_parts(after_preamble: bytes) -> Tuple[bytes, PublicKey, bytes, int, bytes, bytes]:
    """Split into sig, writer, reader_id, gen, mlkem_ct, aes"""
    try:
        wkey = PublicKey(after_preamble[64:64 + 33], raw=True)
    except Exception:
        # FIXME: secp256k1 should use a decent exception here!
        raise ValueError("Invalid wkey {}".format(after_preamble[64:64 + 33].hex()))

    reader_id = after_preamble[64 + 33:64 + 33 + 32]
    gen_off = 64 + 33 + 32
    gen = int.from_bytes(after_preamble[gen_off:gen_off + 8], "big")
    mlkem_ct_off = gen_off + 8
    mlkem_ct = after_preamble[mlkem_ct_off:mlkem_ct_off + MLKEM_CT_LENGTH]
    aes_data = after_preamble[mlkem_ct_off + MLKEM_CT_LENGTH:]

    return (after_preamble[0:64], wkey, reader_id, gen, mlkem_ct, aes_data)


def check_sig(after_preamble: bytes) -> bool:
    assert len(after_preamble) == FULL_LENGTH

    try:
        sig, wkey, _, _, _, _ = split_parts(after_preamble)
    except ValueError:
        return False

    return wkey.schnorr_verify(after_preamble[64:], sig, bip340tag)


def deconstruct(cmetadata: bytes) -> Tuple[PublicKey, bytes, int, bytes]:
    """Deconstructs a cmetadata into writer, reader_id, generation and post-preamble"""
    if not cmetadata.startswith(preamble):
        raise ValueError("Incorrect preamble")
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        raise ValueError("Expected {} bytes after preamble, got {}"
                         .format(FULL_LENGTH, len(after_preamble)))

    _, wkey, reader_id, gen, _, _ = split_parts(after_preamble)
    return wkey, reader_id, gen, after_preamble


def decode(reader_secp_privkey: PrivateKey,
           reader_mlkem_privkey: bytes,
           cmetadata: bytes) -> Optional[List[Tuple[str, str, str]]]:
    if not cmetadata.startswith(preamble):
        return None
    after_preamble = cmetadata[len(preamble):]
    if len(after_preamble) != FULL_LENGTH:
        return None
    if not check_sig(after_preamble):
        return None
    sig, wkey, reader_id, gen, mlkem_ct, encrypted = split_parts(after_preamble)

    ecdh_secret = get_ecdh_secret(reader_secp_privkey, wkey)
    mlkem_secret = ML_KEM_1024.decaps(reader_mlkem_privkey, mlkem_ct)
    aeskey = get_aeskey(ecdh_secret, mlkem_secret)

    comp = unaes(aeskey, encrypted)
    return decompress(comp)
