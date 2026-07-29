from Cryptodome.Cipher import AES
import hashlib
import zlib
from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, preamble, PLAINTEXT_LENGTH, AES_LENGTH, MLKEM_CT_LENGTH
from typing import Callable, Iterable, Tuple, Any


def compress(triples: Iterable[Tuple[str, str, str]]) -> bytes:
    """Compress the triples, padding with zeroes to PLAINTEXT_LENGTH"""
    # CMDATA-SPEC/Writer Requirements:
    # - MUST only use valid [UTF-8](#ref-utf-8) strings without NULs for `TYPE`, `NAME` and `CONTENTS`.
    # - MUST limit `NAME` fields to 255 bytes.
    # ...
    # - MUST terminate each of `TYPE`, `NAME` and `CONTENTS`, for every tuple including the last, with a single NUL character.
    raw = bytes()
    for rtype, name, contents in triples:
        raw += bytes(rtype, encoding="utf8")
        raw += bytes(1)
        namebytes = bytes(name, encoding="utf8")
        assert len(namebytes) <= 255
        raw += namebytes
        raw += bytes(1)
        raw += bytes(contents, encoding="utf8")
        raw += bytes(1)
    # CMDATA-SPEC/Writer Requirements:
    # - MUST compress the terminated tuples using the [zlib](#ref-zlib) protocol:
    #   - MUST NOT set FDICT.
    # [NOTE: zlib.compress() never sets a preset dictionary unless one is passed]
    # [NOTE: to compressobj(zdict=...), which we don't use here.]
    ret = zlib.compress(raw, level=9)

    # CMDATA-SPEC/Writer Requirements:
    # - MUST pad the compressed stream with 0 bytes to make it 14663 bytes long.
    return ret.ljust(PLAINTEXT_LENGTH, bytes(1))


def aes(aeskey: bytes, compressed: bytes) -> bytes:
    """Encrypt the compressed data using the given key, appending the GCM tag"""
    assert len(aeskey) == 32
    assert len(compressed) == PLAINTEXT_LENGTH
    # CMDATA-SPEC/Writer Requirements: MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-encrypt
    # the padded, compressed stream, using a 12-byte all-zero nonce, and
    # append the 16-byte authentication tag.
    encrypter = AES.new(key=aeskey, mode=AES.MODE_GCM, nonce=bytes(12))
    ciphertext, tag = encrypter.encrypt_and_digest(compressed)
    ret = ciphertext + tag
    assert len(ret) == AES_LENGTH
    return ret


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
    # CMDATA-SPEC/Writer Requirements:
    # - MUST set `READER_ID` to the [SHA256](#ref-sha256) of the
    #   concatenated `READER_SECP_PUBKEY` and `READER_MLKEM_PUBKEY`.
    return hashlib.sha256(reader_secp_pubkey.serialize() + reader_mlkem_pubkey).digest()


def get_aeskey(ecdh_secret: bytes, mlkem_secret: bytes, gen: int) -> bytes:
    """Derive AES key: SHA256(ECDH_SECRET | MLKEM_SECRET | GEN)"""
    # CMDATA-SPEC/Writer Requirements:
    # - MUST encode `GEN` as an 8-byte little-endian unsigned integer.
    # ...
    # - MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-encrypt the
    #   padded, compressed stream, using a 12-byte all-zero nonce, and append
    #   the 16-byte authentication tag.
    return hashlib.sha256(ecdh_secret + mlkem_secret + gen.to_bytes(8, "little")).digest()


def contents(writer: PublicKey, reader_id: bytes, gen: int, mlkem_ct: bytes, aes_data: bytes) -> bytes:
    assert len(reader_id) == 32
    assert len(mlkem_ct) == MLKEM_CT_LENGTH
    # CMDATA-SPEC/Writer Requirements:
    # - MUST set `WRITER_PUBKEY` to the compressed [secp256k1](#ref-secp256k1) key it will use to sign the message.
    # ...
    # - MUST encode `GEN` as an 8-byte little-endian unsigned integer.
    return writer.serialize() + reader_id + gen.to_bytes(8, "little") + mlkem_ct + aes_data


def sign(writer: PrivateKey, cont: bytes) -> bytes:
    # CMDATA-SPEC/Writer Requirements:
    # - MUST set `SIG` to a [BIP-340](#ref-bip340) signature, using the
    #   writer's secret key, over
    #   SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    return writer.schnorr_sign(cont, bip340tag)


def encode(writer_privkey: PrivateKey,
           reader_secp_pubkey: PublicKey,
           reader_mlkem_pubkey: bytes,
           generation: int,
           *triples: Any) -> bytes:
    comp = compress(triples)
    if len(comp) > PLAINTEXT_LENGTH:
        raise ValueError("Compressed length too great!")
    # CMDATA-SPEC/Writer Requirements:
    # - MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC
    #   point from [Diffie-Hellman](#ref-ecdh) of `READER_SECP_PUBKEY` and the
    #   writer's secp256k1 private key.
    ecdh_secret = get_ecdh_secret(writer_privkey, reader_secp_pubkey)
    # CMDATA-SPEC/Writer Requirements:
    # - MUST compute `MLKEM_SECRET` and `MLKEM_CT` together via
    #   [ML-KEM](#ref-mlkem)-1024's `Encaps(READER_MLKEM_PUBKEY)`.
    mlkem_secret, mlkem_ct = ML_KEM_1024.encaps(reader_mlkem_pubkey)
    # CMDATA-SPEC/Writer Requirements:
    # - MUST use `SHA256(ECDH_SECRET|MLKEM_SECRET|GEN)` as the `AESKEY`.
    aeskey = get_aeskey(ecdh_secret, mlkem_secret, generation)
    encrypted = aes(aeskey, comp)
    reader_id = get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)
    cont = contents(writer_privkey.pubkey, reader_id, generation, mlkem_ct, encrypted)
    # CMDATA-SPEC/Writer Requirements:
    # A writer of a century metadata file:
    # - MUST begin the file with the literal header.
    # ...
    # - MUST set `SIG` to a [BIP-340](#ref-bip340) signature, using the writer's secret key, over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    return preamble + sign(writer_privkey, cont) + cont
