from Cryptodome.Cipher import AES
import zlib
from kyber_py.ml_kem import ML_KEM_1024
from secp256k1 import PrivateKey, PublicKey
from .constants import bip340tag, verheader, preamble, PLAINTEXT_LENGTH, AES_LENGTH, DATA_LENGTH, MLKEM_CT_LENGTH
from .encode import get_ecdh_secret, get_aeskey, get_reader_id
from typing import Tuple, List, Optional


def decompress(comp: bytes, to_self: bool) -> Tuple[Optional[str], Optional[List[Tuple[str, str, str]]]]:
    """Decompress into type, name, contents triples.  If only some data was extracted, str is set to the error."""

    # CMDATA-SPEC/Reader Requirements:
    # - Otherwise: (not a "to-self" file)
    #   - MAY choose to fail parsing.
    #   - MAY choose not to process all type records (e.g. to display `bitcoin wallet labels` fields).
    #   - If the reader chooses not to fully process the file:
    #     - SHOULD indicate this omission to the user.
    # [NOTE: We choose to parse even non-to-self files.]

    decompressor = zlib.decompressobj()
    try:
        uncomp = decompressor.decompress(comp)
    except zlib.error:
        # CMDATA-SPEC/Reader Requirements:
        # - MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
        return "not a valid zlib stream", None

    # Incomplete/truncated?
    if not decompressor.eof:
        return "truncated zlib stream", None

    # CMDATA-SPEC/Reader Requirements:
    # - MUST ignore any bytes remaining after the zlib stream.
    # [NOTE: decompressobj stops consuming input at eof.]

    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the decompressed size would exceed 1048576 bytes.
    # [NOTE: FIXME: This should be done *before* decompression.  The maximum expansion factor is 1032 to 1
    # [NOTE: (see https://zlib.net/zlib_tech.html), so it's OK for our Python code, and the zlib API doesn't]
    # [NOTE: allow a maximum bound anyway.]
    if len(uncomp) > 1048576:
        return "oversize zlib stream", None

    # CMDATA-SPEC/Reader Requirements:
    # - MUST parse the decompressed bytes as a sequence of TYPE\0NAME\0CONTENTS\0 tuples, in order:
    #   - MUST separate `TYPE`, `NAME` and `CONTENTS` by NUL terminators.
    fields = uncomp.split(sep=bytes(1))
    ret: List[Tuple[str, str, str]] = []

    recorderr = None
    # split() above will leave an empty string for the final NUL.
    while fields != [b""]:
        # CMDATA-SPEC/Reader Requirements:
        #   - MUST stop processing (keeping all tuples already parsed)
        #     upon reaching a tuple for which fewer than three
        #     NUL-terminated fields remaing.
        if len(fields) < 3:
            if recorderr is None:
                recorderr = "unexpected remaining tuples"
            break

        # CMDATA-SPEC/Reader Requirements:
        #   - Otherwise, if `NAME` is greater than 255 bytes:
        #     - MUST fail to parse this record
        if len(fields[1]) > 255:
            recorderr = "overlength name field"

        # CMDATA-SPEC/Reader Requirements:
        #   - If any of `TYPE`, `NAME` or `CONTENTS` are not a valid, complete UTF-8 string:
        #     - MUST fail to parse this record
        try:
            typestr = fields[0].decode('utf8')
            namestr = fields[1].decode('utf8')
            contentstr = fields[2].decode('utf8')
        except UnicodeDecodeError:
            recorderr = "invalid UTF-8 in tuple"

        # Consumed those.
        fields = fields[3:]

        # CMDATA-SPEC/Reader Requirements:
        #   - Otherwise, if `TYPE` is not a known type:
        #     - MUST ignore that tuple and continue processing.
        #   - Otherwise:
        #     - See requirements specific to that `TYPE` (specified in [Individual Record Formats](#individual-record-formats)).
        # [NOTE: We rely on the caller to quantify types (since it may know types we dont!).]

        # CMDATA-SPEC/Reader Requirements:
        #   - If this record "fails to parse" (defined below):
        #     - If this is a "to-self" file:
        #       - MUST continue parsing remaining tuples
        #     - Otherwise (not a "to-self" file):
        #       - MAY continue parsing remaining tuples
        if recorderr is not None and to_self is False:
            break

        ret.append((typestr, namestr, contentstr))

    return recorderr, ret


def unaes(aeskey: bytes, encrypted: bytes) -> Optional[bytes]:
    """Decrypt the compressed data using the given key, verifying the trailing GCM tag.

    Returns None the tag doesn't verify.
    """
    assert len(aeskey) == 32
    assert len(encrypted) == AES_LENGTH
    # CMDATA-SPEC/Reader Requirements:
    # - MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-decrypt
    #   the `AES` bytes (immediately following `MLKEM_CT`), using a 12-byte
    #   all-zero nonce.
    ciphertext, tag = encrypted[:PLAINTEXT_LENGTH], encrypted[PLAINTEXT_LENGTH:]
    decrypter = AES.new(key=aeskey, mode=AES.MODE_GCM, nonce=bytes(12))

    try:
        ret = decrypter.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        # CMDATA-SPEC/Reader Requirements:
        # - MUST fail parsing if the trailing 16-byte authentication tag does not verify.
        return None

    return ret


# CMDATA-SPEC/File Format:
# SIG[64]|WRITER_PUBKEY[33]|READER_ID[32]|GEN[8]|MLKEM_CT[1568]|AES[14679]
def split_parts(after_preamble: bytes) -> Tuple[bytes, PublicKey, bytes, int, bytes, bytes]:
    """Split into sig, writer, reader_id, gen, mlkem_ct, aes"""
    try:
        wkey = PublicKey(after_preamble[64:64 + 33], raw=True)
    except Exception:
        # FIXME: secp256k1 should use a decent exception here!
        raise ValueError("Invalid wkey {}".format(after_preamble[64:64 + 33].hex()))

    reader_id = after_preamble[64 + 33:64 + 33 + 32]
    gen_off = 64 + 33 + 32
    # CMDATA-SPEC/Writer Requirements: MUST encode `GEN` as an 8-byte
    # little-endian unsigned integer.
    gen = int.from_bytes(after_preamble[gen_off:gen_off + 8], "little")
    mlkem_ct_off = gen_off + 8
    mlkem_ct = after_preamble[mlkem_ct_off:mlkem_ct_off + MLKEM_CT_LENGTH]
    aes_data = after_preamble[mlkem_ct_off + MLKEM_CT_LENGTH:]

    return (after_preamble[0:64], wkey, reader_id, gen, mlkem_ct, aes_data)


def check_sig(after_preamble: bytes) -> bool:
    assert len(after_preamble) == DATA_LENGTH

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
    if len(after_preamble) != DATA_LENGTH:
        raise ValueError("Expected {} bytes after preamble, got {}"
                         .format(DATA_LENGTH, len(after_preamble)))

    _, wkey, reader_id, gen, _, _ = split_parts(after_preamble)
    return wkey, reader_id, gen, after_preamble


def decode(reader_secp_privkey: PrivateKey,
           reader_mlkem_privkey: bytes,
           reader_mlkem_pubkey: bytes,
           writer_secp_pubkey: PublicKey,
           cmetadata: bytes) -> Tuple[Optional[str], Optional[List[Tuple[str, str, str]]]]:
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the first 19 bytes of the file are not `centurymetadata v1\0` (where the 19th byte is a NUL).
    if not cmetadata.startswith(verheader):
        return "Not a Century Metadata file", None
    after_preamble = cmetadata[len(preamble):]
    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if the length of the file is not exactly 17571 bytes.
    # - MUST otherwise ignore the first 1187 bytes (the literal header).
    if len(after_preamble) != DATA_LENGTH:
        return "Invalid length for a Century Metadata file", None

    sig, wkey, reader_id, gen, mlkem_ct, encrypted = split_parts(after_preamble)

    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `READER_ID` does not equal
    #   [SHA256](#ref-sha256)(`READER_SECP_PUBKEY`|`READER_MLKEM_PUBKEY`) for a
    #   keypair the reader holds the secrets to.

    expected_reader_id = get_reader_id(reader_secp_privkey.pubkey, reader_mlkem_pubkey)
    if expected_reader_id != reader_id:
        return "Incorrrect READER_ID", None

    # CMDATA-SPEC/Reader Requirements:
    # - MUST fail parsing if `SIG` is not a valid [BIP-340](#ref-bip340)
    #   signature by `WRITER_PUBKEY` over
    #   SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
    if not wkey.schnorr_verify(after_preamble[64:], sig, bip340tag):
        return "Invalid signature", None

    # CMDATA-SPEC/Reader Requirements:
    # - If `WRITER_PUBKEY` equals the pubkey the reader itself would derive at
    #   `0x44315441'/N'/0'` (for the `N` used to derive this file's reader keys):
    #   - The file is referred to as "to-self".
    to_self = (wkey == writer_secp_pubkey)

    # CMDATA-SPEC/Reader Requirements:
    # - MUST compute the 32-byte `MLKEM_SECRET` by decapsulating `MLKEM_CT`.
    mlkem_secret = ML_KEM_1024.decaps(reader_mlkem_privkey, mlkem_ct)

    # CMDATA-SPEC/Reader Requirements:
    # - MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC
    #   point from [Diffie-Hellman](#ref-ecdh) of `WRITER_PUBKEY` and
    #   `READER_SECP_PRIVKEY`.
    ecdh_secret = get_ecdh_secret(reader_secp_privkey, wkey)

    # CMDATA-SPEC/Reader Requirements:
    # - MUST SHA256 the concatenation of `ECDH_SECRET`, `MLKEM_SECRET` and `GEN`
    #   to derive the `AESKEY`.
    aeskey = get_aeskey(ecdh_secret, mlkem_secret, gen)

    # CMDATA-SPEC/Reader Requirements:
    # - MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-decrypt the
    #  `AES` bytes (immediately following `MLKEM_CT`), using a 12-byte all-zero nonce.
    # - MUST fail parsing if the trailing 16-byte authentication tag does not verify.
    comp = unaes(aeskey, encrypted)
    if comp is None:
        return "Invalid secret key", None

    return decompress(comp, to_self)
