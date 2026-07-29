"""centurymetadata: routines to handle long-persistent, small encrypted data.

"""
from .constants import verheader, preamble, PLAINTEXT_LENGTH, AES_LENGTH, DATA_LENGTH, RECORD_LENGTH, MLKEM_CT_LENGTH
from .encode import compress, aes, bip340_tagged_hash, derive_mlkem_keypair, get_ecdh_secret, get_reader_id, get_aeskey, contents, sign, encode
from .decode import decompress, unaes, check_sig, decode, deconstruct, CMDataError, CMDataErrorCode
from .centurymetadata import (
    CenturyMetadata,
    Identity,
    IdentitySource,
    Record,
    PsbtRecord,
    TransactionRecord,
    DescriptorRecord,
    WalletLabelsRecord,
    UnknownRecord,
    NEXT_DERIVATION_TYPE,
)

__all__ = [
    "compress",
    "aes",
    "bip340_tagged_hash",
    "derive_mlkem_keypair",
    "get_ecdh_secret",
    "get_reader_id",
    "get_aeskey",
    "contents",
    "sign",
    "encode",
    "PLAINTEXT_LENGTH",
    "AES_LENGTH",
    "DATA_LENGTH",
    "MLKEM_CT_LENGTH",
    "RECORD_LENGTH",
    "verheader",
    "preamble",
    "decompress",
    "unaes",
    "check_sig",
    "decode",
    "deconstruct",
    "CMDataError",
    "CMDataErrorCode",
    "CenturyMetadata",
    "Identity",
    "IdentitySource",
    "Record",
    "PsbtRecord",
    "TransactionRecord",
    "DescriptorRecord",
    "WalletLabelsRecord",
    "UnknownRecord",
    "NEXT_DERIVATION_TYPE",
]
