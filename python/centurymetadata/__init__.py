"""centurymetadata: routines to handle long-persistent, small encrypted data.

"""
from .constants import verheader, preamble, DATA_LENGTH, FULL_LENGTH, RECORD_LENGTH
from .encode import compress, aes, get_aeskey, contents, sign, encode
from .decode import decompress, unaes, check_sig, decode, deconstruct

__all__ = [
    "compress",
    "aes",
    "get_aeskey",
    "contents",
    "sign",
    "encode",
    "DATA_LENGTH",
    "FULL_LENGTH",
    "RECORD_LENGTH",
    "verheader",
    "preamble",
    "decompress",
    "unaes",
    "check_sig",
    "decode",
    "deconstruct",
]
