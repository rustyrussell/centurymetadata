verheader = b"centurymetadata v0\0"
preamble = verheader + b"""SIG[64]|WRITER[33]|READER[33]|GEN[8]|AES[8054]

SIG: BIP-340 SHA256(TAG|TAG|WRITER|READER|GEN|AES)
WRITER, READER: secp256k1 x-only keys
TAG: SHA256("centurymetadata v0"[18])
AESKEY: SHA256(EC Diffie-Hellman of WRITER,READER)
AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA
DATA: gzip([TITLE\\0CONTENTS\\0]+), padded with 0 bytes to 8054\0"""

FULL_LENGTH = 8192
DATA_LENGTH = FULL_LENGTH - (64 + 33 + 33 + 8)
RECORD_LENGTH = len(preamble) + FULL_LENGTH
# BIP340 tag excludes final \0
bip340tag = verheader[:-1]
