preamble = b"""centurymetadata v0\0SIG[64]|WRITER[32]|READER[32]|GEN[8]|AES[8056]

SIG: BIP-340 SHA256(TAG|TAG|WRITER|READER|GEN|AES)
WRITER, READER: secp256k1 x-only keys
TAG: SHA256("centurymetadata"[15])
AESKEY: SHA256(0x02 | Diffie-Hellman of WRITER,READER)
AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA
DATA: gzip([TITLE\\0CONTENTS\\0]+), padded with 0 bytes to 8056\0
"""

DATA_LENGTH = 8056
FULL_LENGTH = 8192
