verheader = b"centurymetadata v1\0"
preamble = verheader + b"""SIG[64]|WRITER[33]|READER_ID[32]|GEN[8]|KYBER_CT[1568]|AES[6487]

SIG: BIP-340 SHA256(TAG|TAG|WRITER|READER_ID|GEN|KYBER_CT|AES)
WRITER: secp256k1 x-only key
READER_ID: SHA256(reader_secp_pubkey|reader_kyber_pubkey)
TAG: SHA256("centurymetadata v1"[18])
KYBER_CT: Kyber-1024 KEM ciphertext encapsulated to reader's Kyber key
KYBER_SECRET: Kyber-1024.Decapsulate(KYBER_CT, reader_kyber_privkey)
ECDH_SECRET: EC Diffie-Hellman of WRITER and reader_secp_key
AESKEY: SHA256(ECDH_SECRET|KYBER_SECRET)
AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA
DATA: gzip([TITLE\\0CONTENTS\\0]+), padded with 0 bytes to 6487\0"""

FULL_LENGTH = 8192
KYBER_CT_LENGTH = 1568
DATA_LENGTH = FULL_LENGTH - (64 + 33 + 32 + 8 + KYBER_CT_LENGTH)
RECORD_LENGTH = len(preamble) + FULL_LENGTH
# BIP340 tag excludes final \0
bip340tag = verheader[:-1]
