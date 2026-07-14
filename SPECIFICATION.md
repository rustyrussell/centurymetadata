# Century Metadata Format Specification

## Introduction

The *Century Metadata Format* is designed to store data for the long
term.  This makes standards vital, so we spell out those requirements
here, split into Reader (wallet) and Writer (server) sections for
maximal clarity.

## File Format

The file header (below) is embedded verbatim, byte-for-byte, at the start of every file. It contains exactly two real NUL bytes: the 19th byte (ending `centurymetadata v1`) and the final byte. Every other `\0` shown below is literal two-character notation (backslash, zero) marking where NUL-separators fall in `DATA` — not an actual NUL byte:

```
centurymetadata v1\0SIG[64]|WRITER_PUBKEY[33]|READER_ID[32]|GEN[8]|MLKEM_CT[1568]|AES[14679]

SIG: BIP-340 SHA256(TAG|TAG|WRITER_PUBKEY|READER_ID|GEN|MLKEM_CT|AES)
WRITER_PUBKEY: BIP-32 0x44315441'/N'/0'
READER_SECP_PRIVKEY: BIP-32 0x44315441'/N'/1'
READER_SECP_PUBKEY: 33-byte compressed G*READER_SECP_PRIVKEY
READER_MLKEM_SEED_D: BIP-32 0x44315441'/N'/3'
READER_MLKEM_SEED_Z: BIP-340 SHA256(MLKEM_Z_TAG|MLKEM_Z_TAG|READER_MLKEM_SEED_D)
MLKEM_Z_TAG: SHA256("centurymetadata v1 mlkem-z"[26])
READER_MLKEM_PRIVKEY, READER_MLKEM_PUBKEY: ML-KEM-1024.KeyGen(d=READER_MLKEM_SEED_D,z=READER_MLKEM_SEED_Z)
READER_ID: SHA256(READER_SECP_PUBKEY|READER_MLKEM_PUBKEY)
TAG: SHA256("centurymetadata v1"[18])
MLKEM_CT: ML-KEM-1024 (FIPS 203) ciphertext encapsulated to reader's ML-KEM key
MLKEM_SECRET: ML-KEM-1024.Decaps(MLKEM_CT, READER_MLKEM_PRIVKEY)
ECDH_SECRET: EC Diffie-Hellman of WRITER_PUBKEY and READER_SECP_PRIVKEY = SHA256(33-byte compressed WRITER_PUBKEY*READER_SECP_PRIVKEY)
AESKEY: SHA256(ECDH_SECRET|MLKEM_SECRET|GEN)
AES: AES-256-GCM using AESKEY, 12-byte all-zero nonce, of DATA; 16-byte authentication tag appended
DATA: ZLIB([TYPE\0NAME\0CONTENTS\0]+), padded with 0 bytes to 14663\0
```

This describes the rest of the file contents.  For the remainder of
the document we divide this into:

1. Literal header (1187 bytes).
2. Cryptograhic header (1705 bytes).
3. AES-encrypted zlib stream containing tuples (14679 bytes).

### Reader Requirements

A reader of a century metadata file:
- MUST fail parsing if the first 19 bytes of the file are not `centurymetadata v1\0` (where the 19th byte is a NUL).
- MUST fail parsing if the length of the file is not exactly 17571 bytes.
- MUST otherwise ignore the first 1187 bytes (the literal header).
- MUST fail parsing if `READER_ID` does not equal SHA256(`READER_SECP_PUBKEY`|`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to.
- MUST fail parsing if `SIG` is not a valid BIP-340 signature by `WRITER_PUBKEY` over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
- If `WRITER_PUBKEY` does not equal the pubkey the reader itself would derive at `0x44315441'/N'/0'` (for the `N` used to derive this file's reader keys):
  - MAY choose to fail parsing.
  - MAY choose not to process all type records (e.g. to display `bitcoin wallet labels` fields).
  - If the reader chooses not to fully process the file:
    - SHOULD indicate this omission to the user.
- If `MLKEM_CT` does not successfully decapsulate to a 32-byte `MLKEM_SECRET`:
  - MUST fail parsing.
- MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC point from Diffie-Hellman of `WRITER_PUBKEY` and `READER_SECP_PRIVKEY`.
- MUST SHA256 the concatenation of `ECDH_SECRET`, `MLKEM_SECRET` and `GEN` to derive the `AESKEY`.
- MUST use `AESKEY` to AES-256-GCM-decrypt the `AES` bytes (immediately following `MLKEM_CT`), using a 12-byte all-zero nonce.
- MUST fail parsing if the trailing 16-byte authentication tag does not verify.
- MUST fail parsing if the decrypted bytes do not contain a valid zlib stream.
- MUST fail parsing if the decompressed size would exceed 1048576 bytes.
- MUST ignore any bytes remaining after the zlib stream.
- MUST parse the decompressed bytes as a sequence of TYPE\0NAME\0CONTENTS\0 tuples, in order:
  - MUST separate `TYPE`, `NAME` and `CONTENTS` by NUL terminators.
  - MUST stop processing (keeping all tuples already parsed) upon reaching a tuple for which fewer than three NUL-terminated fields remain.
  - If `TYPE` is not a known type:
    - MUST ignore that tuple and continue processing.
  - Otherwise:
    - SHOULD use NAME as a descriptive text for the user's information.

#### Rationale

1. The magic string "centurymetadata v1\0" will change if we change the spec
   in incompatible ways in future.
2. This represents the Literal header followed by 16384 bytes.
3. Minor textual changes (but not length changes) to the Literal Header are
   compatible.
4. We cannot decrypt if we don't have the keys.  This is usually the `0x44315441'/0'/1'` and `0x44315441'/0'/3'` derivation, but could be different for chained files.
5. The signature check is to protect against malicious serving or malformed files, particularly in the case where this is our own writer key (thus the data can be trusted).  The signature (after the tags) is conveniently over the entire file following the `SIG` field itself.
6. Others could potentially write data to give to us.  This runs the risk of an exploit in our parser, so should be treated as untrusted data.  Given the sensitivity of the data we're handling, special treatment may be warranted.  But the user should at least be told the data exists!
7. ML-KEM-1024 Decaps can fail, and is expected to produce 32 bytes of data.
8. AES-GCM decryption can fail outright — the authentication tag won't verify — rather than silently producing garbage: a second, independent integrity check alongside `SIG`.
9. zlib decompression can fail (it has a 32-bit checksum).
10. Implementations must take care not to run out of memory when decompressing; 1MB is beyond a reasonable compression ratio for this size.
11. There is explicit padding after the zlib stream, which must be ignored.
12. A malformed or truncated tuple doesn't invalidate entries already parsed: implementations stop at the first tuple they can't parse, keeping everything before it.  An unrecognized `TYPE` is simply skipped since future additions (or implementations only interested in a subset of types) shouldn't choke on types they don't understand.

### Writer Requirements

A writer of a century metadata file:
- MUST begin the file with the literal header.
- MUST set `WRITER_PUBKEY` to the compressed secp256k1 key it will use to sign the message.
- MUST set `READER_ID` to the SHA256 of the concatenated `READER_SECP_PUBKEY` and `READER_MLKEM_PUBKEY`.
- MUST encode `GEN` as an 8-byte little-endian unsigned integer.
- If it is sending a message to itself:
  - SHOULD derive `WRITER_PUBKEY` from the BIP-32 derivation path `0x44315441'/N'/0'`.
  - For the first file:
    - MUST use `N` = 0.
  - For successive files:
    - MUST write `N` as decimal text (`NAME` MAY be empty) in a `next cmdata derivation path` type record in the previous file.
    - SHOULD select `N` such that the resulting `READER_ID` has a similar prefix to the previous file.
- If a previous file for this `WRITER_PUBKEY` and `READER_ID` exists:
  - MUST set `GEN` to a number greater than all previous such files.
- Otherwise:
  - SHOULD set `GEN` to 0.
- SHOULD only use `TYPE` fields defined in this specification.
- If it uses a `TYPE` not defined in this specification:
  - MUST begin the type string with `_`.
- MUST create the tuples using the per-tuple requirements listed for each type.
- MUST only use valid UTF-8 strings without NULs for `TYPE`, `NAME` and `CONTENTS`.
- MUST terminate each of `TYPE`, `NAME` and `CONTENTS`, for every tuple including the last, with a single NUL character.
- MUST compress the terminated tuples using the zlib protocol:
  - MUST NOT set FDICT.
- Whenever the resulting compressed message is greater than 14663 bytes long:
  - MUST either:
    - Remove the lowest-priority tuples — priority being the order provided, lowest last — until the compressed message is no more than 14663 bytes long, OR
    - Add a `next cmdata derivation path` type record and place the remaining tuples in the next century metadata file.
- MUST pad the compressed stream with 0 bytes to make it 14663 bytes long.
- MUST compute `MLKEM_SECRET` and `MLKEM_CT` together via `ML-KEM-1024.Encaps(READER_MLKEM_PUBKEY)`.
- MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC point from Diffie-Hellman of `READER_SECP_PUBKEY` and the writer's secp256k1 private key.
- MUST use `SHA256(ECDH_SECRET|MLKEM_SECRET|GEN)` as the `AESKEY`.
- MUST use `AESKEY` to AES-256-GCM-encrypt the padded, compressed stream, using a 12-byte all-zero nonce, and append the 16-byte authentication tag.
- MUST set `SIG` to a BIP-340 signature, using the writer's secret key, over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).

#### Rationale

1. The header is designed to be both an identifier for the file, and a detailed description of how to read it.  This increases the chance of salvage in the future, and does not count towards the byte limit.
2. Deriving all the keys deterministically from a single BIP-32 seed ensures everything is recoverable from the same 12 words that recover the wallet itself.
3. The `WRITER_PUBKEY` allows changes to be validated: future `GEN` values will replace this file.
4. `GEN` is encoded little endian because Intel won.
5. The first file is always at index `N` equal to zero.  That file may indicate other `N` values to check, but that's explicit: there's no "key gap".
6. Using non-standard `TYPE`s usually defeats the purpose of long-term storage: you should propose a new type!  But reserving "_" prefixes avoids clashes with standard ones, at least.
7. NULs are disallowed inside `TYPE`, `NAME` and `CONTENTS` because NUL is the only field delimiter.  Most of these values are in fact plain ASCII, though `NAME` can be user-assigned.
8. Prohibiting a zlib preset dictionary (`FDICT`) guarantees any compliant reader can decompress with plain zlib alone.  They're almost never used, but let's be explicit here.
9. Padding every record to the exact same length, keeps PIR retreival simple and resource usage bounded.
10. `AESKEY` combines `ECDH_SECRET` and `MLKEM_SECRET` to form a hybrid scheme, where any bit weakness in either value doesn't reduce security.
11. BIP-340 (Schnorr) rather than ECDSA: simpler, provably secure, supports batch verification, and is already a standard, long-lived Bitcoin primitive.
