# Century Metadata Format Specification

## Introduction

The *Century Metadata Format* is designed to store data for the long
term.  This makes standards vital, so we spell out those requirements
here, split into Reader (wallet) and Writer (server) sections for
maximal clarity.

Another key aim is that, should this data be disclosed in some way, only
privacy, not security is lost.  This means, in particular, that keys
and similar data are never represented directly, only as relative to
known keys.

## Table of Contents

  * [File Format](#file-format)
    * [Reader Requirements](#reader-requirements)
    * [Rationale](#reader-requirements-rationale)
    * [Writer Requirements](#writer-requirements)
    * [Rationale](#writer-requirements-rationale)
  * [Individual Record Formats](#individual-record-formats)
  * [Suggested Type Priorities](#suggested-type-priorities)
  * [Acknowledgments](#acknowledgments)
  * [References](#references)
  * [Authors](#authors)

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

1. Literal [ASCII](#ref-ascii) header with two NUL delimeters (1187 bytes).
2. Cryptograhic header (1705 bytes).
3. AES-encrypted [zlib](#ref-zlib) stream containing records: tuples separated by NUL bytes (14679 bytes).

### Reader Requirements

A reader of a century metadata file:
- MUST fail parsing if the first 19 bytes of the file are not `centurymetadata v1\0` (where the 19th byte is a NUL).
- MUST fail parsing if the length of the file is not exactly 17571 bytes.
- MUST otherwise ignore the first 1187 bytes (the literal header).
- MUST fail parsing if `READER_ID` does not equal [SHA256](#ref-sha256)(`READER_SECP_PUBKEY`|`READER_MLKEM_PUBKEY`) for a keypair the reader holds the secrets to.
- MUST fail parsing if `SIG` is not a valid [BIP-340](#ref-bip340) signature by `WRITER_PUBKEY` over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).
- If `WRITER_PUBKEY` equals the pubkey the reader itself would derive at `0x44315441'/N'/0'` (for the `N` used to derive this file's reader keys):
  - The file is referred to as "to-self".
- Otherwise: (not a "to-self" file)
  - MAY choose to fail parsing.
  - MAY choose not to process all type records (e.g. to display `bitcoin wallet labels` fields).
  - If the reader chooses not to fully process the file:
    - SHOULD indicate this omission to the user.
- If `MLKEM_CT` does not successfully decapsulate to a 32-byte `MLKEM_SECRET`:
  - MUST fail parsing.
- MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC point from [Diffie-Hellman](#ref-ecdh) of `WRITER_PUBKEY` and `READER_SECP_PRIVKEY`.
- MUST SHA256 the concatenation of `ECDH_SECRET`, `MLKEM_SECRET` and `GEN` to derive the `AESKEY`.
- MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-decrypt the `AES` bytes (immediately following `MLKEM_CT`), using a 12-byte all-zero nonce.
- MUST fail parsing if the trailing 16-byte authentication tag does not verify.
- MUST fail parsing if the decrypted bytes do not contain a valid [zlib](#ref-zlib) stream.
- MUST fail parsing if the decompressed size would exceed 1048576 bytes.
- MUST ignore any bytes remaining after the zlib stream.
- MUST parse the decompressed bytes as a sequence of TYPE\0NAME\0CONTENTS\0 tuples, in order:
  - MUST separate `TYPE`, `NAME` and `CONTENTS` by NUL terminators.
  - MUST stop processing (keeping all tuples already parsed) upon reaching a tuple for which fewer than three NUL-terminated fields remain.
  - If `TYPE` is not a known type:
    - MUST ignore that tuple and continue processing.
  - Otherwise:
    - If `NAME` is greater than 255 bytes or the record fails to parse, as defined in the requirements specific to that `TYPE` (specified in [Individual Record Formats](#individual-record-formats)):
      - If this is a "to-self" file:
        - MUST continue parsing remaining tuples
      - Otherwise (not a "to-self" file):
        - MAY continue parsing remaining tuples

### Reader Requirements Rationale

1. The magic string "centurymetadata v1\0" will change if we change the spec
   in incompatible ways in future.
2. This represents the Literal header followed by 16384 bytes.
3. Minor textual changes (but not length changes) to the Literal Header are
   compatible.
4. We cannot decrypt if we don't have the keys.  This is usually the `0x44315441'/0'/1'` and `0x44315441'/0'/3'` derivation, but could be different for chained files.
5. The signature check is to protect against malicious serving or malformed files, particularly in the case where this is our own writer key (thus the data can be trusted).  The signature (after the tags) is conveniently over the entire file following the `SIG` field itself.
6. Others could potentially write data to give to us.  This runs the risk of an exploit in our parser, so should be treated as untrusted data.  Given the sensitivity of the data we're handling, special treatment may be warranted.  But the user should at least be told the data exists!
7. [ML-KEM](#ref-mlkem)-1024 Decaps can fail, and is expected to produce 32 bytes of data.
8. [AES](#ref-aes)-[GCM](#ref-gcm) decryption can fail outright, which is technically redundant, but this widely-used AES mode also provides protection against accidental key reuse (in this case, non-random `MLKEM_SECRET` and duplicate `GEN` would be required, but bugs can happen).
9. [zlib](#ref-zlib) decompression can fail (it has a 32-bit checksum).
10. Implementations must take care not to run out of memory when decompressing; 1MB is beyond a reasonable compression ratio for this size using the [deflate](#ref-deflate) algorithm.
11. There is explicit padding after the zlib stream, which must be ignored.
12. A malformed or truncated tuple doesn't invalidate entries already parsed: implementations stop at the first tuple they can't parse, keeping everything before it.  An unrecognized `TYPE` is simply skipped since future additions (or implementations only interested in a subset of types) shouldn't choke on types they don't understand.
13. If it's a "to-self" file, it is trusted, so we should try really hard to process any data we can.  If it's not, it may make sense to stop immediately when something fails.

### Writer Requirements

A writer of a century metadata file:
- MUST begin the file with the literal header.
- MUST set `WRITER_PUBKEY` to the compressed [secp256k1](#ref-secp256k1) key it will use to sign the message.
- MUST set `READER_ID` to the [SHA256](#ref-sha256) of the concatenated `READER_SECP_PUBKEY` and `READER_MLKEM_PUBKEY`.
- MUST encode `GEN` as an 8-byte little-endian unsigned integer.
- If it is sending to itself (a "to-self" file):
  - SHOULD derive `WRITER_PUBKEY` from the [BIP-32](#ref-bip32) derivation path `0x44315441'/N'/0'`.
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
- Otherwise:
  - MUST meet any requirements specific to that `TYPE` as specified below.
- MUST create the tuples using the per-tuple requirements listed for each type.
- MUST only use valid [UTF-8](#ref-utf-8) strings without NULs for `TYPE`, `NAME` and `CONTENTS`.
- MUST limit `NAME` fields to 255 bytes.
- MUST write tuples in decreasing priority order (see [Suggested Type Priorities](#suggested-type-priorities)).
- MUST terminate each of `TYPE`, `NAME` and `CONTENTS`, for every tuple including the last, with a single NUL character.
- If it has read tuples from a previous version of the file:
  - MUST write back all tuples which it did not deliberately remove or alter.
- MUST compress the terminated tuples using the [zlib](#ref-zlib) protocol:
  - MUST NOT set FDICT.
- Whenever the resulting compressed message is greater than 14663 bytes long:
  - MUST either:
    - Remove the lowest-priority tuples until the compressed message is no more than 14663 bytes long, OR
    - Add a `next cmdata derivation path` type record and place the remaining tuples in the next century metadata file.
- MUST pad the compressed stream with 0 bytes to make it 14663 bytes long.
- MUST compute `MLKEM_SECRET` and `MLKEM_CT` together via [ML-KEM](#ref-mlkem)-1024's `Encaps(READER_MLKEM_PUBKEY)`.
- MUST compute `ECDH_SECRET` as SHA256 of the 33-byte compressed EC point from [Diffie-Hellman](#ref-ecdh) of `READER_SECP_PUBKEY` and the writer's secp256k1 private key.
- MUST use `SHA256(ECDH_SECRET|MLKEM_SECRET|GEN)` as the `AESKEY`.
- MUST use `AESKEY` to [AES](#ref-aes)-256-[GCM](#ref-gcm)-encrypt the padded, compressed stream, using a 12-byte all-zero nonce, and append the 16-byte authentication tag.
- MUST set `SIG` to a [BIP-340](#ref-bip340) signature, using the writer's secret key, over SHA256(`TAG`|`TAG`|`WRITER_PUBKEY`|`READER_ID`|`GEN`|`MLKEM_CT`|`AES`).

### Writer Requirements Rationale

1. The header is designed to be both an identifier for the file, and a detailed description of how to read it.  This increases the chance of salvage in the future, and does not count towards the byte limit.
2. Deriving all the keys deterministically from a single [BIP-32](#ref-bip32) seed ensures everything is recoverable from the same seed as the wallet itself (usually a [BIP-39](#ref-bip39) 12/24-word phrase).
3. The `WRITER_PUBKEY` allows changes to be validated: future `GEN` values will replace this file.
4. `GEN` is encoded little endian because Intel won.
5. The first file is always at index `N` equal to zero.  That file may indicate other `N` values to check, but that's explicit: there's no "key gap".
6. Using non-standard `TYPE`s usually defeats the purpose of long-term storage: you should propose a new type!  But reserving "_" prefixes avoids clashes with standard ones, at least.
7. [BIP 329](#ref-bip329) limits wallet names to "255 characters", which is a bit ambiguous in the case of non-ASCII UTF-8.  Bytes is slightly more conservative, and having a limit makes handling a little easier.
8. Priority order is important if we have to omit records which don't fit in the file, and also makes parsing easier: wallets come before their labels.
9. NULs are disallowed inside `TYPE`, `NAME` and `CONTENTS` because NUL is the only field delimiter.  Most of these values are in fact plain ASCII, though `NAME` can be user-assigned.
10. It's common to restore a file and write a new one.  Maximum compatibility means not changing things you don't deal with: unknown or unwanted records.  Note that this may still be omitted in some cases, if we run out of space.
11. Prohibiting a [zlib](#ref-zlib) preset dictionary (`FDICT`) guarantees any compliant reader can decompress with plain zlib alone.  They're almost never used, but let's be explicit here.
12. Padding every record to the exact same length, keeps PIR retreival simple and resource usage bounded.
13. `AESKEY` combines `ECDH_SECRET` and `MLKEM_SECRET` to form a hybrid scheme, where any bit weakness in either value doesn't reduce security.
14. [BIP-340](#ref-bip340) (Schnorr) rather than ECDSA: simpler, provably secure, supports batch verification, and is already a standard, long-lived Bitcoin primitive.

## Individual Record Formats

Each distinctive `TYPE` has its own requirements on the `NAME` and
`CONTENTS` fields.  These are generally references to other,
pre-existing standards.

Note that the phrase "fail to parse" here is specific language referred to in the general Reader Requirements previously.

### `next cmdata derivation path`

This record exists to chain files together, as each is of limited length.  It simply lists the next derivation path, rather than the next record keys directly.

#### Requirements

The reader:
- MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is not greater than `N` for this file.
- SHOULD fetch the file for that `N` value and continue processing records from that after this file.
- If it does:
  - MUST ignore this record if there is no file corresponding to that next `N` value.
- MUST NOT follow multiple `next cmdata derivation path` records in the same file.

The writer:
- MUST NOT create more than one of these records per file.
- MUST set `NAME` empty.
- MUST set `CONTENTS` to the derivation path `N` for the next file, as the ASCII representation of a decimal number.
- MUST choose `N` for the next file greater than this one.
- SHOULD choose the next `N` such that the reader key has a similar prefix.
- MAY write this record before creating the next file.

#### Rationale

For the reader:
1. The reader should ignore invalid records, or records which could lead to loops.
2. The user expects all the data to be read, so chaining should be followed, though there could
   be limits (particularly if it is not a "to-self" file).
3. The writer is allowed to create this record, then the new file.  The reader should not get upset in this case.
4. Since there should only be one chain, how a reader chooses to interpret multiple is left open to implementation convenience: first or last would be fine.

For the writer:
1. This is a chain, not a tree.
2. `NAME` doesn't make sense here.
3. All `CONTENTS` is text, so this is the logical representation.
4. This means it's easy for the reader to avoid loops.
5. Using neighboring keys promotes privacy, since records can be fetched in groups.  Generating N this way requires grinding, but an implementation could generate candidates for three seconds then choose the best one.
6. This simplifies implementation, though it is not required.

### `bitcoin psbt`

This type provides a partial transaction, possibly with parts pre-signed, and only requiring a signature which the wallet has access to.  The wallet user might then choose to sign and broadcast this on recovery.

#### Requirements

The reader:
- If `NAME` is non-empty:
  - If this is not a "to-self" file:
    - MAY indicate `NAME` as a description of the contents.
    - SHOULD indicate that `NAME` is not trusted.
  - Otherwise:
    - SHOULD indicate `NAME` as a description of the contents.
- If `CONTENTS` is not a valid base-64 encoded PSBT, or an unknown PSBT version:
  - MUST fail to parse the record.

The writer:
- MUST set `CONTENTS` to a valid base-64 encoded PSBT ([version 0](#ref-psbt) or [version 2](#ref-psbt2)).
- MAY set `NAME` to the description of the purpose of the PSBT.
- Otherwise:
  - MUST set `NAME` empty.

#### Rationale

For the reader:
1. Name is a useful suggestion ("Timelocked 18th birthday present for Alice"), but unless the file is trusted, may be misleading.

For the writer:
1. To be clear, if there's no known useful purpose string, "Made by FooWallet" or some other unrelated-to-purpose string is specifically discouraged.  It's OK to be silent when you have nothing useful to say!

### `bitcoin transaction`

This contains a full, valid bitcoin transaction.  It might have a timelock, and the user might choose to broadcast the transaction once it is valid.

#### Requirements

The reader:
- If `NAME` is non-empty:
  - If this is not a "to-self" file:
    - MAY indicate `NAME` as a description of the contents.
    - SHOULD indicate that `NAME` is not trusted.
  - Otherwise:
    - SHOULD indicate `NAME` as a description of the contents.
- If `CONTENTS` is not a valid hex-encoded bitcoin transaction:
  - MUST fail to parse the record.

The writer:
- MUST set `CONTENTS` to a valid hex-encoded bitcoin transaction.
- MAY set `NAME` to the description of the purpose of the transaction.
- Otherwise:
  - MUST set `NAME` empty.

#### Rationale

See [bitcoin psbt](#bitcoin-psbt) above.

### `bitcoin output script descriptor`

Bitcoin wallets can use their secret keys in different ways to spend funds; there may be separate sub-accounts, or multiple signers for funds.  This is compactly described by Output Script Descriptors, as per [BIP 380](#ref-bip380) and related standards [BIP 381](#ref-bip381), [BIP 382](#ref-bip382), [BIP 383](#ref-bip383), [BIP 384](#ref-bip384), [BIP 385](#ref-bip385), [BIP 386](#ref-bip386), [BIP 390](#ref-bip390) and [BIP 392](#ref-bip392).

#### Requirements

The reader:
- If `NAME` is non-empty:
  - If this is not a "to-self" file:
    - MAY indicate `NAME` as a description of the wallet.
    - SHOULD indicate that `NAME` is not trusted.
  - Otherwise:
    - SHOULD use `NAME` as the title for this wallet.
- If `CONTENTS` is not a valid output script descriptor, OR contains a checksum which does not match:
  - MUST fail to parse the record.
- If `CONTENTS` contains unknown or unsupported script expressions:
  - MUST fail to parse the record.
  - SHOULD indicate that this may be an incompatible (e.g. future) descriptor.
- Otherwise:
  - SHOULD restore this output script descriptor as a wallet.

The writer:
- SHOULD use the wallet name for the `NAME` field.
- MUST place a valid script BIP-380 descriptor describing the wallet format in the `CONTENTS` field.
- SHOULD include a checksum in the descriptor.

#### Rationale

For the reader:
- `NAME` is a common field across all wallets, and is useful for users to keep track, e.g. "Life savings" or "Petty cash".
- Script descriptors can be invalid, but are also extensible: the error given to a user for these two cases should be different.
  For example, a wallet restores a descriptor containing silent payment information, which it does not support, should warn the
  user that there may be funds it is unaware of.

For the writer:
- The BIP suggests a reader may refuse to parse a descriptor without a checksum, so including it is the most compatible choice.

### `bitcoin wallet labels`

Users can add informative labels to transactions seen by the wallet.  This is standardized in [BIP-329](#ref-bip329) as
a series of JSON objects, one per line (aka "JSONL").

#### Requirements

The reader:
- If `CONTENTS` is not valid JSONL:
  - MUST fail to parse the record.
- If `CONTENTS` contains an unknown `type` field:
  - MUST ignore that object.
  - SHOULD warn the user that it does not understand the complete label set.
- If `NAME` matches the `NAME` of a restored `bitcoin output script descriptor`:
  - If this is not a "to-self" file, and the restored `bitcoin output script descriptor` was a "to-self" file:
    - MAY apply these wallet labels to that wallet.
    - SHOULD indicate that the labels are not trusted.
  - Otherwise:
    - SHOULD apply the wallet labels to that wallet.
- Otherwise:
  - MAY apply the wallet labels to a suitable wallet.
- If it chooses to apply the wallet labels:
  - MUST do so as described in [BIP-329](#ref-bip329).
  - If this is a "to-self" file:
    - MUST continue processing remaining labels if one label is not valid.
  - Otherwise:
    - MAY stop processing remaining labels if one label is not valid.
  - MUST handle the case of multiple records applying to the same wallet.

The writer:
- MUST set `NAME` to match the name of the wallet these labels apply to.
- MUST set `CONTENTS` to the JSONL encoding of the wallet labels as per BIP-329.
- SHOULD restore any unknown or unused labels it read from the file, untouched.
- MAY provide multiple `bitcoin wallet labels` with the same `NAME`.

#### Rationale

For the reader:
1. Invalid records are skipped entirely, but future types should cause a warning that we might be too old.
2. An external wallet may have labels applied, but it's less obvious what to do for an external wallet to try to label your own transactions, so that it cautioned here.
3. The BIP indicates you can choose to omit some label types, though it does not explicitly say you should ignore unknown ones.
4. What to do on an invalid labels differs: for to-self files, it's a bug not malice, so makes sense to try to restore as much as possible.  Other files might be malice, so it makes sense to stop at the first sign of trouble.
5. If there are many labels, they might need to be split across multiple files, thus multiple records.

For the writer:
1. `NAME` matches the preceding wallet name, for easy matching.
2. Like for unknown records, we should seek to maintain unknown/unused labels.
3. In the case of too many labels, multiple files may be needed, and records cannot cross file boundaries, so multiple records are needed.

## Suggested Type Priorities

In the case where the user only has insufficient space, it's useful to
decide what to omit on a best-effort basis.  This should be done based
on "least likely to lose funds" basis.

1. `next cmdata derivation path`.  This doesn't take up much space, omitting this means truncating data, and so it gains more space than it takes.
2. `bitcoin output script descriptor`.  This is the wallet definition itself, though if the wallet contains no funds and has issued no addresses, it could be omitted.
3. `bitcoin transaction` and `bitcoin psbt`.  This may be omitted if it does not deliver funds to the wallet itself, or is invalid (i.e. spending long-spent outputs).
4. `bitcoin wallet labels`.  This is the lowest priority, but may be *reduced* if necessary by omitting some labels.  How to choose which to omit is currently an exercise for the reader.
5. Other types.  Without other knowledge, we assume these are mere annotations and so are least important.

## Acknowledgments

I would like to thank my supportive wife and children, without whom I would not be able to spend my time thinking about protocols.  And who also stop me thinking about protocols, when necessary!

## References

The following standards are used, in historical order (most predate their latest standard versions, but deriving the date of Ken and Rob's diner placemat is left as an exercise for the reader):

* <a id="ref-ascii"></a>RFC 20 — "ASCII format for Network Interchange" (Vint Cerf, 1969) 
  https://www.rfc-editor.org/info/rfc20/
* <a id="ref-zlib"></a>RFC 1950 — "ZLIB Compressed Data Format Specification version 3.3" (P. Deutsch & J-L. Gailly, 1996) 
  https://www.rfc-editor.org/info/rfc1950/
* <a id="ref-deflate"></a>RFC 1951 — "DEFLATE Compressed Data Format Specification version 1.3" (P. Deutsch, 1996)
  https://www.rfc-editor.org/info/rfc1951/
* <a id="ref-aes"></a>FIPS 197 — "Advanced Encryption Standard (AES)" (NIST, 2001)
  https://doi.org/10.6028/NIST.FIPS.197
* <a id="ref-sha256"></a>FIPS 180-2 — "Secure Hash Standard (SHS)" (NIST, 2002) 
  https://doi.org/10.6028/NIST.FIPS.180-2
* <a id="ref-utf-8"></a>RFC 3629 — "UTF-8, a transformation format of ISO 10646" (F. Yergeau, 2003) 
  https://www.rfc-editor.org/info/rfc3629/
* <a id="ref-gcm"></a>NIST SP 800-38D — "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC" (Morris Dworkin, 2007)
  https://doi.org/10.6028/NIST.SP.800-38D
* <a id="ref-ecdh"></a>SEC 1 — "Elliptic Curve Cryptography" (Certicom Research, 2009) 
  https://www.secg.org/sec1-v2.pdf
* <a id="ref-secp256k1"></a>SEC 2 — "Recommended Elliptic Curve Domain Parameters" (Certicom Research, 2010) 
  https://www.secg.org/sec2-v2.pdf
* <a id="ref-bip32"></a>BIP 32 — "Hierarchical Deterministic Wallets" (Pieter Wuille, 2012) 
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
* <a id="ref-bip39"></a>BIP 39 — "Mnemonic code for generating deterministic keys" (Marek Palatinus, Pavol Rusnak, Aaron Voisine, Sean Bowe, 2013) 
  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
* <a id="ref-psbt"></a>BIP 174 — "Partially Signed Bitcoin Transaction Format" (Ava Chow, 2017) 
  https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
* <a id="ref-bip340"></a>BIP 340 — "Schnorr Signatures for secp256k1" (Pieter Wuille, Jonas Nick, Tim Ruffing, 2020) 
  https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
* <a id="ref-psbt2"></a>BIP 370 — "PSBT Version 2" (Ava Chow, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
* <a id="ref-bip380"></a>BIP 380 — "Output Script Descriptors General Operation" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
* <a id="ref-bip381"></a>BIP 381 — "Non-Segwit Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki
* <a id="ref-bip382"></a>BIP 382 — "Segwit Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki
* <a id="ref-bip383"></a>BIP 383 — "Multisig Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki
* <a id="ref-bip384"></a>BIP 384 — "combo() Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
* <a id="ref-bip385"></a>BIP 385 — "raw() and addr() Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0385.mediawiki
* <a id="ref-bip386"></a>BIP 386 — "tr() Output Script Descriptors" (Pieter Wuille, 2021) 
  https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
* <a id="ref-bip329"></a>BIP 329 — "Wallet Labels Export Format" (Craig Raw, 2022) 
  https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki
* <a id="ref-mlkem"></a>FIPS 203 — "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)" (NIST, 2024) 
  https://doi.org/10.6028/NIST.FIPS.203
* <a id="ref-bip390"></a>BIP 390 — "musig() Descriptor Key Expression" (Ava Chow, 2024) 
  https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki
* <a id="ref-bip392"></a>BIP 392 — "Silent Payment Output Script Descriptors" (Craig Raw, 2026) 
  https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki

## Authors

Rusty Russell was the author of this specification: <rusty@rustcorp.com.au> or <rusty@centurymetadata.org>.
