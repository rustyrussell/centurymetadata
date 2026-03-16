# centurymetadata.org: Long-term Bitcoin Metadata Storage

## About

*Century Metadata* is a project to provide storage for small amounts
of auxiliary data.  As an example, this is useful for Bitcoin wallets,
which can be restored from 12 seed words, but cannot know about more
complex funds without additional data.  On restore, your wallet would attempt to
fetch this data from [https://centurymetadata.org](https://centurymetadata.org) or a mirror.

We are currently in alpha, seeking feedback.

## File Format

The file format is designed to be self-explanatory and use standard,
long-lived primitives as much as possible.  Every file contains a
text preamble followed by binary header fields and encrypted data,
totalling 8192 bytes.  The preamble describes the binary format
which follows:

```
centurymetadata v1\0SIG[64]|WRITER[33]|READER_ID[32]|GEN[8]|KYBER_CT[1568]|AES[6487]

SIG: BIP-340 SHA256(TAG|TAG|WRITER|READER_ID|GEN|KYBER_CT|AES)
WRITER: secp256k1 x-only key
READER_ID: SHA256(reader_secp_pubkey|reader_kyber_pubkey)
TAG: SHA256("centurymetadata v1"[18])
KYBER_CT: Kyber-1024 KEM ciphertext encapsulated to reader's Kyber key
KYBER_SECRET: Kyber-1024.Decapsulate(KYBER_CT, reader_kyber_privkey)
ECDH_SECRET: EC Diffie-Hellman of WRITER and reader_secp_key
AESKEY: SHA256(ECDH_SECRET|KYBER_SECRET)
AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA
DATA: gzip([TITLE\0CONTENTS\0]+), padded with 0 bytes to 6487\0
```

The data itself is a series of NUL-separated title, contents pairs.
Obviously this cannot be validated on the production server, but the
test server (which only allows known keys) will check the file is
compliant.

## Usage with Bitcoin

The BIP 32 path recommended for centurymetadata is
`0x44315441'/N'/0'` through `/3'` (`DATA`),
where `N` starts at 0 and increments for each additional key set.
`/0'` is the writer secp256k1 key, `/1'` is the reader
secp256k1 key, `/2'` seeds the writer Kyber-1024 key, and
`/3'` seeds the reader Kyber-1024 key.  Each Kyber key pair is
derived from the 32-byte BIP32 private key d at that path: the ML-KEM-1024
seed is d concatenated with z, where z is the BIP-340 tagged hash of d with
tag "centurymetadata v1 kyber-z".
The WRITER and READER_ID fields in the file are
SHA256(secp_pubkey|kyber_pubkey) for their respective paths.
Of course, others can also send data to your reader key, but you know
that the record from your own writer key can be trusted. 

The types of records accepted are as follows:

* Title: `bitcoin psbt`, Body: base64-encoded PSBT
* Title: `bitcoin transaction` Body: hex-encoded transaction
* Title: `bitcoin miniscript` Body: miniscript string

## API

The test API endpoint can be found at [testapi.centurymetadata.org](https://testapi.centurymetadata.org/api/v1).

### Entry Creation: POST /api/v1/authorize/{READER_ID}/{WRITER_PUBKEY}/{AUTHTOKEN}

You need to get an *AUTHTOKEN* for each new entry.  There can only be
one entry for any *READER_ID*/*WRITER_PUBKEY* pair, but once the entry is
authorized it can be updated by the writer at any time.  *READER_ID* is the 64-character hex encoding of
SHA256(secp_pubkey|kyber_pubkey) for the reader, and *WRITER_PUBKEY* is the public key of the writer.

### Entry Update: POST /api/v1/update

Updates a previously authorized writer/reader entry.  The
`Content-Type: application/x-centurymetadata` should contain a valid
centurymetadata file.

### Entries Depth: GET /api/v1/fetchdepth

Since we bundle records by READER_ID prefix (e.g. all reader IDs starting with `42a3` might be bundled together), you need to know how long the prefix is: it starts as an empty prefix and increases by one hex digit as we grow, so bundles are always a reasonable size.

Returns a JSON object with member `depth` containing how many hex digits of READER_ID to use for `fetchbundle`.

### Retrieving Entries: GET /api/v1/fetchbundle/{READERPREFIX}

This returns the given bundle, as `Content-Type: application/x-centurymetadata`, consisting of multiple back-to-back
centurymetadata files.

## Tools

There is an experimental Python package to encode and decode
centurymetadata files in the [GitHub repository](https://github.com/rustyrussell/centurymetadata)

## Roadmap

I'm committed to maintaining this service for at least 5 years
as a trial.  After that if it's proven useful I would like to
spin it into a real not-for-profit foundation to provide as much
certainty on continuity as possible.

## How Much?

There will never be a charge for ratelimited updates or retrievals;
the idea is to charge a small cost for the creation of new entries to
cover ongoing running costs.  We may also accept donations.

## Who?

Rusty Russell started this as a side project; my original problem was
how to give someone timelocked bitcoin, but realized there was a large
related class of problems for someone to solve.

## Feedback

Advice, suggestions, kudos, blame: hosting is on [GitHub](https://github.com/rustyrussell/centurymetadata), and you can reach us on [Twitter](https://twitter.com/centurymetadata), or send
[me email](mailto:rusty@rustcorp.com.au) or other contact as listed on 
[my personal site](https://rusty.ozlabs.org).
