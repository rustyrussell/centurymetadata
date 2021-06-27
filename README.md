# centurymetadata.org: Long-term Bitcoin Metadata Storage

## About

_Century Metadata_ is a project to provide storage for small amounts
of auxiliary data.  As an example, this is useful for Bitcoin wallets,
which can be restored from 12 seed words, but cannot know about more
complex funds without additional data.  On restore, a would attempt to
fetch this data from [centurymetadata.org] or a mirror.

We are currently in alpha, seeking feedback.

## File Format

The file format is designed to be self-explanatory and use standard,
long-lived primitives as much as possible.  Every file contains a
preamble, followed by 8192 bytes.  The preamble describes the data
format which follows:

    centurymetadata v0\0SIG[64]|WRITER[32]|READER[32]|GEN[8]|AES[8056]

    SIG: BIP-340 SHA256(TAG|TAG|WRITER|READER|GEN|AES)
    WRITER, READER: secp256k1 x-only keys
    TAG: SHA256("centurymetadata"[15])
    AESKEY: SHA256(0x02 | Diffie-Hellman of WRITER,READER)
    AES: CTR mode (starting 0, nonce 0) using AESKEY of DATA
    DATA: gzip([TITLE\\0CONTENTS\\0]+), padded with 0 bytes to 8056\0

The data itself is a series of NUL-separated title, contents pairs.
Obviously this cannot be validated on the production server, but the
test server (which only allows known keys) will check the file is
compliant.


## Usage with Bitcoin


The BIP 32 path recommended for centurymetadata is `0x44315441'`
(`DATA`), with `/0'` as the writer key, `/1'` as the reader key.  Of
course, others can also send data to your reader key, but you know
that the record from your own writer key can be trusted.


The types of records accepted are as follows:

* Title: `bitcoin psbt`, Body: base64-encoded PSBT
* Title: `bitcoin transaction` Body: hex-encoded transaction
* Title: 1bitcoin miniscript` Body: miniscript string

## API

The test API endpoint can be found at [testapi.centurymetadata.org].

### Entry Creation: POST /api/v0/authorize/{WRITER}/{READER}/{AUTHTOKEN}

You need to get an *AUTHTOKEN* for each new entry.  There can only be
one entry for any *READER*/*WRITER* pair, but once the entry is
authorized it can be updated by the writer at any time.


### Entry Update: POST /api/v0/update

Updates a previously authorized writer/reader entry.  The
`Content-Type: application/x-centurymetadata` should contain a valid
centurymetadata file.


### Entries Index: GET /api/v0/index

This queries the bundles of entries which can be retrieved: we only
allow retreival of entire bundles.  Bundles are ordered by increasing
*READER*, then *WRITER* values.

Returns a JSON object with member `bundles` containing an
array of objects.  Each object contains `first_reader`,
`first_writer`, `last_reader`, `last_writer`.

### Retrieiving Entries: GET /api/v0/fetchbundle/{READERSTART}/{WRITERSTART}

This returns the given bundle, as `Content-Type:
application/x-centurymetadata`, consisting of multiple back-to-back
century metadata files.

## Tools

There is an experimental Python package to encode and decode
centurymetadata files in the [GitHub repository](https://github.com/rustyrussell/centurymetadata).

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

Advice, suggestions, kudos, blame: please send to
[me](mailto:rusty@rustcorp.com.au) or other contact as listed on 
[my personal site](https://rusty.ozlabs.org)
