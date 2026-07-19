# centurymetadata.org: Long-term Bitcoin Metadata Storage

## About

*Century Metadata* is a project to provide storage for small amounts
of auxiliary data.  As an example, this is useful for Bitcoin wallets,
which can be restored from 12 seed words, but cannot know about more
complex funds without additional data.  On restore, your wallet would attempt to
fetch this data from [https://centurymetadata.org](https://centurymetadata.org) or a mirror.

We are currently in alpha, seeking feedback.

## File Format

The [file format](SPECIFICATION.md#file-format) is designed to be
self-explanatory and use standard, long-lived primitives as much as
possible.  Every file contains a text preamble which describes the
format exactly, followed by the encrypted data.

The data itself is a series of NUL-separated type, name, contents
triples.  Obviously this cannot be validated on the production server,
but the test server (which only allows known keys) will check the file
is compliant.

## Usage with Bitcoin

The BIP 32 path recommended for centurymetadata is `0x44315441'/N'/0'`
through `/3'` (`DATA`), where `N` starts at 0 and increments for each
additional key set.  `/0'` is the writer secp256k1 key, `/1'` is the
reader secp256k1 key, `/2'` seeds the writer ML-KEM-1024 key
(currently unused), and `/3'` seeds the reader ML-KEM-1024 key.  The
READER_ID field is hashed, but if you share your reader keys others
could also send encrypted data to you: files created with your own
writer keys can be trusted.

The types of records accepted are:

* Type: `bitcoin psbt`, a base64-encoded PSBT for wallet to sign
* Type: `bitcoin transaction`, a hex-encoded transaction for wallet to broadcast
* Type: `bitcoin output script descriptor`, a wallet descriptor string to wallet to find funds
* Type: `bitcoin wallet labels`, a BIP-329 JSONL to annotate wallet
* Type: `next cmdata derivation path`, another `N` value for chaining more than one file.

The detailed requirements are [specified here](SPECIFICATION.md#individual-record-formats).

## API

The test API endpoint can be found at [testapi.centurymetadata.org](https://testapi.centurymetadata.org/api/v1).

### Entry Creation: POST /api/v1/authorize/{READER_ID}/{WRITER}/{AUTHTOKEN}

You need to get an *AUTHTOKEN* for each new entry.  There can only be
one entry for any *READER_ID*/*WRITER* pair, but once the entry is
authorized it can be updated by the writer at any time.  *READER_ID* is
the 64-character hex encoding of SHA256(secp_pubkey|mlkem_pubkey).

### Entry Update: POST /api/v1/update

Updates a previously authorized writer/reader entry.  The
`Content-Type: application/x-centurymetadata` should contain a valid
centurymetadata file.

### Listing Bundles: GET /api/v1/listbundles

Records are stored in a two-level hierarchy of directories and bundles, each bundle holding up to 1024 records.  To find your bundle, fetch the bundle listing.

Returns a JSON array of objects, each giving the `directory` and `bundle` names (hex-range identifiers) and the bundle's 0-based `index` within its directory: the bit position to set for `fetchxor`.

### Retrieving Entries: POST /api/v1/fetchxor/{DIRECTORY}

POST a 128-byte bitmask (one bit per bundle in the directory) as `Content-Type: application/octet-stream`. The server XORs together every bundle whose bit is set and returns the result as `Content-Type: application/x-centurymetadata`: always 1024 x 8192 = 8,388,608 bytes.  Setting a single bit simply returns that bundle.

For *private* retrieval, query two servers with complementary bitmasks (one with your bundle's bit set, one with it cleared, all other bits matching): XOR the two responses together to recover your bundle without either server learning which one you wanted.

## Known Test Keys

Because it holds the corresponding private keys, the test server at
[testapi.centurymetadata.org](https://testapi.centurymetadata.org/api/v1) can decrypt
and check compliance for a small, fixed set of *known* reader identities, rejecting
`authorize`/`update` requests for any other `READER_ID`. A reader
identity is *known* if it is derived (as above) from a BIP-39 mnemonic consisting of
the same word repeated 12 times whose checksum happens to be valid: roughly 1 in 16 of the
2048-word English wordlist qualifies (130 words). The test server computes this set
itself from the public wordlist; there is no secret list to request access to.

Ordering these known words by their position in the wordlist, the first
half are the *normal* case: the record's `WRITER_PUBKEY` must match that same
identity's own derived writer key, i.e. the data is self-authored. The second half are
reserved for the test server's own pre-populated example data, and may use other writers.

For convenience when testing your own implementation, the first few known
words (ordered by wordlist position) are `action`, `agent`, `aim`;
the last few are `word`, `world`, `yellow`. The full,
authoritative list is the checked-in
[known_words.txt](https://raw.githubusercontent.com/rustyrussell/centurymetadata/master/python/centurymetadata/server/known_words.txt).

## Tools

There is an experimental Python package to encode and decode
centurymetadata files in the [GitHub repository](https://github.com/rustyrussell/centurymetadata)

## Roadmap

I'm currently raising startup funding.  If successful, I will use that to start a non-profit foundation to raise a long-term endowment to ensure the longevity of the data.

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
[me email](mailto:rusty@centurymetadata.org) or other contact as listed on 
[my personal site](https://rusty.ozlabs.org).
