# Examples of using Century Metadata

## Creating an Encoded Record

You need two key pairs: one for the reader, and one for the writer.  Let's
use all-1 bytes for the writer's secp256k1 secret, all-2 bytes for the
reader's secp256k1 secret, and all-2 bytes as the seed for the reader's
Kyber-1024 key.

The `--reader-secret` argument takes two 32-byte hex secrets separated by
`/`: the secp256k1 private key, then the Kyber seed (used with
`derive_kyber_keypair` to produce the Kyber keypair deterministically).

Let's encode two records, one titled `text`, contents `text one`, the
second also titled `text` and contents `text two`.

Here's how we'd do this with the example tool:

```
$ ./examples/centurytool.py --writer-secret=0101010101010101010101010101010101010101010101010101010101010101 \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --encode text 'text one' --encode text 'text two' --raw > /tmp/encfile
Derived reader_id: 9fdfee0fd29117971c256c275112effa4891629fae631c3fe75e514a16db4201
Writer pubkey: 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
```

The output is 8192 bytes of binary data (including the preamble header).
It is non-deterministic because the Kyber encapsulation uses randomness.

And here's how we'd do this in python:

```python
import centurymetadata
import secp256k1

# Dummy secrets!
writer_privkey = secp256k1.PrivateKey(bytes((1,) * 32))
reader_secp_privkey = secp256k1.PrivateKey(bytes((2,) * 32))
reader_kyber_seed = bytes((2,) * 32)

reader_secp_pubkey = reader_secp_privkey.pubkey
reader_kyber_pubkey, reader_kyber_privkey = centurymetadata.derive_kyber_keypair(reader_kyber_seed)

# Generation is 0, as this is our first data
enc = centurymetadata.encode(writer_privkey, reader_secp_pubkey, reader_kyber_pubkey,
                             0, ('text', 'text one'), ('text', 'text two'))
```

If you are encoding for someone else (you have their public keys, not their
secrets), use `--reader=secp_pubkey_hex/kyber_pubkey_hex`.  For our example
reader with secrets `0202.../0202...`, the public keys are:

```
--reader=024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766/6f5c98bd93369d3786426223abfb7ed02148ebf41850e651db52503b071996e7c0db8377ca481fdb8271554b9281bcbe299567a8bcbbf66a5eb8685779327473a356e7412279a84dcfe7bc327b88dcf2577f01c982d515be1a3094620c57e50e655b3bfb586bab92215e46ab67ba9908a760be3100d9380f94399b0b3844f83003e49b3d50a54c498038c426a369f016ab9751cf409a9f89aeb2e92395d9a39419a7139c49731a932a57ca4540416c143265d139b1bb034f9333bc436376e8813de984f23a5ed255539650145d566525a302aac7a0000237e242ae25ac87216b971fa58f30d535b8d6207ad96359f18744429ecbd7abd10233326238ed1a270c7c39012669ba6154ec0517842893879302df391f0e631682c04e5458a180a4c89f7924635c2a4f04bc30029fe7dc7a611342bfd36b76ac18c58c5d92fa5c55e951d05007076242ae9c3251c63838c1b22562094ab89419111000e2b0816151c0058aefc2747fc24a4463bc792638e1c7a50b4c43705452d1c8393af72359679d01543ddeb02f426a92ed66b0007c6eb31254eac55e5ecb1b9125cb60897c37755bed3a9806c1b697f6ace52c5386e073695b8bb8d71bd92a4c3ad51ca6e9c20c84787804a3fadb69f2764b3975cfe3c80a67e72b16c2ce40ab15c91a145206067a2aab5eeb29cef29bd891a5ee484acf6b235ac1c00fd804bf9b58ae1095a5812166f11480a2677b05c80d2323296c3ad5744c7346b39282819ad540fbb540a8b09019e981636697bb497a7cb93f1a579066632a5abc45d5fc7c4ee695a9740d3566bf275c71226535fa5cb3dbf60c59a8ae9be75a65e871761a14f7f68225ea599cd61bee11084a1b8b9cd82edfbb724a126ed3a0782b59462050274694ccbce8b6e3397b2dd513ae5a59ab62131a6144a5e5b5c5f9985c70bdaf165dbbd3b839c729b0c3abeef97679d601dbb1a64243b2d30bada9b98d07f1795790b409a30ea09113dd0bc315089ddbb7839102799f693b348301d79402cdd80562f60c3ffabb3efb61c4e4446a9317d6876cffa432242570cb1a37957971a7a33242257ea89719f62148e6860b60e5470b305821ec9a61f2cb6bd32036d153e28513a65c5365515f83d575094a1c9ca2a5e6276605333eed748da7622387c777c312b504c601bef00a392090cb62c80089245f6150f39418b5c0403c49ac72ca531c870674281a73d8ad468c2cacac4723c88425fca755917420096c973112eebacb649194bab41e09926ed68ba44682a558e8ac8c9b97197a044d28119529333b29c002e64295822623e72f5eb95430a8a4089a8775d2a5bd701246c07bc4d54710146a0996b3d973bd624c00cb8255456a66b1f055f566249dc49bcaa08d0cd30864aa8be6bc8bdb4bca8d9c8309293ad1f41a38d692430b9ee8633c8c5951b53598dd17835c577f4548b3119b782396053ee4949882458e1747d57ab5005c8b9ca85bee7725371aa2b9481d5212b344598b93437a51020f2c720a058b75055795cb0a18826327d8159497a986ab1a4508ba818ac330194a2614a0883fc19dc8e5c95d227885fca7cf80910db237f1e65ddad196c2398a8a41af928534e0087858594ae4d69cfa36c2d7186a87469fae3ca9d01371dbc70e7c4bc316018aeac05adcc3ce60d8850ad05f9fec411d21225c39c613516f0d7675abb6240c58cc682760aec120dd79475a8a5a6235206d66953cac6bc86b6fbb004ef4369592a48ba8624575eb91fd71184e39666286917285a05e905c1aaac252f46e2781655fdcaab238bb790b6f29712d2ca45318f09ed03b0ddc8a0314303f24c7cc9dc25b3a0294c13a56bbb88e1941b70a2500d892ac2ba2137cb455c7048846b6110d6641dda43cda3c3b750353c6459578128249146f39371beeba8417c467ff03c3a1d34e0eb031fa6579c00893ce867cd4aa71664ac36cc54f92511825259b7f1c058d322d78dc81772c146d5a900587189ab113841bac50f725f7b642ee12c0efbc2cedf7500b55a1c9a16860d5bfb7488ab31b0426e549b0b632dd34675393348a841524554102345060197cf079ba1f09859b837e222468cf65b9d36592d48609621a4e4572ba733285b5b12e5f2553827aa5673389bbbb18eda73c2ffa3655299c7f9c602bb67bcdb6cabf2a7faacb9aeafa757d17401018cef0b43c0cd311a2cc8a038c
```

## Uploading an Encoded Record

Now we have our reader_id (`9fdfee0f...`) and writer pubkey (`031b84c5...`),
we can authorize the server to accept updates.  The AUTHTOKEN for the
test server is 64 zeros, so we simply do:

```
$ curl -d '' http://testapi.centurymetadata.org/api/v1/authorize/9fdfee0fd29117971c256c275112effa4891629fae631c3fe75e514a16db4201/031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f/0000000000000000000000000000000000000000000000000000000000000000
Success
```

Now we can actually upload our record:

```
$ curl --data-binary @/tmp/encfile -H 'Content-Type: application/x-centurymetadata' http://testapi.centurymetadata.org/api/v1/update
Success
```

## Updating an Encoded Record

If we try to re-upload it, we get an error that it already exists:

```
$ curl --data-binary @/tmp/encfile -H 'Content-Type: application/x-centurymetadata' http://testapi.centurymetadata.org/api/v1/update
Bad Request (Generation 0 already exists)
```

We need a version with a greater generation number, so let's generate it:

```
$ ./examples/centurytool.py --writer-secret=0101010101010101010101010101010101010101010101010101010101010101 \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --encode text 'text one' --encode text 'text two' --generation 2 --raw > /tmp/encfile1
$ curl --data-binary @/tmp/encfile1 -H 'Content-Type: application/x-centurymetadata' http://testapi.centurymetadata.org/api/v1/update
Success
```

## Retreiving a Record

Records are stored in a two-level hierarchy of directories and bundles,
each bundle holding up to 1024 records.  To find your bundle, fetch the
bundle listing:

```
$ curl http://testapi.centurymetadata.org/api/v1/listbundles
[{"directory": "00-ff", "bundle": "00-ff", "index": 0}]
```

Each entry gives the directory name, the bundle name within it, and the
bundle's 0-based index (its bit position in the bitmask for `fetchxor`).

To fetch a bundle, POST a 128-byte bitmask to `fetchxor/{directory}`.
The server XORs together all bundles whose corresponding bit is set and
returns the result — always 1024 × 8192 = 8,388,608 bytes.  With a
single bit set you simply get that bundle back:

```
$ printf '\x01%0.s' {1..127} | cat <(printf '\x01') - | \
  curl --data-binary @- -H 'Content-Type: application/octet-stream' \
  http://testapi.centurymetadata.org/api/v1/fetchxor/00-ff > /tmp/bundle
```

Each 8192-byte slot in the bundle contains a record (SIG[64]|WRITER[33]|
READER_ID[32]|...) with empty slots zeroed.  Your record is the slot
whose READER_ID field (bytes 97–128) matches your reader_id.

For **private retrieval**, query two servers with complementary bitmasks R
and R⊕(1<<index): XOR their responses to recover your bundle without
either server learning which one you wanted.

There's a shortcut for single-server fetch using centurytool (no privacy):

```
./examples/centurytool.py \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --fetch --raw > /tmp/encdata
```

## Decoding a Record

Even without the key, we can check the record:

```
$ ./examples/centurytool.py --raw --check @/tmp/encdata
writer: 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
reader_id: 9fdfee0fd29117971c256c275112effa4891629fae631c3fe75e514a16db4201
generation: 2
```

With the reader key, we can decrypt it:

```
./examples/centurytool.py \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --raw --decode @/tmp/encdata
text
text one

text
text two

```
