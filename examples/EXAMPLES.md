# Examples of using Century Metadata

## Creating an Encoded Record

You need two key pairs: one for the reader, and one for the writer.  Let's
use all-1 bytes for the writer's secp256k1 secret, all-2 bytes for the
reader's secp256k1 secret, and all-2 bytes as the seed for the reader's
ML-KEM-1024 key.

The `--reader-secret` argument takes two 32-byte hex secrets separated by
`/`: the secp256k1 private key, then the ML-KEM seed (used with
`derive_mlkem_keypair` to produce the ML-KEM keypair deterministically).

Let's encode two records, both of type `text`.  The first named `one`,
contents `text one`, the second named `two` with contents `text two`.

Here's how we'd do this with the example tool:

```
$ ./examples/centurytool.py --writer-secret=0101010101010101010101010101010101010101010101010101010101010101 \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --encode text one 'text one' --encode text two 'text two' --raw > /tmp/encfile
Derived reader_id: 86bc303b5a3a42d81319561bab832beb13bbcc66951893398db1150a5da26b9b
Writer pubkey: 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
```

The output is 16384 bytes of binary data (following the preamble header).
It is non-deterministic because the ML-KEM encapsulation uses randomness.

And here's how we'd do this in python:

```python
import centurymetadata
import secp256k1

# Dummy secrets!
writer_privkey = secp256k1.PrivateKey(bytes((1,) * 32))
reader_secp_privkey = secp256k1.PrivateKey(bytes((2,) * 32))
reader_mlkem_seed = bytes((2,) * 32)

reader_secp_pubkey = reader_secp_privkey.pubkey
reader_mlkem_pubkey, reader_mlkem_privkey = centurymetadata.derive_mlkem_keypair(reader_mlkem_seed)

# Generation is 0, as this is our first data
enc = centurymetadata.encode(writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey,
                             0, ('text', 'one', 'text one'), ('text', 'two', 'text two'))
```

If you are encoding for someone else (you have their public keys, not their
secrets), use `--reader=secp_pubkey_hex/mlkem_pubkey_hex`.  For our example
reader with secrets `0202.../0202...`, the public keys are:

```
--reader=024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766/60e56b72c5821af22a359880ed38c94b828c8eb74609a6c845f1be5f244e8d99890c5609087778b48b6d0f7693a5e80da8490c20c9367d6110a31507c126bf15374a74e460d13188cf0b1885b3c884a042fe253a6b487a9597c3c1f0c674fc2358c7b7712c77ce676907905dc0e8363d6461c41aa8d0d47cae478dcda321f3b0c2b7008d86a97e1613678109bdcdb7327a58cdf312c0512910946a9df2308585810443932d46e8b93b9511a9161e79c749f3812b34bacb6c77c745a5a33a4a230c9330b5f5bc185147d426c86313b1eaa21fd54a15a3635ab0405dfe30025b49369262b5d88a051e7c62a9473172c52c45d50784dc4f28008483b31e81d68075ea782e368773f80cc777aad8540c8203000cd57c5b45a322b3134e25088ff7116592cb7b236849935426062d8c0acd0c34314b939df64a794fe0aae14ba778e18bc7324d9d0a6f82980e1052a08a29af6ba392b4e23ccee2cddbf7905ca1ae1d086878d6044d911c0f56c4a41a337c3644e2120f672181f49049143c3da7fac725c97c0d5a4d0df10789935684b88b22c65769ecaf5df34a32d7c3d05449b725ba758c9f0fbcb326a6a6d48a8d81881bfcf6694db88bdfdb2218d4a0b55b8ddaf8077f181a60dacd3d456d65f2a01bd87b654355189656cc398e2f1a2312484427017cd53b56879c172a4558f26aa415b2ce2e3382946b5eda3320f6d8760fb8131ad88d4493028424b1ed73a8cfdc9644fcb5ade912696271ea57606e008eb1ec9be8e2a25d145984f37a158b08563c60b9668cd0779005c3ae39e400744953ffba3dc56ac8303b2f51a50c85a19106d8cff0114b8acc652218750775903dc372501c0f277990450b0883db30dd93b49ce1be2bb7affed88135d99c5d964874642156220025e9839d7472b1c3b775802dc2329dd34c0e656669c45b851c496e8fa43f9024b593210bf4886b910438875363173256d088a34e5bb1deb70e2a9c52d4639b51a0ccecfb68fc9194952113eb2730a061788f4989f6f0bf657c0a614060d480a6d5494059598c51b50bd898b8ddf7b5fc7633206c81301c44c58a6c05131e2f8aa7491b68a8679e5b705fc68b8d9c76185f60340f300a3375a108190ba3993cb6d0ca07fb68156601c097b293c75eb080b56eb075d6ba8db6132b988a103fc36898274f9a7668893b6711200bb71cc16362ba3c19cec30549a6c6a64ef503bd53527f47852846cc8af42dc949ba79866f6e52a6c9c081ddc456fc2b239fb405abe61056ac859253b9b39685f3d36fc0a6472554cfd800bfb373458fbc43a661b25e1332970c9fcfa4bf50b289ecb319e7f59443563e5309a5d0c75be0587ce5f9aa1ca6bcb4aa671083ae535a4ac94210cb6c1f60675035359429aa943794bf482b56f8f696542871d6747760396140d92304a37efad84307492a5f0292a9fc08d7a5cf69082084c04d26122efb46ca02725b7bd9a9839b5fcb91b6833586f623c5a1a48d088533acb92af2b40ee1d784d137ab49714e0a3a77e8fa8084e80987870afd29c5aaa04e7af95fb58b0ed78a2b5b1526058ba6728b70d311002fdb7ec93755ac8a48fa7923d8b747ee105022d075eda89dce362366c11cb41294c07008d5d77546fb603dac8cbf61b9895ab1ed45744f78c734b26be1cc8017b15d736253324a7965969a00408258fc2dfc5933c4199891465871120e1848cc55dc698bb636ccb38315400f2528150a329ef0fa3da5318dc0889a40979c57dc939c046c73201ef4ecca629348f37164da52a085b0661b03c82454ba5005c83d750ebf2812df1189081297ded189e4c248f4b85e3111b96c70996c4052c46b2b5a5a5612ec1d022a9fb6ab617ecb9749227c80f23d63014cf2ea34c6521e30ab96d38345ce1583bf028b1099763d5321c177298fea52bf5b556afac9d1b430fb215bc6b469c859461cc49b6a9cb3748606542cb5575057587167ddf04290800938c83a16256a1948135b76af771485818b39195486f7bc557dabbc0c675a60997e08c9b2f8ab19c47499198033f0139b01e00b68b68896c2718cec2c8e0b38dd3b172345a53b02a38e6b890a990cc3ebaae6c82a961cb4ec47981616c97a3a39a3c5a3d36ac8515119f17352b7a1039703a59e620b5ad73ad1253c586259693bc2dd63f8ab92be14256a97f95088abb66af28f7c99d9587c3f0961b864b60000237e242ae25ac87216b971fa58f30d535b8d6207ad96359f18744429ecbd7abd10233326238ed1a270c7c39012669ba6154ec0517842893879302df391f0e631682c04e5458a180a4c89f7924635c2a4f04bc30029fe7dc7a611342bfd36b76ac18c58c5d92fa5c55e951d05007076242ae9c3251c63838c1b22562094ab89419111000e2b0816151c0058aefc2747fc24a4463bc792638e1c7a50b4c43705452d1c8393af72359679d01543ddeb02f426a92ed66b0007c6eb31254eac55e5ecb1b9125cb60897c37755bed3a9806c1b697f6ace52c5386e073695b8bb8d71bd92a4c3ad51ca6e9c20c84787804a3fadb69f2764b3975cfe3c80a67e72b16c2ce40ab15c91a145206067a2aab5eeb29cef29bd891a5ee484acf6b235ac1c00fd804bf9b58ae1095a5812166f11480a2677b05c80d2323296c3ad5744c7346b39282819ad540fbb540a8b09019e981636697bb497a7cb93f1a579066632a5abc45d5fc7c4ee695a9740d3566bf275c71226535fa5cb3dbf60c59a8ae9be75a65e871761a14f7f68225ea599cd61bee11084a1b8b9cd82edfbb724a126ed3a0782b59462050274694ccbce8b6e3397b2dd513ae5a59ab62131a6144a5e5b5c5f9985c70bdaf165dbbd3b839c729b0c3abeef97679d601dbb1a64243b2d30bada9b98d07f1795790b409a30ea09113dd0bc315089ddbb7839102799f693b348301d79402cdd80562f60c3ffabb3efb61c4e4446a9317d6876cffa432242570cb1a37957971a7a33242257ea89719f62148e6860b60e5470b305821ec9a61f2cb6bd32036d153e28513a65c5365515f83d575094a1c9ca2a5e6276605333eed748da7622387c777c312b504c601bef00a392090cb62c80089245f6150f39418b5c0403c49ac72ca531c870674281a73d8ad468c2cacac4723c88425fca755917420096c973112eebacb649194bab41e09926ed68ba44682a558e8ac8c9b97197a044d28119529333b29c002e64295822623e72f5eb95430a8a4089a8775d2a5bd701246c07bc4d54710146a0996b3d973bd624c00cb8255456a66b1f055f566249dc49bcaa08d0cd30864aa8be6bc8bdb4bca8d9c8309293ad1f41a38d692430b9ee8633c8c5951b53598dd17835c577f4548b3119b782396053ee4949882458e1747d57ab5005c8b9ca85bee7725371aa2b9481d5212b344598b93437a51020f2c720a058b75055795cb0a18826327d8159497a986ab1a4508ba818ac330194a2614a0883fc19dc8e5c95d227885fca7cf80910db237f1e65ddad196c2398a8a41af928534e0087858594ae4d69cfa36c2d7186a87469fae3ca9d01371dbc70e7c4bc316018aeac05adcc3ce60d8850ad05f9fec411d21225c39c613516f0d7675abb6240c58cc682760aec120dd79475a8a5a6235206d66953cac6bc86b6fbb004ef4369592a48ba8624575eb91fd71184e39666286917285a05e905c1aaac252f46e2781655fdcaab238bb790b6f29712d2ca45318f09ed03b0ddc8a0314303f24c7cc9dc25b3a0294c13a56bbb88e1941b70a2500d892ac2ba2137cb455c7048846b6110d6641dda43cda3c3b750353c6459578128249146f39371beeba8417c467ff03c3a1d34e0eb031fa6579c00893ce867cd4aa71664ac36cc54f92511825259b7f1c058d322d78dc81772c146d5a900587189ab113841bac50f725f7b642ee12c0efbc2cedf7500b55a1c9a16860d5bfb7488ab31b0426e549b0b632dd34675393348a841524554102345060197cf079ba1f09859b837e222468cf65b9d36592d48609621a4e4572ba733285b5b12e5f2553827aa5673389bbbb18eda73c2ffa3655299c7f9c602bb67bcdb6cabf2a7faacb9aeafa757d17401018cef0b43c0cd311a2cc8a038c
```

## Uploading an Encoded Record

Now we have our reader_id (`86bc303b...`) and writer pubkey (`031b84c5...`),
we can authorize the server to accept updates.  The AUTHTOKEN for the
test server is 64 zeros, so we simply do:

```
$ curl -d '' http://testapi.centurymetadata.org/api/v1/authorize/86bc303b5a3a42d81319561bab832beb13bbcc66951893398db1150a5da26b9b/031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f/0000000000000000000000000000000000000000000000000000000000000000
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
  --encode text one 'text one' --encode text two 'text two' --generation 2 --raw > /tmp/encfile1
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
returns the result — always 1024 × 16384 = 16,777,216 bytes.  With a
single bit set you simply get that bundle back:

```
$ printf '\x01%0.s' {1..127} | cat <(printf '\x01') - | \
  curl --data-binary @- -H 'Content-Type: application/octet-stream' \
  http://testapi.centurymetadata.org/api/v1/fetchxor/00-ff > /tmp/bundle
```

Each 16384-byte slot in the bundle contains a record (SIG[64]|WRITER[33]|
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
reader_id: 86bc303b5a3a42d81319561bab832beb13bbcc66951893398db1150a5da26b9b
generation: 2
```

With the reader key, we can decrypt it:

```
./examples/centurytool.py \
  --reader-secret=0202020202020202020202020202020202020202020202020202020202020202/0202020202020202020202020202020202020202020202020202020202020202 \
  --raw --decode @/tmp/encdata
text
one
text one

text
two
text two

```
