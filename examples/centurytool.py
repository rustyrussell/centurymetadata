#! /usr/bin/python3
import centurymetadata
import secp256k1
import argparse
import json
import requests
import sys


def parse_reader_public(reader_str):
    """Parse --reader as 'secp_pubkey_hex/mlkem_pubkey_hex'"""
    parts = reader_str.split('/')
    if len(parts) != 2:
        print("--reader must be secp_pubkey_hex/mlkem_pubkey_hex", file=sys.stderr)
        exit(1)
    try:
        secp_pubkey = secp256k1.PublicKey(bytes.fromhex(parts[0]), raw=True)
        mlkem_pubkey = bytes.fromhex(parts[1])
    except Exception as e:
        print("Bad --reader: {}".format(e), file=sys.stderr)
        exit(1)
    return secp_pubkey, mlkem_pubkey


def parse_reader_secret(secret_str):
    """Parse --reader-secret as 'secp_privkey_hex/mlkem_seed_hex'"""
    parts = secret_str.split('/')
    if len(parts) != 2:
        print("--reader-secret must be secp_privkey_hex/mlkem_seed_hex", file=sys.stderr)
        exit(1)
    try:
        secp_privkey = secp256k1.PrivateKey(bytes.fromhex(parts[0]))
        mlkem_seed = bytes.fromhex(parts[1])
    except Exception as e:
        print("Bad --reader-secret: {}".format(e), file=sys.stderr)
        exit(1)
    mlkem_pk, mlkem_sk = centurymetadata.derive_mlkem_keypair(mlkem_seed)
    return secp_privkey, mlkem_pk, mlkem_sk


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--writer-secret", help="Writer secret key (64 hex digits)")
    parser.add_argument("--reader", help="Reader public keys (secp_pubkey_hex/mlkem_pubkey_hex)")
    parser.add_argument("--reader-secret", help="Reader secret keys (secp_privkey_hex/mlkem_seed_hex)")
    parser.add_argument("--generation", type=int, help="Generation number", default=0)
    parser.add_argument("--raw", help="Output raw binary, suppress other output", action="store_true")
    parser.add_argument("--decode", help='hex string to decode (@ means read raw binary filename)')
    parser.add_argument("--encode", help='title body pair to encode (@ means read filename)', nargs=2, action="append", default=None)
    parser.add_argument("--check", help='check signature and print information (@ means read raw binary filename)')
    parser.add_argument("--fetch", help='fetch the record for the given reader (and optional writer)', action="store_true")
    parser.add_argument("--server", help='server to use', default='https://testapi.centurymetadata.org')
    args = parser.parse_args()

    # Derive reader keys
    reader_secp_privkey = None
    reader_secp_pubkey = None
    reader_mlkem_pubkey = None
    reader_mlkem_privkey = None
    reader_id = None

    if args.reader_secret:
        reader_secp_privkey, reader_mlkem_pubkey, reader_mlkem_privkey = parse_reader_secret(args.reader_secret)
        reader_secp_pubkey = reader_secp_privkey.pubkey
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)
        if not args.raw:
            print("Derived reader_id: {}".format(reader_id.hex()))
    elif args.reader:
        reader_secp_pubkey, reader_mlkem_pubkey = parse_reader_public(args.reader)
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)

    if args.decode:
        if not args.reader_secret:
            print("Decode needs --reader-secret", file=sys.stderr)
            exit(1)
        if args.decode.startswith('@'):
            decode_data = open(args.decode[1:], "rb").read()
        else:
            decode_data = bytes.fromhex(args.decode)
        ret = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey, decode_data)
        if ret is None:
            print("decode failed", file=sys.stderr)
            exit(1)
        for title, body in ret:
            print(title)
            print(body)
            print()
    elif args.encode:
        if reader_secp_pubkey is None or reader_mlkem_pubkey is None:
            print("Needs --reader or --reader-secret", file=sys.stderr)
            exit(1)

        if args.writer_secret is None:
            print("Needs --writer-secret", file=sys.stderr)
            exit(1)

        writer = secp256k1.PrivateKey(bytes.fromhex(args.writer_secret))
        if not args.raw:
            print("Writer pubkey: {}".format(writer.pubkey.serialize().hex()))

        ret = centurymetadata.encode(writer, reader_secp_pubkey, reader_mlkem_pubkey,
                                     args.generation,
                                     *args.encode)
        if args.raw:
            sys.stdout.buffer.write(ret)
        else:
            print(ret.hex())
    elif args.check:
        if args.check.startswith('@'):
            b = open(args.check[1:], "rb").read()
        else:
            b = bytes.fromhex(args.check)
        # Handle multiple concatenated entries
        while True:
            try:
                wkey, rec_reader_id, gen, after_pre = centurymetadata.deconstruct(b[:centurymetadata.RECORD_LENGTH])
            except ValueError as e:
                print("Malformed ({})".format(e), file=sys.stderr)
                exit(1)

            if not centurymetadata.check_sig(after_pre):
                print("Bad signature", file=sys.stderr)
                exit(1)

            if reader_id and reader_id != rec_reader_id:
                print("Bad reader_id {}".format(rec_reader_id.hex()), file=sys.stderr)
                exit(1)

            print("writer: {}".format(wkey.serialize().hex()))
            print("reader_id: {}".format(rec_reader_id.hex()))
            print("generation: {}".format(gen))

            b = b[centurymetadata.RECORD_LENGTH:]
            if len(b) == 0:
                break
        exit(0)
    elif args.fetch:
        if reader_id is None:
            print("Needs --reader or --reader-secret", file=sys.stderr)
            exit(1)

        listreq = requests.get(args.server + '/api/v1/listbundles')
        if listreq.status_code != 200:
            print("listbundles failed: {}".format(listreq.status_code), file=sys.stderr)
            exit(1)
        bundle_list = json.loads(listreq.text)

        # Find the rightmost bundle whose min prefix <= our reader_id
        rid_hex = reader_id.hex()
        target_dir = None
        target_idx = 0
        for entry in bundle_list:
            bmin = entry['bundle'].split('-')[0]
            if rid_hex[:len(bmin)] >= bmin:
                target_dir = entry['directory']
                target_idx = entry['index']

        if target_dir is None:
            print("No bundle found for reader_id {}".format(rid_hex), file=sys.stderr)
            exit(1)

        # Build 128-byte bitmask with only our bundle's bit set.
        # (For real PIR privacy, query two servers with complementary masks.)
        bitmask = bytearray(128)
        bitmask[target_idx // 8] |= (1 << (target_idx % 8))

        r = requests.post(args.server + '/api/v1/fetchxor/{}'.format(target_dir),
                          data=bytes(bitmask),
                          headers={'Content-Type': 'application/octet-stream'})
        if r.status_code != 200:
            print("fetchxor failed: {}".format(r.status_code), file=sys.stderr)
            exit(1)

        # Scan the bundle for our record: READER_ID sits at offset 64+33 in each slot
        bundle = r.content
        slot_size = centurymetadata.FULL_LENGTH
        reader_id_offset = 64 + 33  # after SIG[64] and WRITER[33]
        for i in range(1024):
            slot = bundle[i * slot_size:(i + 1) * slot_size]
            if slot[reader_id_offset:reader_id_offset + 32] == reader_id:
                record = centurymetadata.preamble + slot
                if args.raw:
                    sys.stdout.buffer.write(record)
                else:
                    print(record.hex())
                exit(0)

        print("Record not found in bundle", file=sys.stderr)
        exit(1)
    else:
        print("Needs --encode, --decode, --check or --fetch", file=sys.stderr)
        exit(1)
