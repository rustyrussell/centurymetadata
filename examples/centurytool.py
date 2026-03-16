#! /usr/bin/python3
import centurymetadata
import secp256k1
import argparse
import json
import requests
import sys


def parse_reader_public(reader_str):
    """Parse --reader as 'secp_pubkey_hex/kyber_pubkey_hex'"""
    parts = reader_str.split('/')
    if len(parts) != 2:
        print("--reader must be secp_pubkey_hex/kyber_pubkey_hex", file=sys.stderr)
        exit(1)
    try:
        secp_pubkey = secp256k1.PublicKey(bytes.fromhex(parts[0]), raw=True)
        kyber_pubkey = bytes.fromhex(parts[1])
    except Exception as e:
        print("Bad --reader: {}".format(e), file=sys.stderr)
        exit(1)
    return secp_pubkey, kyber_pubkey


def parse_reader_secret(secret_str):
    """Parse --reader-secret as 'secp_privkey_hex/kyber_seed_hex'"""
    parts = secret_str.split('/')
    if len(parts) != 2:
        print("--reader-secret must be secp_privkey_hex/kyber_seed_hex", file=sys.stderr)
        exit(1)
    try:
        secp_privkey = secp256k1.PrivateKey(bytes.fromhex(parts[0]))
        kyber_seed = bytes.fromhex(parts[1])
    except Exception as e:
        print("Bad --reader-secret: {}".format(e), file=sys.stderr)
        exit(1)
    kyber_pk, kyber_sk = centurymetadata.derive_kyber_keypair(kyber_seed)
    return secp_privkey, kyber_pk, kyber_sk


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--writer-secret", help="Writer secret key (64 hex digits)")
    parser.add_argument("--reader", help="Reader public keys (secp_pubkey_hex/kyber_pubkey_hex)")
    parser.add_argument("--reader-secret", help="Reader secret keys (secp_privkey_hex/kyber_seed_hex)")
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
    reader_kyber_pubkey = None
    reader_kyber_privkey = None
    reader_id = None

    if args.reader_secret:
        reader_secp_privkey, reader_kyber_pubkey, reader_kyber_privkey = parse_reader_secret(args.reader_secret)
        reader_secp_pubkey = reader_secp_privkey.pubkey
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_kyber_pubkey)
        if not args.raw:
            print("Derived reader_id: {}".format(reader_id.hex()))
    elif args.reader:
        reader_secp_pubkey, reader_kyber_pubkey = parse_reader_public(args.reader)
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_kyber_pubkey)

    if args.decode:
        if not args.reader_secret:
            print("Decode needs --reader-secret", file=sys.stderr)
            exit(1)
        if args.decode.startswith('@'):
            decode_data = open(args.decode[1:], "rb").read()
        else:
            decode_data = bytes.fromhex(args.decode)
        ret = centurymetadata.decode(reader_secp_privkey, reader_kyber_privkey, decode_data)
        if ret is None:
            print("decode failed", file=sys.stderr)
            exit(1)
        for title, body in ret:
            print(title)
            print(body)
            print()
    elif args.encode:
        if reader_secp_pubkey is None or reader_kyber_pubkey is None:
            print("Needs --reader or --reader-secret", file=sys.stderr)
            exit(1)

        if args.writer_secret is None:
            print("Needs --writer-secret", file=sys.stderr)
            exit(1)

        writer = secp256k1.PrivateKey(bytes.fromhex(args.writer_secret))
        if not args.raw:
            print("Writer pubkey: {}".format(writer.pubkey.serialize().hex()))

        ret = centurymetadata.encode(writer, reader_secp_pubkey, reader_kyber_pubkey,
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

        depthreq = requests.get(args.server + '/api/v1/fetchdepth')
        depth = int(json.loads(depthreq.text)['depth'])

        if depth > 32:
            print("Server returned unbelievable depth {}"
                  .format(depthreq.text), file=sys.stderr)
            exit(1)

        r = requests.get(args.server + '/api/v1/fetchbundle/{}'
                         .format(reader_id.hex()[:depth]))
        if r.headers['Content-Type'] != 'application/x-centurymetadata':
            print("Server returned bad content type {}"
                  .format(r.headers['Content-Type']), file=sys.stderr)
            exit(1)
        if args.raw:
            sys.stdout.buffer.write(r.content)
        else:
            print(r.content.hex())
        exit(0)
    else:
        print("Needs --encode, --decode, --check or --fetch", file=sys.stderr)
        exit(1)
