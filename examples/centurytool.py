#! /usr/bin/python3
import centurymetadata
import secp256k1
import argparse
import json
import requests
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--writer-secret", help="Writer secret key (64 hex digits)")
    parser.add_argument("--reader", help="Reader public key (66 hex digits)")
    parser.add_argument("--reader-secret", help="Reader secret key (64 hex digits)")
    parser.add_argument("--generation", type=int, help="Generation number", default=0)
    parser.add_argument("--raw", help="Output raw binary, suppress other output", action="store_true")
    parser.add_argument("--decode", help='hex string to decode (@ means read filename)')
    parser.add_argument("--encode", help='title body pair to encode (@ means read filename)', nargs=2, action="append", default=None)
    parser.add_argument("--check", help='check signature and print information (@ means read filename)')
    parser.add_argument("--fetch", help='fetch the record for the given reader (and optional writer)', action="store_true")
    parser.add_argument("--server", help='server to use', default='https://testapi.centurymetadata.org')
    args = parser.parse_args()

    if args.reader_secret:
        args.reader = secp256k1.PrivateKey(bytes.fromhex(args.reader_secret)).pubkey.serialize().hex()
        if not args.raw:
            print("Converted reader secret to reader pubkey {}".format(args.reader))

    if args.decode:
        if not args.reader_secret:
            print("Decode needs --reader-secret", file=sys.stderr)
            exit(1)
        if args.decode.startswith('@'):
            if args.raw:
                decode = open(args.decode[1:], "rb").read()
            else:
                decode = open(args.decode[1:], "rt").read().encode('utf8')
        else:
            if args.raw:
                decode = args.decode
            else:
                decode = bytes.fromhex(args.decode)
        reader_seckey = secp256k1.PrivateKey(bytes.fromhex(args.reader_secret))
        ret = centurymetadata.decode(reader_seckey, decode)
        if ret is None:
            print("decode failed", file=sys.stderr)
            exit(1)
        for title, body in ret:
            print(title)
            print(body)
            print()
    elif args.encode:
        if args.reader is None:
            print("Needs --reader or --reader-secret", file=sys.stderr)
            exit(1)

        if args.writer_secret is None:
            print("Needs --writer-secret", file=sys.stderr)
            exit(1)

        writer = secp256k1.PrivateKey(bytes.fromhex(args.writer_secret))
        if not args.raw:
            print("Writer pubkey: {}".format(writer.pubkey.serialize().hex()))
        reader = secp256k1.PublicKey(bytes.fromhex(args.reader), raw=True)

        ret = centurymetadata.encode(writer, reader,
                                     args.generation,
                                     *args.encode)
        if args.raw:
            sys.stdout.buffer.write(ret)
        else:
            print(ret.hex())
    elif args.check:
        if args.check.startswith('@'):
            if args.raw:
                b = open(args.check[1:], "rb").read()
            else:
                b = open(args.check[1:], "rt").read().encode('utf8')
        else:
            if args.raw:
                b = args.check
            else:
                b = bytes.fromhex(args.check)
        # Handle multiple concatenated entries
        while True:
            try:
                wkey, rkey, gen, after_pre = centurymetadata.deconstruct(b[:centurymetadata.RECORD_LENGTH])
            except ValueError as e:
                print("Malformed ({})".format(e), file=sys.stderr)
                exit(1)

            if not centurymetadata.check_sig(after_pre):
                print("Bad signature", file=sys.stderr)
                exit(1)

            if args.reader and bytes.fromhex(args.reader) != rkey.serialize():
                print("Bad reader {}".format(rkey.serialize().hex()), file=sys.stderr)
                exit(1)

            print("writer: {}".format(wkey.serialize().hex()))
            print("reader: {}".format(rkey.serialize().hex()))
            print("generation: {}".format(gen))

            b = b[centurymetadata.RECORD_LENGTH:]
            if len(b) == 0:
                break
        exit(0)
    elif args.fetch:
        if args.reader is None:
            print("Needs --reader or --reader-secret", file=sys.stderr)
            exit(1)

        r = requests.get(args.server + '/api/v0/index')
        indices = json.loads(r.text)

        reader = bytes.fromhex(args.reader)
        for a in indices['bundles']:
            rstart = bytes.fromhex(a['first_reader'])
            rend = bytes.fromhex(a['last_reader'])
            if reader >= rstart and reader <= rend:
                r = requests.get(args.server + '/api/v0/fetchbundle/{}/{}'
                                 .format(a['first_reader'], a['first_writer']))
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
