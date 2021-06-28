#! /usr/bin/python3
import centurymetadata
import argparse
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--writer-secret", help="Writer secret key (64 hex digits)")
    parser.add_argument("--reader", help="Reader public key (64 hex digits)")
    parser.add_argument("--reader-secret", help="Reader secret key (64 hex digits)")
    parser.add_argument("--generation", type=int, help="Generation number", default=0)
    parser.add_argument("--raw", help="Output raw binary, suppress other output", action="store_true")
    parser.add_argument("--decode", help='hex string to decode (@ means read filename)')
    parser.add_argument("--encode", help='title body pair to encode (@ means read filename)', nargs=2, action="append", default=None)
    parser.add_argument("--check", help='check signature and print information (@ means read filename)')
    args = parser.parse_args()

    if args.reader_secret:
        reader, _ = centurymetadata.compute_xonly_pubkey(bytes.fromhex(args.reader_secret))
        args.reader = reader.hex()
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
        ret = centurymetadata.decode(bytes.fromhex(args.reader_secret), decode)
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

        writer, _ = centurymetadata.compute_xonly_pubkey(bytes.fromhex(args.writer_secret))
        if not args.raw:
            print("Writer pubkey: {}".format(writer.hex()))

        ret = centurymetadata.encode(bytes.fromhex(args.writer_secret),
                                     bytes.fromhex(args.reader),
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
        wbytes, rbytes, gen, after_pre = centurymetadata.deconstruct(b)
        if wbytes is None:
            print("Malformed", file=sys.stderr)
            exit(1)

        if not centurymetadata.check_sig(after_pre):
            print("Bad signature", file=sys.stderr)
            exit(1)

        if args.reader and bytes.fromhex(args.reader) != rbytes:
            print("Bad reader {}".format(rbytes.hex()), file=sys.stderr)
            exit(1)

        print("writer: {}".format(wbytes.hex()))
        print("reader: {}".format(rbytes.hex()))
        print("generation: {}".format(gen))
        exit(0)
    else:
        print("Needs --encode, --decode or --check", file=sys.stderr)
        exit(1)
