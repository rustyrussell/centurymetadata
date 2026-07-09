#! /usr/bin/python3
import centurymetadata
from centurymetadata.bip39 import bip39_to_seed, derive_cm_keys
import secp256k1
import argparse
import json
import requests
import sys


# ── Fetch helper ─────────────────────────────────────────────────────────────

def fetch_slot(server: str, reader_id: bytes):
    """XOR-PIR fetch. Returns the raw FULL_LENGTH slot bytes, or None if not found."""
    listreq = requests.get(server + '/api/v1/listbundles')
    if listreq.status_code != 200:
        print("listbundles failed: {}".format(listreq.status_code), file=sys.stderr)
        return None
    bundle_list = json.loads(listreq.text)

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
        return None

    bitmask = bytearray(128)
    bitmask[target_idx // 8] |= (1 << (target_idx % 8))

    r = requests.post(server + '/api/v1/fetchxor/{}'.format(target_dir),
                      data=bytes(bitmask),
                      headers={'Content-Type': 'application/octet-stream'})
    if r.status_code != 200:
        print("fetchxor failed: {}".format(r.status_code), file=sys.stderr)
        return None

    bundle = r.content
    slot_size = centurymetadata.FULL_LENGTH
    reader_id_offset = 64 + 33  # after SIG[64] and WRITER_PUBKEY[33]
    for i in range(len(bundle) // slot_size):
        slot = bundle[i * slot_size:(i + 1) * slot_size]
        if slot[reader_id_offset:reader_id_offset + 32] == reader_id:
            return slot

    return None


# ── Argument parsing helpers ──────────────────────────────────────────────────

def parse_reader_public(reader_str: str) -> tuple:
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


def parse_reader_secret(secret_str: str) -> tuple:
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
    parser = argparse.ArgumentParser(
        description="centurymetadata tool — default action is fetch+decode when reader keys are available")
    parser.add_argument("--bip39", metavar="MNEMONIC",
                        help="Derive all keys from a BIP39 mnemonic (12/24 words)")
    parser.add_argument("--passphrase", default="",
                        help="BIP39 passphrase (default: empty)")
    parser.add_argument("--slot", type=int, default=0,
                        help="CenturyMetadata slot N (default: 0)")
    parser.add_argument("--writer-secret", help="Writer secret key (64 hex digits)")
    parser.add_argument("--reader", help="Reader public keys (secp_pubkey_hex/mlkem_pubkey_hex)")
    parser.add_argument("--reader-secret", help="Reader secret keys (secp_privkey_hex/mlkem_seed_hex)")
    parser.add_argument("--generation", type=int, help="Generation number", default=0)
    parser.add_argument("--raw", help="Output raw binary, suppress other output", action="store_true")
    parser.add_argument("--decode", help='hex string to decode (@ means read raw binary filename)')
    parser.add_argument("--encode", help='type name body triple to encode (@ means read filename)',
                        nargs=3, action="append", default=None)
    parser.add_argument("--check", help='check signature and print information (@ means read raw binary filename)')
    parser.add_argument("--fetch", help='fetch the record for the given reader (outputs raw/hex)',
                        action="store_true")
    parser.add_argument("--server", help='server to use', default='https://testapi.centurymetadata.org')
    args = parser.parse_args()

    # ── Derive reader/writer keys ─────────────────────────────────────────────

    reader_secp_privkey = None
    reader_secp_pubkey = None
    reader_mlkem_pubkey = None
    reader_mlkem_privkey = None
    reader_id = None
    writer_privkey = None  # secp256k1.PrivateKey, if available

    if args.bip39:
        seed = bip39_to_seed(args.bip39, args.passphrase)
        w_secp_bytes, r_secp_bytes, w_mlkem_seed, r_mlkem_seed = derive_cm_keys(seed, args.slot)

        writer_privkey = secp256k1.PrivateKey(w_secp_bytes)
        reader_secp_privkey = secp256k1.PrivateKey(r_secp_bytes)
        reader_secp_pubkey = reader_secp_privkey.pubkey
        reader_mlkem_pubkey, reader_mlkem_privkey = centurymetadata.derive_mlkem_keypair(r_mlkem_seed)
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)
        print("reader_id: {}".format(reader_id.hex()), file=sys.stderr)

    if args.reader_secret:
        reader_secp_privkey, reader_mlkem_pubkey, reader_mlkem_privkey = parse_reader_secret(args.reader_secret)
        reader_secp_pubkey = reader_secp_privkey.pubkey
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)
        print("Derived reader_id: {}".format(reader_id.hex()), file=sys.stderr)
    elif args.reader:
        reader_secp_pubkey, reader_mlkem_pubkey = parse_reader_public(args.reader)
        reader_id = centurymetadata.get_reader_id(reader_secp_pubkey, reader_mlkem_pubkey)

    # Explicit --writer-secret overrides bip39-derived writer key
    if args.writer_secret:
        writer_privkey = secp256k1.PrivateKey(bytes.fromhex(args.writer_secret))

    # ── Actions ───────────────────────────────────────────────────────────────

    if args.decode:
        if reader_secp_privkey is None or reader_mlkem_privkey is None:
            print("Decode needs --reader-secret or --bip39", file=sys.stderr)
            exit(1)
        if args.decode.startswith('@'):
            decode_data = open(args.decode[1:], "rb").read()
        else:
            decode_data = bytes.fromhex(args.decode)
        # Prepend preamble if not already present (slot-only input)
        if not decode_data.startswith(centurymetadata.preamble):
            decode_data = centurymetadata.preamble + decode_data
        ret = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey, decode_data)
        if ret is None:
            print("decode failed", file=sys.stderr)
            exit(1)
        for rtype, name, body in ret:
            print(rtype)
            print(name)
            print(body)
            print()

    elif args.encode:
        if reader_secp_pubkey is None or reader_mlkem_pubkey is None:
            print("Needs --reader, --reader-secret, or --bip39", file=sys.stderr)
            exit(1)
        if writer_privkey is None:
            print("Needs --writer-secret or --bip39", file=sys.stderr)
            exit(1)
        print("Writer pubkey: {}".format(writer_privkey.pubkey.serialize().hex()), file=sys.stderr)
        ret = centurymetadata.encode(writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey,
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
            print("Needs --reader, --reader-secret, or --bip39", file=sys.stderr)
            exit(1)
        slot = fetch_slot(args.server, reader_id)
        if slot is None:
            print("Record not found", file=sys.stderr)
            exit(1)
        record = centurymetadata.preamble + slot
        if args.raw:
            sys.stdout.buffer.write(record)
        else:
            print(record.hex())

    else:
        # Default: fetch and decode (requires reader secret keys)
        if reader_id is None or reader_secp_privkey is None or reader_mlkem_privkey is None:
            print("Provide --bip39 (or --reader-secret) to fetch and decode your record,\n"
                  "or use --encode / --decode / --check / --fetch for other operations.",
                  file=sys.stderr)
            exit(1)

        slot = fetch_slot(args.server, reader_id)
        if slot is None:
            print("No record found for this reader_id", file=sys.stderr)
            exit(1)

        # Extract generation from slot: SIG[64] | WRITER[33] | READER_ID[32] | GEN[8]
        import struct
        gen = struct.unpack('>Q', slot[64 + 33 + 32:64 + 33 + 32 + 8])[0]
        if not args.raw:
            print("generation: {}".format(gen))

        ret = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey,
                                     centurymetadata.preamble + slot)
        if ret is None:
            print("decode failed", file=sys.stderr)
            exit(1)
        for rtype, name, body in ret:
            print("{}:".format(rtype))
            print(name)
            print(body)
            print()
