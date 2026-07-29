#! /usr/bin/python3
import centurymetadata
from centurymetadata.bip39 import bip39_to_seed, derive_cm_keys
import secp256k1
import argparse
import json
import requests
import sys
from typing import Optional


# ── Fetch helper ─────────────────────────────────────────────────────────────

def fetch_slot(server: str, reader_id: bytes):
    """XOR-PIR fetch. Returns the raw DATA_LENGTH slot bytes, or None if not found."""
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
    slot_size = centurymetadata.DATA_LENGTH
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


def identity_for_slot(seed: bytes, n: int) -> centurymetadata.Identity:
    """Derive the full Identity (writer + reader keys) for bip39 derivation slot n."""
    w_secp_bytes, r_secp_bytes, w_mlkem_seed, r_mlkem_seed = derive_cm_keys(seed, n)
    writer_privkey = secp256k1.PrivateKey(w_secp_bytes)
    reader_secp_privkey = secp256k1.PrivateKey(r_secp_bytes)
    reader_mlkem_pubkey, reader_mlkem_privkey = centurymetadata.derive_mlkem_keypair(r_mlkem_seed)
    return centurymetadata.Identity(writer_privkey, reader_secp_privkey, reader_mlkem_pubkey, reader_mlkem_privkey)


def load_chain(server: str, seed: bytes, start_n: int, start_raw: bytes) -> centurymetadata.CenturyMetadata:
    """Load derivation slot start_n (already-fetched start_raw), then keep
    following `next cmdata derivation path` records, fetching and loading
    each subsequent slot, for as long as the bip39 seed can derive its
    identity."""
    doc = centurymetadata.CenturyMetadata()
    n: Optional[int] = start_n
    raw = start_raw
    while n is not None:
        identity = identity_for_slot(seed, n)
        try:
            _wkey, _reader_id, gen, _after = centurymetadata.deconstruct(raw)
            print("slot {} generation: {}".format(n, gen), file=sys.stderr)
        except ValueError:
            pass
        errors, next_n = doc.load(identity, n, raw)
        for e in errors:
            print("WARNING: partial decode of slot {} due to record {}: {}".format(
                n, e.record_index, e), file=sys.stderr)
        if any(e.fatal for e in errors):
            print("decode of slot {} failed".format(n), file=sys.stderr)
            break
        if next_n is None:
            break
        next_slot = fetch_slot(server, identity_for_slot(seed, next_n).reader_id)
        if next_slot is None:
            print("Chain continues to slot {} but it could not be fetched".format(next_n), file=sys.stderr)
            break
        n = next_n
        raw = centurymetadata.preamble + next_slot
    return doc


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
        identity0 = identity_for_slot(seed, args.slot)

        writer_privkey = identity0.writer_privkey
        reader_secp_privkey = identity0.reader_secp_privkey
        reader_secp_pubkey = identity0.reader_secp_pubkey
        reader_mlkem_pubkey = identity0.reader_mlkem_pubkey
        reader_mlkem_privkey = identity0.reader_mlkem_privkey
        reader_id = identity0.reader_id
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

    # Default is fetch and decode
    if not args.decode and not args.encode and not args.check and not args.fetch:
        fetch = True
        decode = True
    else:
        fetch = args.fetch
        decode = args.decode

    if fetch:
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

    if decode:
        if reader_secp_privkey is None or reader_mlkem_privkey is None:
            print("Decode needs --reader-secret or --bip39", file=sys.stderr)
            exit(1)
        if fetch and args.bip39:
            # Uses the higher-level CenturyMetadata class: since --bip39
            # derives a full Identity (including the writer key) for any
            # slot, it can follow `next cmdata derivation path` records
            # across the chain, not just decode the one fetched slot.
            doc = load_chain(args.server, seed, args.slot, record)
            for rec in doc.records:
                print(rec.rtype)
                print(rec.name)
                print(rec.contents)
                print()
        else:
            if fetch:
                decode_data = record
                if not args.raw:
                    import struct
                    gen = struct.unpack('>Q', slot[64 + 33 + 32:64 + 33 + 32 + 8])[0]
                    print("generation: {}".format(gen))
            elif args.decode.startswith('@'):
                decode_data = open(args.decode[1:], "rb").read()
            else:
                decode_data = bytes.fromhex(args.decode)
            # Prepend preamble if not already present (slot-only input)
            if not decode_data.startswith(centurymetadata.preamble):
                decode_data = centurymetadata.preamble + decode_data
            # The reader's own writer pubkey (for "to-self" detection), if known.
            own_writer_pubkey = writer_privkey.pubkey if writer_privkey is not None else reader_secp_pubkey
            errors, ret = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey, reader_mlkem_pubkey,
                                                 own_writer_pubkey, decode_data)
            if any(e.fatal for e in errors):
                for e in errors:
                    print(f"decode failed: {e}", file=sys.stderr)
                exit(1)
            for e in errors:
                print(f"WARNING: partial decode due to record {e.record_index}: {e}", file=sys.stderr)
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
