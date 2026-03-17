#! /usr/bin/python3
import cgi
import json
import os
import sys
import centurymetadata
from secp256k1 import PublicKey
from typing import Optional, Tuple, Any

TOPLEVEL = "/api/v1/"
BASEDIR = "/home/rusty/data/centurymetadata/v1"

# Directory layout under BASEDIR:
#
#   <dirmin>-<dirmax>/            <- directory: groups ~1024 bundles, named by
#     <bmin>-<bmax>/              <-   min-max reader_id hex prefix of contents
#       <reader_id>+<writer>/     <- record dir (empty = authorized, not yet written)
#         <gen_hex>               <- record file (8192-byte binary, no preamble stored
#     <bmin>-<bmax>.old/          <-   but full record written; preamble stripped on
#     ...                         <-   bundle assembly).  .old dirs are left after a
#   <dirmin>-<dirmax>/            <-   bundle split for ~1hr to serve in-flight queries.
#   ...
#
# setup.sh creates the initial skeleton: one directory (00-ff) with one bundle (00-ff).
# Records are routed to the bundle whose min-prefix <= reader_id (rightmost match).
# Bundle splitting (when a bundle exceeds ~1024 records) is not yet implemented.


def bad_404() -> None:
    print('Status: 404\n\n<html><head></head><body>Invalid URL, see <a href="https://github.com/rustyrussell/centurymetadata/tree/master/examples/EXAMPLES.md">EXAMPLES.md</a></body></html>')
    exit(0)


def bad_405() -> None:
    print("Status: 405\n\nMethod Not Allowed")
    exit(0)


def bad_400(extra: str) -> None:
    print("Status: 400\n\nBad Request ({})".format(extra))
    exit(0)


def bad_403(extra: str) -> None:
    print("Status: 403\n\nForbidden ({})".format(extra))
    exit(0)


def success(msg: str = 'Success', ctype: str = 'text/plain') -> None:
    print("Content-Type: {}\n".format(ctype))
    print(msg)
    exit(0)


def decode_id(hexid: str) -> Optional[bytes]:
    """Decode a 32-byte hex-encoded READER_ID"""
    try:
        b = bytes.fromhex(hexid)
    except ValueError:
        return None
    if len(b) != 32:
        return None
    return b


def decode_key(hexkey: str) -> Optional[PublicKey]:
    try:
        k = PublicKey(bytes.fromhex(hexkey), raw=True)
    except ValueError:
        return None
    return k


def is_range_name(name: str) -> bool:
    """Check if name looks like a bundle/directory range: hexmin-hexmax"""
    if name.endswith('.old'):
        return False
    parts = name.split('-')
    if len(parts) != 2:
        return False
    return all(c in '0123456789abcdef' for c in parts[0] + parts[1])


def find_dir_and_bundle(reader_id: bytes) -> Optional[Tuple[str, str]]:
    """Find the (directory, bundle) for a given reader_id.

    Directories and bundles are sorted by their min prefix; we find the
    rightmost dir/bundle whose min prefix <= reader_id.
    """
    rid_hex = reader_id.hex()

    dirs = sorted([d for d in os.listdir(BASEDIR)
                   if os.path.isdir(os.path.join(BASEDIR, d)) and is_range_name(d)])
    if not dirs:
        return None

    dir_name = dirs[0]
    for d in dirs:
        dmin = d.split('-')[0]
        if rid_hex[:len(dmin)] >= dmin:
            dir_name = d

    dir_path = os.path.join(BASEDIR, dir_name)
    bundles = sorted([b for b in os.listdir(dir_path)
                      if os.path.isdir(os.path.join(dir_path, b)) and is_range_name(b)])
    if not bundles:
        return None

    bundle_name = bundles[0]
    for b in bundles:
        bmin = b.split('-')[0]
        if rid_hex[:len(bmin)] >= bmin:
            bundle_name = b

    return dir_name, bundle_name


def storage_dir(reader_id: bytes, wkey: PublicKey) -> Optional[str]:
    location = find_dir_and_bundle(reader_id)
    if location is None:
        return None
    dir_name, bundle_name = location
    return os.path.join(BASEDIR, dir_name, bundle_name,
                        reader_id.hex() + "+" + wkey.serialize().hex())


def authorize(reader: str, writer: str, authtoken: str) -> None:
    # We use a dummy authtoken for testapi
    if authtoken != '0' * 64:
        return bad_403("AUTHTOKEN must be all-zero for testapi")
    reader_id = decode_id(reader)
    wkey = decode_key(writer)
    if reader_id is None:
        return bad_400("reader must be a 64-character hex READER_ID")
    if wkey is None:
        return bad_400("writer must be a valid compressed secp256k1 pubkey")

    sdir = storage_dir(reader_id, wkey)
    if sdir is None:
        return bad_403("Server not configured: no bundles found")

    try:
        os.mkdir(sdir)
    except FileExistsError:
        bad_400("READER_ID {} WRITER {} already authorized"
                .format(reader, writer))
    success()


def update() -> None:
    content = os.getenv("CONTENT_TYPE")
    if content != 'application/x-centurymetadata':
        return bad_400("update must be Content-Type: application/x-centurymetadata")
    bytelen = int(os.getenv("CONTENT_LENGTH") or 0)
    b = bytes()
    while bytelen > 0:
        r = sys.stdin.buffer.read(bytelen)
        bytelen -= len(r)
        b += r
    wkey, reader_id, gen, after_pre = centurymetadata.deconstruct(b)

    if not centurymetadata.check_sig(after_pre):
        return bad_400("Bad signature on x-centurymetadata")

    sdir = storage_dir(reader_id, wkey)
    if sdir is None:
        return bad_403("Server not configured: no bundles found")

    try:
        f = open(os.path.join(sdir, gen.to_bytes(8, "big").hex()), "xb")
    except FileExistsError:
        return bad_400("Generation {} already exists".format(gen))
    except FileNotFoundError:
        return bad_403("Writer {} reader_id {} not authorized; try authorize?"
                       .format(wkey.serialize().hex(), reader_id.hex()))

    f.write(b)
    f.close()
    success()


def listbundles() -> None:
    result = []
    dirs = sorted([d for d in os.listdir(BASEDIR)
                   if os.path.isdir(os.path.join(BASEDIR, d)) and is_range_name(d)])
    for dir_name in dirs:
        dir_path = os.path.join(BASEDIR, dir_name)
        bundles = sorted([b for b in os.listdir(dir_path)
                          if os.path.isdir(os.path.join(dir_path, b)) and is_range_name(b)])
        for idx, bundle_name in enumerate(bundles):
            result.append({"directory": dir_name, "bundle": bundle_name, "index": idx})
    success(ctype='application/json', msg=json.dumps(result))


def assemble_bundle(bundle_path: str) -> bytes:
    """Pack records from a bundle dir into 1024 × FULL_LENGTH bytes, sorted by
    reader_id, with empty slots zero-padded.  Preamble is stripped from each record."""
    entries = sorted([e for e in os.listdir(bundle_path)
                      if os.path.isdir(os.path.join(bundle_path, e)) and '+' in e])

    result = bytearray(1024 * centurymetadata.FULL_LENGTH)
    preamble_len = len(centurymetadata.preamble)

    for i, entry in enumerate(entries[:1024]):
        entry_path = os.path.join(bundle_path, entry)
        gens = sorted(os.listdir(entry_path))
        if not gens:
            continue
        with open(os.path.join(entry_path, gens[-1]), 'rb') as f:
            data = f.read()
        if data[:preamble_len] == centurymetadata.preamble:
            data = data[preamble_len:]
        slot_start = i * centurymetadata.FULL_LENGTH
        result[slot_start:slot_start + centurymetadata.FULL_LENGTH] = data[:centurymetadata.FULL_LENGTH]

    return bytes(result)


def xor_into(result: bytearray, data: bytes) -> None:
    """XOR data into result in-place using big-integer arithmetic."""
    n = len(result)
    xored = (int.from_bytes(result, 'little') ^ int.from_bytes(data, 'little')).to_bytes(n, 'little')
    result[:] = xored


def fetchxor(directory: str) -> None:
    if not all(c in '0123456789abcdef-' for c in directory):
        return bad_400("directory must be lowercase hex with -")

    dir_path = os.path.join(BASEDIR, directory)
    if not os.path.isdir(dir_path):
        old_path = dir_path + '.old'
        if os.path.isdir(old_path):
            dir_path = old_path
        else:
            return bad_404()

    bitmask = sys.stdin.buffer.read(128)
    if len(bitmask) != 128:
        return bad_400("bitmask must be exactly 128 bytes")

    bundles = sorted([b for b in os.listdir(dir_path)
                      if os.path.isdir(os.path.join(dir_path, b)) and is_range_name(b)])

    result = bytearray(1024 * centurymetadata.FULL_LENGTH)

    for idx, bundle_name in enumerate(bundles):
        if idx >= 1024:
            break
        if not (bitmask[idx // 8] & (1 << (idx % 8))):
            continue
        bundle_data = assemble_bundle(os.path.join(dir_path, bundle_name))
        xor_into(result, bundle_data)

    print("Content-Type: application/x-centurymetadata\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(bytes(result))
    sys.stdout.buffer.flush()


handlers: Any = {'authorize': ("POST", authorize, 3),
                 'update': ("POST", update, 0),
                 'listbundles': ("GET", listbundles, 0),
                 'fetchxor': ("POST", fetchxor, 1)}

req = os.getenv("PATH_INFO")
reqmethod = os.getenv("REQUEST_METHOD")
if not req or not reqmethod:
    cgi.test()
    exit(1)

if not req.startswith(TOPLEVEL):
    bad_404()

reqparts = req.split('/')[3:]
if reqparts[0] not in handlers:
    bad_404()

method, handler, numargs = handlers[reqparts[0]]
if reqmethod != method:
    bad_405()

# In case last one is empty (i.e. ends in /):
if reqparts[-1] == '':
    reqparts = reqparts[0:-1]

if len(reqparts[1:]) != numargs:
    bad_400("Expected {} args, got {}".format(numargs, len(reqparts[1:])))

handler(*reqparts[1:])
