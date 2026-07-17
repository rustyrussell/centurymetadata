#! /usr/bin/python3
import json
import os
import shutil
import sys
import centurymetadata
from secp256k1 import PublicKey
from typing import Optional, Tuple, Any

TOPLEVEL = "/api/v1/"
BASEDIR = os.getenv("CENTURYMETADATA_BASEDIR", "/var/lib/centurymetadata/v1")
SPLIT_THRESHOLD = int(os.getenv("CENTURYMETADATA_SPLIT_THRESHOLD", "1024"))
TEST_MODE = os.getenv("CENTURYMETADATA_TEST_MODE") == "1"

# For testing, make files group-writable
os.umask(0o002)

# Directory layout under BASEDIR:
#
#   <dirmin>-<dirmax>/            <- directory: groups ~1024 bundles, named by
#     <bmin>-<bmax>/              <-   min-max reader_id hex prefix of contents
#       <reader_id>+<writer>/     <- record dir (empty = authorized, not yet written)
#         <gen_hex>               <- record file: exactly FULL_LENGTH bytes,
#     <bmin>-<bmax>.old/          <-   preamble stripped and verified on upload.
#     ...                         <- .old dirs kept ~1hr after a split for in-flight
#   <dirmin>-<dirmax>/            <-   fetchxor queries, then cleaned up.
#   ...
#
# setup.sh creates the initial skeleton: one directory (00-ff) with one bundle (00-ff).
# Records are routed to the bundle whose min-prefix <= reader_id (rightmost match).
# When a bundle exceeds SPLIT_THRESHOLD records it is split into two halves; when a
# directory exceeds SPLIT_THRESHOLD bundles it is likewise split.


def bad_404() -> None:
    print('Status: 404\nContent-Type: text/html\n\n<html><head></head><body>Invalid URL, see <a href="https://github.com/rustyrussell/centurymetadata/tree/master/examples/EXAMPLES.md">EXAMPLES.md</a></body></html>')
    exit(0)


def bad_405() -> None:
    print("Status: 405\nContent-Type: text/plain\n\nMethod Not Allowed")
    exit(0)


def bad_400(extra: str) -> None:
    print("Status: 400\nContent-Type: text/plain\n\nBad Request ({})".format(extra))
    exit(0)


def bad_409(extra: str) -> None:
    print("Status: 409\nContent-Type: text/plain\n\nConflict ({})".format(extra))
    exit(0)


def bad_403(extra: str) -> None:
    print("Status: 403\nContent-Type: text/plain\n\nForbidden ({})".format(extra))
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


def minimal_prefix_len(a: str, b: str) -> int:
    """Shortest L such that a[:L] != b[:L]."""
    for L in range(1, min(len(a), len(b)) + 1):
        if a[:L] != b[:L]:
            return L
    return min(len(a), len(b))


def split_bundle(dir_path: str, bundle_name_str: str) -> None:
    """Split an overfull bundle into two halves sorted by reader_id.

    Copies records to two new bundle directories named by the minimal
    distinct hex prefix of their min/max reader_ids, then renames the
    old bundle directory to <name>.old.
    """
    bundle_path = os.path.join(dir_path, bundle_name_str)
    entries = sorted([e for e in os.listdir(bundle_path)
                      if os.path.isdir(os.path.join(bundle_path, e)) and '+' in e])
    if len(entries) < 2:
        return

    mid = len(entries) // 2
    half1, half2 = entries[:mid], entries[mid:]

    rid1_min = half1[0].split('+')[0]
    rid1_max = half1[-1].split('+')[0]
    rid2_min = half2[0].split('+')[0]
    rid2_max = half2[-1].split('+')[0]

    L = minimal_prefix_len(rid1_max, rid2_min)
    name1 = '{}-{}'.format(rid1_min[:L], rid1_max[:L])
    name2 = '{}-{}'.format(rid2_min[:L], rid2_max[:L])
    path1 = os.path.join(dir_path, name1)
    path2 = os.path.join(dir_path, name2)

    os.mkdir(path1)
    for entry in half1:
        shutil.copytree(os.path.join(bundle_path, entry), os.path.join(path1, entry))

    os.mkdir(path2)
    for entry in half2:
        shutil.copytree(os.path.join(bundle_path, entry), os.path.join(path2, entry))

    os.rename(bundle_path, bundle_path + '.old')


def split_directory(dir_name: str) -> None:
    """Split an overfull directory into two halves sorted by bundle name.

    Copies bundles to two new directories, then renames the old directory
    to <name>.old.
    """
    dir_path = os.path.join(BASEDIR, dir_name)
    bundles = sorted([b for b in os.listdir(dir_path)
                      if os.path.isdir(os.path.join(dir_path, b)) and is_range_name(b)])
    if len(bundles) < 2:
        return

    mid = len(bundles) // 2
    half1, half2 = bundles[:mid], bundles[mid:]

    dir1_min = half1[0].split('-')[0]
    dir1_max = half1[-1].split('-')[1]
    dir2_min = half2[0].split('-')[0]
    dir2_max = half2[-1].split('-')[1]

    # Pad to full reader_id length for boundary comparison
    L = minimal_prefix_len(dir1_max.ljust(64, 'f'), dir2_min.ljust(64, '0'))
    name1 = '{}-{}'.format(dir1_min[:L], dir1_max[:L])
    name2 = '{}-{}'.format(dir2_min[:L], dir2_max[:L])
    path1 = os.path.join(BASEDIR, name1)
    path2 = os.path.join(BASEDIR, name2)

    os.mkdir(path1)
    for bundle in half1:
        shutil.copytree(os.path.join(dir_path, bundle), os.path.join(path1, bundle))

    os.mkdir(path2)
    for bundle in half2:
        shutil.copytree(os.path.join(dir_path, bundle), os.path.join(path2, bundle))

    os.rename(dir_path, dir_path + '.old')


def check_known_keys(reader_id: bytes, wkey: PublicKey) -> Optional[str]:
    """In test mode, only known reader identities may authorize/update.

    Returns an error string if the (reader, writer) pair is not allowed,
    else None.
    """
    from centurymetadata.server import known_keys

    if reader_id not in known_keys.known_reader_ids():
        return "READER_ID {} is not a known test identity".format(reader_id.hex())

    required_writer = known_keys.required_writer_pubkey(reader_id)
    if required_writer is not None and wkey.serialize() != required_writer.serialize():
        return ("WRITER {} does not match the known writer for READER_ID {}"
                .format(wkey.serialize().hex(), reader_id.hex()))
    return None


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

    if TEST_MODE:
        err = check_known_keys(reader_id, wkey)
        if err is not None:
            return bad_403(err)

    sdir = storage_dir(reader_id, wkey)
    if sdir is None:
        return bad_403("Server not configured: no bundles found")

    try:
        os.mkdir(sdir)
    except FileExistsError:
        bad_409("READER_ID {} WRITER {} already authorized"
                .format(reader, writer))
    success()


def check_content_compliance(reader_id: bytes, record: bytes) -> Optional[str]:
    """In test mode, decrypt a known reader's record and check it's compliant.

    Returns an error string if the reader is unknown or the decrypted
    contents don't comply with the record spec, else None.
    """
    from centurymetadata.server import known_keys
    from centurymetadata import validate

    privkeys = known_keys.reader_privkeys(reader_id)
    if privkeys is None:
        return "READER_ID {} is not a known test identity".format(reader_id.hex())
    reader_secp_privkey, reader_mlkem_privkey = privkeys

    triples = centurymetadata.decode(reader_secp_privkey, reader_mlkem_privkey, record)
    if triples is None:
        return "Could not decrypt record for content validation"

    return validate.validate_triples(triples)


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
    try:
        wkey, reader_id, gen, after_pre = centurymetadata.deconstruct(b)
    except ValueError as e:
        return bad_400("Malformed record: {}".format(e))

    if not centurymetadata.check_sig(after_pre):
        return bad_400("Bad signature on x-centurymetadata")

    if TEST_MODE:
        err = check_content_compliance(reader_id, b)
        if err is not None:
            return bad_400(err)

    location = find_dir_and_bundle(reader_id)
    if location is None:
        return bad_403("Server not configured: no bundles found")
    dir_name, bundle_name = location

    sdir = os.path.join(BASEDIR, dir_name, bundle_name,
                        reader_id.hex() + "+" + wkey.serialize().hex())

    try:
        # Deliberately big-endian here, unlike the wire GEN[8] field (see
        # SPECIFICATION.md): this filename only exists so pack_bundle()
        # can find the latest generation via sorted(os.listdir(...))[-1],
        # which needs lexicographic order to match numeric order.
        f = open(os.path.join(sdir, gen.to_bytes(8, "big").hex()), "xb")
    except FileExistsError:
        return bad_400("Generation {} already exists".format(gen))
    except FileNotFoundError:
        return bad_403("Writer {} reader_id {} not authorized; try authorize?"
                       .format(wkey.serialize().hex(), reader_id.hex()))

    # Store only the binary part (preamble already verified by deconstruct)
    f.write(after_pre)
    f.close()

    # Split bundle if it exceeds the threshold
    dir_path = os.path.join(BASEDIR, dir_name)
    bundle_path = os.path.join(dir_path, bundle_name)
    bundle_entries = [e for e in os.listdir(bundle_path)
                      if os.path.isdir(os.path.join(bundle_path, e)) and '+' in e]
    if len(bundle_entries) > SPLIT_THRESHOLD:
        split_bundle(dir_path, bundle_name)
        live_bundles = [b for b in os.listdir(dir_path) if is_range_name(b)]
        if len(live_bundles) > SPLIT_THRESHOLD:
            split_directory(dir_name)

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
    reader_id, with empty slots zero-padded.  Each record file is exactly
    FULL_LENGTH bytes (preamble already stripped on upload)."""
    entries = sorted([e for e in os.listdir(bundle_path)
                      if os.path.isdir(os.path.join(bundle_path, e)) and '+' in e])

    result = bytearray(1024 * centurymetadata.FULL_LENGTH)

    for i, entry in enumerate(entries[:1024]):
        entry_path = os.path.join(bundle_path, entry)
        gens = sorted(os.listdir(entry_path))
        if not gens:
            continue
        with open(os.path.join(entry_path, gens[-1]), 'rb') as f:
            data = f.read()
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
    print("Status: 400\n\nNot a CGI environment (PATH_INFO/REQUEST_METHOD not set)")
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
