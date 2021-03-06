#! /usr/bin/python3
import cgi
import os
import sys
import centurymetadata
from typing import Optional

TOPLEVEL = "/api/v0/"
BASEDIR = "/home/rusty/data/centurymetadata/"

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


def success(msg='Success', ctype='text/plain') -> None:
    print("Content-Type: {}\n".format(ctype))
    print(msg)
    exit(0)


def decode_key(hexkey: str) -> Optional[bytes]:
    try:
        b = bytes.fromhex(hexkey)
    except ValueError:
        return None
    if len(b) != 32:
        return None
    return b


def storage_dir(rbytes: bytes, wbytes: bytes) -> str:
    return os.path.join(BASEDIR, rbytes.hex() + "+" + wbytes.hex())


def authorize(reader: str, writer: str, authtoken: str) -> None:
    # We use a dummy authtoken for testapi
    if authtoken != '0' * 64:
        return bad_403("AUTHTOKEN must be all-zero for testapi")
    wbytes = decode_key(writer)
    rbytes = decode_key(reader)
    if wbytes is None:
        return bad_400("writer must be 32 hex bytes")
    if rbytes is None:
        return bad_400("reader must be 32 hex bytes")

    try:
        os.mkdir(storage_dir(rbytes, wbytes))
    except FileExistsError:
        bad_400("READER {} WRITER {} already authorized"
                .format(writer, reader))
    success()


def update() -> None:
    content = os.getenv("CONTENT_TYPE")
    if content != 'application/x-centurymetadata':
        return bad_400("update must be Content-Type: application/x-centurymetadata")
    bytelen = int(os.getenv("CONTENT_LENGTH"))
    b = bytes()
    while bytelen > 0:
        r = sys.stdin.buffer.read(bytelen)
        bytelen -= len(r)
        b += r
    # FIXME: Better feedback here!
    wbytes, rbytes, gen, after_pre = centurymetadata.deconstruct(b)
    if wbytes is None:
        return bad_400("Malformed x-centurymetadata")

    if not centurymetadata.check_sig(after_pre):
        return bad_400("Bad signature on x-centurymetadata")

    # OK, signature checks out.
    try:
        f = open(os.path.join(storage_dir(rbytes, wbytes), gen.to_bytes(8, "big").hex()), "xb")
    except FileExistsError:
        return bad_400("Generation {} already exists".format(gen))
    except FileNotFoundError:
        return bad_403("Writer {} reader {} not authorized; try authorize?"
                       .format(wbytes.hex(), rbytes.hex()))

    f.write(b)
    f.close()
    success()


def index() -> None:
    """FIXME: don't generate this every time, but cache it daily"""
    entries = sorted(os.listdir(BASEDIR))
    first_reader, first_writer = entries[0].split('+')
    last_reader, last_writer = entries[-1].split('+')
    success(ctype='application/json',
            msg='{{"bundles": [{{"first_reader":"{}","first_writer":"{}","last_reader":"{}","last_writer":"{}"}}]}}'.format(first_reader, first_writer, last_reader, last_writer))


def fetchbundle(reader: str, writer: str) -> None:
    """FIXME: make sure entries come from current or prev index"""
    entries = sorted(os.listdir(BASEDIR))
    print("Content-Type: application/x-centurymetadata\n")
    sys.stdout.flush()

    rbytes = bytes.fromhex(reader)
    wbytes = bytes.fromhex(writer)
    for f in entries:
        r, w = f.split('+')
        rb = bytes.fromhex(r)
        wb = bytes.fromhex(w)
        if rb < rbytes or rb == rbytes and wb < wbytes:
            continue

        gens = sorted(os.listdir(storage_dir(rb, wb)))
        # Might be authorized, but never updated, otherwise send last.
        if len(gens) != 0:
            with open(os.path.join(storage_dir(rb, wb), gens[-1]), "rb") as f:
                sys.stdout.buffer.write(f.read())

    sys.stdout.buffer.flush()


requests = {'authorize': ("POST", authorize, 3),
            'update': ("POST", update, 0),
            'index': ("GET", index, 0),
            'fetchbundle': ("GET", fetchbundle, 2)}

req = os.getenv("PATH_INFO")
reqmethod = os.getenv("REQUEST_METHOD")
if not req or not reqmethod:
    cgi.test()
    exit(1)

if not req.startswith(TOPLEVEL):
    bad_404()

reqparts = req.split('/')[3:]
if reqparts[0] not in requests:
    bad_404()

method, handler, numargs = requests[reqparts[0]]
if reqmethod != method:
    bad_405()

# In case last one is empty (i.e. ends in /):
if reqparts[-1] == '':
    reqparts = reqparts[0:-1]

if len(reqparts[1:]) != numargs:
    bad_400("Expected {} args, got {}".format(numargs, len(reqparts[1:])))

handler(*reqparts[1:])
