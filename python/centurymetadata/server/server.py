#! /usr/bin/python3
import cgi
import os
import json
import sys
import centurymetadata
from secp256k1 import PublicKey
from typing import Optional, Any

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


def success(msg: str = 'Success', ctype: str = 'text/plain') -> None:
    print("Content-Type: {}\n".format(ctype))
    print(msg)
    exit(0)


def decode_key(hexkey: str) -> Optional[PublicKey]:
    try:
        k = PublicKey(bytes.fromhex(hexkey), raw=True)
    except ValueError:
        return None
    return k


def storage_dir(rkey: PublicKey, wkey: PublicKey) -> str:
    return os.path.join(BASEDIR, rkey.serialize().hex() + "+" + wkey.serialize().hex())


def authorize(reader: str, writer: str, authtoken: str) -> None:
    # We use a dummy authtoken for testapi
    if authtoken != '0' * 64:
        return bad_403("AUTHTOKEN must be all-zero for testapi")
    wkey = decode_key(writer)
    rkey = decode_key(reader)
    if wkey is None:
        return bad_400("writer must be valid compressed pubkey")
    if rkey is None:
        return bad_400("reader must be valid compressed pubkey")

    try:
        os.mkdir(storage_dir(rkey, wkey))
    except FileExistsError:
        bad_400("READER {} WRITER {} already authorized"
                .format(writer, reader))
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
    wkey, rkey, gen, after_pre = centurymetadata.deconstruct(b)

    if not centurymetadata.check_sig(after_pre):
        return bad_400("Bad signature on x-centurymetadata")

    # OK, signature checks out.
    try:
        f = open(os.path.join(storage_dir(rkey, wkey), gen.to_bytes(8, "big").hex()), "xb")
    except FileExistsError:
        return bad_400("Generation {} already exists".format(gen))
    except FileNotFoundError:
        return bad_403("Writer {} reader {} not authorized; try authorize?"
                       .format(wkey.serialize().hex(), rkey.serialize().hex()))

    f.write(b)
    f.close()
    success()


def fetchdepth() -> None:
    """Get the length of prefix we're supposed to use for fetchbundle"""
    with open(os.path.join(BASEDIR, "maxdepth"), "r") as depthf:
        maxdepth = int(depthf.read())

    success(ctype='application/json',
            msg='{"depth":' + str(maxdepth) + '}')


def fetchbundle(prefix: str) -> None:
    if any(c not in "0123456789abcdef" for c in prefix):
        return bad_400("prefix must be lowercase hex characters!")

    with open(os.path.join(BASEDIR, "maxdepth"), "r") as depthf:
        maxdepth = int(depthf.read())
    with open(os.path.join(BASEDIR, "mindepth"), "r") as depthf:
        mindepth = int(depthf.read())

    # For transitions, we allow a range, but really we expect maxdepth.
    if len(prefix) < mindepth or len(prefix) > maxdepth:
        return bad_400("prefix must be {} characters: see fetchdepth!"
                       .format(maxdepth))

    print("Content-Type: application/x-centurymetadata\n")
    sys.stdout.flush()
    entries = sorted([d for d in os.listdir(BASEDIR) if d.startswith(prefix)])

    for f in entries:
        gens = sorted(os.listdir(os.path.join(BASEDIR, f)))
        # Might be authorized, but never updated, otherwise send last.
        if len(gens) != 0:
            with open(os.path.join(BASEDIR, f, gens[-1]), "rb") as serv:
                sys.stdout.buffer.write(serv.read())

    sys.stdout.buffer.flush()


requests = {'authorize': ("POST", authorize, 3),
            'update': ("POST", update, 0),
            'fetchdepth': ("GET", fetchdepth, 0),
            'fetchbundle': ("GET", fetchbundle, 1)}

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

handler: Any
method, handler, numargs = requests[reqparts[0]]
if reqmethod != method:
    bad_405()

# In case last one is empty (i.e. ends in /):
if reqparts[-1] == '':
    reqparts = reqparts[0:-1]

if len(reqparts[1:]) != numargs:
    bad_400("Expected {} args, got {}".format(numargs, len(reqparts[1:])))

handler(*reqparts[1:])
