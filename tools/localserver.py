#!/usr/bin/env python3
"""Run a local centurymetadata server for manual testing.

Populates a fresh basedir with the same generated test vectors used by
the test server at testapi.centurymetadata.org (see
tools/gen_test_vectors.py and "Known Test Keys" in README.md) -- unless
--basedir points at a directory already populated by a previous run, in
which case its existing contents are served as-is -- and serves the CGI
API over plain HTTP until interrupted.

Run from the python/ subdirectory (which has the venv and dependencies):

    cd python && uv run python ../tools/localserver.py

Add --test-mode to only allow known test identities and validate record
content, matching testapi.centurymetadata.org. Equivalently: make
localserver TESTMODE=1
"""
import argparse
import shutil
import sys
import tempfile
from pathlib import Path

import gen_test_vectors
from centurymetadata.server.devserver import CenturyHTTPServer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8199)
    parser.add_argument("--basedir", type=Path, default=None,
                        help="Storage directory (default: a fresh tmpdir, removed on exit)")
    parser.add_argument("--test-mode", action="store_true",
                        help="Only allow known test identities, matching testapi.centurymetadata.org")
    args = parser.parse_args()

    basedir = args.basedir or Path(tempfile.mkdtemp(prefix="centurymetadata-"))
    skeleton = basedir / gen_test_vectors.SKELETON_DIR / gen_test_vectors.SKELETON_BUNDLE
    if skeleton.exists():
        print(f"Reusing existing test vectors in {basedir}", file=sys.stderr)
    else:
        vs = gen_test_vectors.generate(basedir)
        print(f"Populated {basedir} with {len(vs.manifest)} generated test vectors", file=sys.stderr)

    extra_env = {"CENTURYMETADATA_TEST_MODE": "1"} if args.test_mode else {}
    httpd = CenturyHTTPServer(basedir, args.host, args.port, extra_env=extra_env)
    port = httpd.server_address[1]
    print(f"Serving centurymetadata API on http://{args.host}:{port}/api/v1/ (basedir={basedir})")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if args.basedir is None:
            shutil.rmtree(basedir, ignore_errors=True)


if __name__ == "__main__":
    main()
