#!/usr/bin/env python3
"""Run a local centurymetadata server for manual testing.

Creates the standard directory skeleton in a fresh tmpdir (unless
--basedir is given) and serves the CGI API over plain HTTP until
interrupted.

Run from the python/ subdirectory (which has the venv and dependencies):

    cd python && uv run python ../tools/localserver.py

Add --test-mode to only allow known test identities and validate record
content, matching testapi.centurymetadata.org (see "Known Test Keys" in
README.md). Equivalently: make localserver TESTMODE=1
"""
import argparse
import shutil
import tempfile
from pathlib import Path

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
    (basedir / "00-ff" / "00-ff").mkdir(parents=True, exist_ok=True)

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
