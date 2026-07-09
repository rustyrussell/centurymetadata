"""In-process HTTP wrapper around server.py's CGI script.

server.py speaks CGI (env vars in, headers+body on stdout), which is
what the production deployment (Apache/cgi-bin) provides. This module
fronts it with a plain http.server so it can be driven with normal
HTTP requests, both for tests and for local manual testing
(tools/localserver.py).
"""
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, Tuple

SERVER_PY = Path(__file__).parent / 'server.py'


def call_server(basedir: Path, method: str, path: str,
                body: bytes = b'', content_type: str = '',
                extra_env: Dict[str, str] = {}) -> Tuple[int, Dict[str, str], bytes]:
    """Invoke server.py as a CGI subprocess and return (status, headers, body)."""
    env = os.environ.copy()
    env['REQUEST_METHOD'] = method
    env['PATH_INFO'] = path
    env['CENTURYMETADATA_BASEDIR'] = str(basedir)
    if body:
        env['CONTENT_LENGTH'] = str(len(body))
    if content_type:
        env['CONTENT_TYPE'] = content_type
    env.update(extra_env)

    result = subprocess.run(
        [sys.executable, str(SERVER_PY)],
        input=body,
        capture_output=True,
        env=env
    )

    if result.returncode != 0:
        raise RuntimeError(f"Server subprocess failed (rc={result.returncode}):\n"
                           f"{result.stderr.decode(errors='replace')}")

    stdout = result.stdout
    header_part, resp_body = stdout.split(b'\n\n', 1) if b'\n\n' in stdout else (stdout, b'')

    status = 200
    headers: Dict[str, str] = {}
    for line in header_part.decode('utf-8', errors='replace').split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('Status:'):
            status = int(line.split()[1])
        elif ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()

    return status, headers, resp_body


class _CenturyHandler(BaseHTTPRequestHandler):
    """Thin HTTP wrapper that delegates each request to server.py as a subprocess."""

    server: 'CenturyHTTPServer'

    def do_GET(self) -> None:
        self._dispatch(b'')

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', 0))
        self._dispatch(self.rfile.read(length))

    def _dispatch(self, body: bytes) -> None:
        content_type = self.headers.get('Content-Type', '')
        status, headers, resp_body = call_server(
            self.server.basedir, self.command, self.path, body, content_type,
            extra_env=self.server.extra_env
        )
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, *args: object) -> None:
        pass  # suppress output during tests


class CenturyHTTPServer(HTTPServer):
    def __init__(self, basedir: Path, host: str = 'localhost', port: int = 0,
                 extra_env: Dict[str, str] = {}) -> None:
        self.basedir = basedir
        self.extra_env = extra_env
        super().__init__((host, port), _CenturyHandler)
