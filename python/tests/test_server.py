#! /usr/bin/env python3
"""Integration tests for the centurymetadata server and centurytool."""
import json
import os
import random
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, Generator, Set, Tuple

import pytest
from secp256k1 import PrivateKey

import centurymetadata

SERVER_PY = Path(__file__).parent.parent / 'centurymetadata' / 'server' / 'server.py'
TOOL_PY = Path(__file__).parent.parent.parent / 'examples' / 'centurytool.py'


# ── CGI subprocess helper ─────────────────────────────────────────────────────

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


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def basedir(tmp_path: Path) -> Path:
    (tmp_path / '00-ff' / '00-ff').mkdir(parents=True)
    return tmp_path


@pytest.fixture()
def keys() -> Dict:
    writer_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_secp_privkey = PrivateKey(bytes([random.choice(range(256)) for _ in range(32)]))
    reader_mlkem_seed = bytes([random.choice(range(256)) for _ in range(32)])
    reader_mlkem_pk, reader_mlkem_sk = centurymetadata.derive_mlkem_keypair(reader_mlkem_seed)
    reader_id = centurymetadata.get_reader_id(reader_secp_privkey.pubkey, reader_mlkem_pk)
    return {
        'writer': writer_privkey,
        'reader_secp': reader_secp_privkey,
        'reader_mlkem_pk': reader_mlkem_pk,
        'reader_mlkem_sk': reader_mlkem_sk,
        'reader_id': reader_id,
    }


class _CenturyHandler(BaseHTTPRequestHandler):
    """Thin HTTP wrapper that delegates each request to server.py as a subprocess."""

    server: '_CenturyHTTPServer'

    def do_GET(self) -> None:
        self._dispatch(b'')

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', 0))
        self._dispatch(self.rfile.read(length))

    def _dispatch(self, body: bytes) -> None:
        content_type = self.headers.get('Content-Type', '')
        status, headers, resp_body = call_server(
            self.server.basedir, self.command, self.path, body, content_type
        )
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, *args: object) -> None:
        pass  # suppress output during tests


class _CenturyHTTPServer(HTTPServer):
    def __init__(self, basedir: Path) -> None:
        self.basedir = basedir
        super().__init__(('localhost', 0), _CenturyHandler)


@pytest.fixture()
def http_server(basedir: Path) -> Generator[Tuple[str, Path], None, None]:
    httpd = _CenturyHTTPServer(basedir)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
    yield f'http://localhost:{port}', basedir
    httpd.shutdown()


# ── Server tests (via CGI subprocess) ────────────────────────────────────────

def test_listbundles_skeleton(basedir: Path) -> None:
    status, _, body = call_server(basedir, 'GET', '/api/v1/listbundles')
    assert status == 200
    assert json.loads(body) == [{'directory': '00-ff', 'bundle': '00-ff', 'index': 0}]


def test_authorize(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}'
    )
    assert status == 200
    assert (basedir / '00-ff' / '00-ff' / f'{reader_id}+{writer_pub}').is_dir()


def test_authorize_duplicate(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    path = f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}'
    call_server(basedir, 'POST', path)
    status, _, _ = call_server(basedir, 'POST', path)
    assert status == 409


def test_authorize_bad_authtoken(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        f'/api/v1/authorize/{reader_id}/{writer_pub}/{"1" * 64}'
    )
    assert status == 403


def test_update(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    call_server(basedir, 'POST',
                f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}')

    record = centurymetadata.encode(
        keys['writer'], keys['reader_secp'].pubkey, keys['reader_mlkem_pk'],
        0, ['title', 'body']
    )
    status, _, _ = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata')
    assert status == 200


def test_update_unauthorized(basedir: Path, keys: Dict) -> None:
    record = centurymetadata.encode(
        keys['writer'], keys['reader_secp'].pubkey, keys['reader_mlkem_pk'],
        0, ['title', 'body']
    )
    status, _, _ = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata')
    assert status == 403


def test_update_duplicate_gen(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    call_server(basedir, 'POST',
                f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}')

    record = centurymetadata.encode(
        keys['writer'], keys['reader_secp'].pubkey, keys['reader_mlkem_pk'],
        0, ['title', 'body']
    )
    call_server(basedir, 'POST', '/api/v1/update',
                body=record, content_type='application/x-centurymetadata')
    status, _, _ = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata')
    assert status == 400


def test_fetchxor_contains_record(basedir: Path, keys: Dict) -> None:
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    call_server(basedir, 'POST',
                f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}')

    record = centurymetadata.encode(
        keys['writer'], keys['reader_secp'].pubkey, keys['reader_mlkem_pk'],
        0, ['title', 'body']
    )
    call_server(basedir, 'POST', '/api/v1/update',
                body=record, content_type='application/x-centurymetadata')

    bitmask = bytearray(128)
    bitmask[0] = 1
    status, _, bundle = call_server(basedir, 'POST', '/api/v1/fetchxor/00-ff',
                                    body=bytes(bitmask),
                                    content_type='application/octet-stream')
    assert status == 200
    assert len(bundle) == 1024 * centurymetadata.FULL_LENGTH

    # Find our record by READER_ID field (offset 64+33 in each slot)
    slot_size = centurymetadata.FULL_LENGTH
    reader_id_offset = 64 + 33
    our_reader_id = keys['reader_id']
    found = False
    for i in range(1024):
        slot = bundle[i * slot_size:(i + 1) * slot_size]
        if slot[reader_id_offset:reader_id_offset + 32] == our_reader_id:
            found = True
            decoded = centurymetadata.decode(
                keys['reader_secp'], keys['reader_mlkem_sk'],
                centurymetadata.preamble + slot
            )
            assert decoded == [('title', 'body')]
            break
    assert found


def test_fetchxor_xor_cancels(basedir: Path, keys: Dict) -> None:
    """XOR of a bundle with itself should be all zeroes."""
    reader_id = keys['reader_id'].hex()
    writer_pub = keys['writer'].pubkey.serialize().hex()
    call_server(basedir, 'POST',
                f'/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}')

    record = centurymetadata.encode(
        keys['writer'], keys['reader_secp'].pubkey, keys['reader_mlkem_pk'],
        0, ['title', 'body']
    )
    call_server(basedir, 'POST', '/api/v1/update',
                body=record, content_type='application/x-centurymetadata')

    bitmask_one = bytearray(128)
    bitmask_one[0] = 1
    bitmask_zero = bytearray(128)

    _, _, bundle1 = call_server(basedir, 'POST', '/api/v1/fetchxor/00-ff',
                                body=bytes(bitmask_one),
                                content_type='application/octet-stream')
    _, _, bundle0 = call_server(basedir, 'POST', '/api/v1/fetchxor/00-ff',
                                body=bytes(bitmask_zero),
                                content_type='application/octet-stream')

    n = len(bundle1)
    xored = (int.from_bytes(bundle1, 'little') ^ int.from_bytes(bundle0, 'little')).to_bytes(n, 'little')
    assert xored == bundle1  # XOR with zero bundle is identity
    assert bundle0 == bytes(n)  # empty bitmask returns all zeroes


# ── Centurytool tests (via HTTP server) ───────────────────────────────────────

def _run_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL_PY), *args],
        capture_output=True
    )


def test_tool_encode_check_decode(tmp_path: Path) -> None:
    """Local encode / check / decode round-trip, no server needed."""
    writer_hex = '01' * 32
    reader_secret = '02' * 32 + '/' + '02' * 32
    enc_file = str(tmp_path / 'enc.bin')

    result = _run_tool(f'--writer-secret={writer_hex}',
                       f'--reader-secret={reader_secret}',
                       '--encode', 'mytitle', 'mybody',
                       '--raw')
    assert result.returncode == 0
    Path(enc_file).write_bytes(result.stdout)

    result = _run_tool('--raw', '--check', f'@{enc_file}')
    assert result.returncode == 0
    out = result.stdout.decode()
    assert 'writer:' in out
    assert 'reader_id:' in out
    assert 'generation: 0' in out

    result = _run_tool(f'--reader-secret={reader_secret}',
                       '--raw', '--decode', f'@{enc_file}')
    assert result.returncode == 0
    out = result.stdout.decode()
    assert 'mytitle' in out
    assert 'mybody' in out


def test_tool_fetch(http_server: Tuple[str, Path], tmp_path: Path) -> None:
    """Full round-trip: encode, authorize, upload, fetch, decode via server."""
    server_url, _ = http_server
    writer_hex = '01' * 32
    reader_secret = '02' * 32 + '/' + '02' * 32
    enc_file = str(tmp_path / 'enc.bin')

    # Encode
    result = _run_tool(f'--writer-secret={writer_hex}',
                       f'--reader-secret={reader_secret}',
                       '--encode', 'mytitle', 'mybody',
                       '--raw')
    assert result.returncode == 0
    encoded = result.stdout

    # Compute reader_id and writer pubkey for authorize step
    writer = PrivateKey(bytes([1] * 32))
    writer_pub = writer.pubkey.serialize().hex()
    reader_secp = PrivateKey(bytes([2] * 32))
    reader_mlkem_pk, _ = centurymetadata.derive_mlkem_keypair(bytes([2] * 32))
    reader_id = centurymetadata.get_reader_id(reader_secp.pubkey, reader_mlkem_pk).hex()

    # Authorize
    req = urllib.request.Request(
        f'{server_url}/api/v1/authorize/{reader_id}/{writer_pub}/{"0" * 64}',
        data=b'', method='POST'
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200

    # Upload
    req = urllib.request.Request(
        f'{server_url}/api/v1/update',
        data=encoded, method='POST',
        headers={'Content-Type': 'application/x-centurymetadata'}
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200

    # Fetch via centurytool
    result = _run_tool(f'--reader-secret={reader_secret}',
                       f'--server={server_url}',
                       '--fetch', '--raw')
    assert result.returncode == 0
    Path(enc_file).write_bytes(result.stdout)

    # Decode
    result = _run_tool(f'--reader-secret={reader_secret}',
                       '--raw', '--decode', f'@{enc_file}')
    assert result.returncode == 0
    out = result.stdout.decode()
    assert 'mytitle' in out
    assert 'mybody' in out


# ── Bundle / directory splitting tests ───────────────────────────────────────

def _authorize_and_upload(basedir: Path, writer_privkey: PrivateKey,
                          reader_secp: PrivateKey, reader_mlkem_pk: bytes,
                          reader_id: bytes, gen: int,
                          extra_env: Dict[str, str] = {}) -> None:
    """Authorize then upload a single record."""
    rid_hex = reader_id.hex()
    wpub_hex = writer_privkey.pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        f'/api/v1/authorize/{rid_hex}/{wpub_hex}/{"0" * 64}',
        extra_env=extra_env
    )
    assert status in (200, 409)  # 409 = already authorized
    record = centurymetadata.encode(writer_privkey, reader_secp.pubkey,
                                    reader_mlkem_pk, gen, ['t', 'b'])
    status, _, _ = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata',
        extra_env=extra_env
    )
    assert status == 200


def test_bundle_split(tmp_path: Path) -> None:
    """Uploading more than SPLIT_THRESHOLD records causes the bundle to split."""
    (tmp_path / '00-ff' / '00-ff').mkdir(parents=True)
    threshold = 4
    extra_env = {'CENTURYMETADATA_SPLIT_THRESHOLD': str(threshold)}

    privkeys = [PrivateKey(bytes([i + 1]) + bytes(31)) for i in range(threshold + 1)]
    writer = privkeys[0]

    for i, reader_secp in enumerate(privkeys):
        mlkem_seed = bytes([i + 1] * 32)
        reader_mlkem_pk, _ = centurymetadata.derive_mlkem_keypair(mlkem_seed)
        reader_id = centurymetadata.get_reader_id(reader_secp.pubkey, reader_mlkem_pk)
        _authorize_and_upload(tmp_path, writer, reader_secp, reader_mlkem_pk,
                              reader_id, 0, extra_env=extra_env)

    status, _, body = call_server(tmp_path, 'GET', '/api/v1/listbundles',
                                  extra_env=extra_env)
    assert status == 200
    bundles = json.loads(body)
    assert len(bundles) > 1, f"Expected split, got {bundles}"


def test_split_records_accessible(tmp_path: Path) -> None:
    """After splitting, records can still be fetched via fetchxor."""
    (tmp_path / '00-ff' / '00-ff').mkdir(parents=True)
    threshold = 4
    extra_env = {'CENTURYMETADATA_SPLIT_THRESHOLD': str(threshold)}

    privkeys = [PrivateKey(bytes([i + 1]) + bytes(31)) for i in range(threshold + 1)]
    writer = privkeys[0]
    mlkem_seeds = [bytes([i + 1] * 32) for i in range(len(privkeys))]
    reader_ids = []

    for i, reader_secp in enumerate(privkeys):
        reader_mlkem_pk, _ = centurymetadata.derive_mlkem_keypair(mlkem_seeds[i])
        reader_id = centurymetadata.get_reader_id(reader_secp.pubkey, reader_mlkem_pk)
        reader_ids.append(reader_id)
        _authorize_and_upload(tmp_path, writer, reader_secp, reader_mlkem_pk,
                              reader_id, 0, extra_env=extra_env)

    status, _, body = call_server(tmp_path, 'GET', '/api/v1/listbundles',
                                  extra_env=extra_env)
    assert status == 200
    bundles = json.loads(body)

    slot_size = centurymetadata.FULL_LENGTH
    all_slots: Dict[bytes, bytes] = {}
    dirs_seen: Set[str] = set()
    for bundle_entry in bundles:
        directory = bundle_entry['directory']
        idx = bundle_entry['index']
        dirs_seen.add(directory)
        bitmask = bytearray(128)
        bitmask[idx // 8] |= (1 << (idx % 8))
        s, _, data = call_server(tmp_path, 'POST',
                                 f'/api/v1/fetchxor/{directory}',
                                 body=bytes(bitmask),
                                 content_type='application/octet-stream',
                                 extra_env=extra_env)
        assert s == 200
        for j in range(1024):
            slot = data[j * slot_size:(j + 1) * slot_size]
            rid = slot[64 + 33:64 + 33 + 32]
            if any(rid):
                all_slots[rid] = slot

    for reader_id in reader_ids:
        assert reader_id in all_slots, f"reader_id {reader_id.hex()} not found after split"
