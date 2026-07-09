#! /usr/bin/env python3
"""Integration tests for the test server's known-keys enforcement."""
from pathlib import Path
from typing import Tuple

import pytest
from secp256k1 import PrivateKey

from centurymetadata.server import known_keys
from centurymetadata.server.devserver import call_server

TEST_MODE_ENV = {'CENTURYMETADATA_TEST_MODE': '1'}


@pytest.fixture()
def basedir(tmp_path: Path) -> Path:
    (tmp_path / '00-ff' / '00-ff').mkdir(parents=True)
    return tmp_path


def _first_half_reader() -> Tuple[bytes, bytes]:
    for reader_id, identity in known_keys._IDENTITIES.items():
        if identity.self_authored:
            return reader_id, identity.writer_pubkey.serialize()
    raise AssertionError("no self-authored known identity found")


def _second_half_reader() -> bytes:
    for reader_id, identity in known_keys._IDENTITIES.items():
        if not identity.self_authored:
            return reader_id
    raise AssertionError("no second-half known identity found")


def test_authorize_unknown_reader_rejected(basedir: Path) -> None:
    random_writer = PrivateKey(bytes([9] * 32)).pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format('ab' * 32, random_writer, '0' * 64),
        extra_env=TEST_MODE_ENV
    )
    assert status == 403


def test_authorize_first_half_wrong_writer_rejected(basedir: Path) -> None:
    reader_id, _correct_writer = _first_half_reader()
    wrong_writer = PrivateKey(bytes([9] * 32)).pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format(reader_id.hex(), wrong_writer, '0' * 64),
        extra_env=TEST_MODE_ENV
    )
    assert status == 403


def test_authorize_first_half_correct_writer_accepted(basedir: Path) -> None:
    reader_id, correct_writer = _first_half_reader()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format(reader_id.hex(), correct_writer.hex(), '0' * 64),
        extra_env=TEST_MODE_ENV
    )
    assert status == 200


def test_authorize_second_half_any_writer_accepted(basedir: Path) -> None:
    reader_id = _second_half_reader()
    any_writer = PrivateKey(bytes([9] * 32)).pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format(reader_id.hex(), any_writer, '0' * 64),
        extra_env=TEST_MODE_ENV
    )
    assert status == 200


def test_authorize_test_mode_off_unaffected(basedir: Path) -> None:
    """Without test mode, any syntactically valid reader/writer is accepted."""
    random_writer = PrivateKey(bytes([9] * 32)).pubkey.serialize().hex()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format('ab' * 32, random_writer, '0' * 64)
    )
    assert status == 200
