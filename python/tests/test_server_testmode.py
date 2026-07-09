#! /usr/bin/env python3
"""Integration tests for the test server's known-keys enforcement."""
from pathlib import Path
from typing import Tuple

import pytest
from secp256k1 import PrivateKey, PublicKey

import centurymetadata
from centurymetadata.bip39 import bip39_to_seed, derive_cm_keys
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


def _first_half_full_keys() -> Tuple[bytes, PrivateKey, PublicKey, bytes]:
    """(reader_id, writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey) for a
    self-authored known identity, re-derived from its word like known_keys did."""
    for reader_id, identity in known_keys._IDENTITIES.items():
        if not identity.self_authored:
            continue
        seed = bip39_to_seed(" ".join([identity.word] * 12))
        w_secp, _r_secp, _w_mlkem, r_mlkem_seed = derive_cm_keys(seed, n=0)
        writer_privkey = PrivateKey(w_secp)
        reader_mlkem_pubkey, _ = centurymetadata.derive_mlkem_keypair(r_mlkem_seed)
        privkeys = known_keys.reader_privkeys(reader_id)
        assert privkeys is not None
        reader_secp_privkey, _reader_mlkem_privkey = privkeys
        return reader_id, writer_privkey, reader_secp_privkey.pubkey, reader_mlkem_pubkey
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


def _authorize(basedir: Path, reader_id: bytes, writer_pubkey_hex: str) -> None:
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format(reader_id.hex(), writer_pubkey_hex, '0' * 64),
        extra_env=TEST_MODE_ENV
    )
    assert status == 200


def test_update_compliant_record_accepted(basedir: Path) -> None:
    reader_id, writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey = _first_half_full_keys()
    _authorize(basedir, reader_id, writer_privkey.pubkey.serialize().hex())

    labels = ('{"type": "tx", "ref": '
              '"f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd", '
              '"label": "coffee"}')
    record = centurymetadata.encode(
        writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey, 0,
        ('bitcoin wallet labels', 'labels', labels)
    )
    status, _, body = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata',
        extra_env=TEST_MODE_ENV
    )
    assert status == 200, body


def test_update_unrecognized_type_rejected(basedir: Path) -> None:
    reader_id, writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey = _first_half_full_keys()
    _authorize(basedir, reader_id, writer_privkey.pubkey.serialize().hex())

    record = centurymetadata.encode(
        writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey, 0,
        ('text', 'note', 'not an accepted type')
    )
    status, _, body = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata',
        extra_env=TEST_MODE_ENV
    )
    assert status == 400
    assert b'Unrecognized TYPE' in body


def test_update_empty_contents_rejected(basedir: Path) -> None:
    reader_id, writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey = _first_half_full_keys()
    _authorize(basedir, reader_id, writer_privkey.pubkey.serialize().hex())

    record = centurymetadata.encode(
        writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey, 0,
        ('bitcoin miniscript', 'empty', '')
    )
    status, _, body = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata',
        extra_env=TEST_MODE_ENV
    )
    assert status == 400
    assert b'Empty CONTENTS' in body


def test_update_test_mode_off_unaffected(basedir: Path) -> None:
    """Without test mode, arbitrary types/content are accepted, as before."""
    reader_id, writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey = _first_half_full_keys()
    status, _, _ = call_server(
        basedir, 'POST',
        '/api/v1/authorize/{}/{}/{}'.format(reader_id.hex(), writer_privkey.pubkey.serialize().hex(), '0' * 64)
    )
    assert status == 200

    record = centurymetadata.encode(
        writer_privkey, reader_secp_pubkey, reader_mlkem_pubkey, 0,
        ('text', 'note', 'arbitrary, not in the accepted type list')
    )
    status, _, body = call_server(
        basedir, 'POST', '/api/v1/update',
        body=record, content_type='application/x-centurymetadata'
    )
    assert status == 200, body
