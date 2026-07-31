#!/usr/bin/env python3
"""
Regression test for tools/gen_test_vectors.py.

Runs the generator's own category functions against a fresh VectorSet
(same code path main() uses), then independently re-reads every stored
file back from disk and re-decodes it, checking the outcome matches
what each vector is supposed to demonstrate -- a disk round-trip on top
of the generator's own inline self-verification (which already runs,
and would raise, while building the fixture below). Identities are
re-derived purely from each manifest entry's own public "reader"/"n"
fields (not from the generator's in-memory vs.identities), so this
doubles as a check that the manifest alone is enough to reconstruct
and decode every vector.
"""
import json
import sys
from pathlib import Path
from typing import Tuple

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

sys.path.insert(0, str(REPO_ROOT / "tools"))
import gen_test_vectors as gtv  # noqa: E402

import centurymetadata  # noqa: E402
from centurymetadata import CenturyMetadata, CMDataErrorCode, Identity  # noqa: E402

EXPECTED_CATEGORIES = {
    "baseline", "gen-ordering", "wire-errors", "next-derivation",
    "priority-ordering", "unknown-type", "to-self-vs-not", "per-type-contents",
}


@pytest.fixture(scope="module")
def vector_set(tmp_path_factory: pytest.TempPathFactory) -> gtv.VectorSet:
    directory = tmp_path_factory.mktemp("cmdata-vectors") / "basedir"
    (directory / gtv.SKELETON_DIR / gtv.SKELETON_BUNDLE).mkdir(parents=True)
    vs = gtv.VectorSet(directory)
    for category in gtv.CATEGORIES:
        category(vs)
    vs.write_manifest()
    return vs


def _identity_for_entry(entry: gtv.ManifestEntry) -> Identity:
    """Re-derived purely from the manifest's own "reader" mnemonic and
    "n" fields -- independent of whatever writer key a given vector was
    actually signed with (this is always the *reader's own* self-authored
    identity, which is exactly what's needed both to decrypt and, for
    to-self detection, as the "own writer pubkey")."""
    return gtv.identity_for_word(entry.reader, n=entry.n)


def _read_full_record(vs: gtv.VectorSet, entry: gtv.ManifestEntry) -> bytes:
    after_pre = (vs.basedir / entry.path).read_bytes()
    assert len(after_pre) == centurymetadata.DATA_LENGTH
    return centurymetadata.preamble + after_pre


def _decode_entry(vs: gtv.VectorSet, entry: gtv.ManifestEntry) -> Tuple[list, list]:
    identity = _identity_for_entry(entry)
    full = _read_full_record(vs, entry)
    return centurymetadata.decode(
        identity.reader_secp_privkey, identity.reader_mlkem_privkey,
        identity.reader_mlkem_pubkey, identity.writer_privkey.pubkey, full)


# ── Manifest shape ────────────────────────────────────────────────────────────

def test_manifest_covers_every_category(vector_set: gtv.VectorSet) -> None:
    categories = {e.category for e in vector_set.manifest}
    assert categories == EXPECTED_CATEGORIES
    assert len(vector_set.manifest) >= 30


def test_manifest_json_matches_written_file(vector_set: gtv.VectorSet) -> None:
    data = json.loads((vector_set.basedir / "manifest.json").read_text())
    assert len(data) == len(vector_set.manifest)
    assert {d["path"] for d in data} == {e.path for e in vector_set.manifest}


def test_manifest_invalid_and_writer_flags_are_conditional(vector_set: gtv.VectorSet) -> None:
    """"invalid" and "writer" keys are present in the JSON only when
    they apply -- never null/empty placeholders."""
    data = json.loads((vector_set.basedir / "manifest.json").read_text())
    by_path = {d["path"]: d for d in data}

    for entry in vector_set.manifest:
        d = by_path[entry.path]
        assert ("invalid" in d) == (entry.invalid is not None)
        assert ("writer" in d) == (entry.writer is not None)
        assert ("records" in d) == (entry.records is not None)
        if "records" in d:
            assert isinstance(d["records"], (list, str))
            if isinstance(d["records"], list):
                for r in d["records"]:
                    assert set(r) == {"type", "name", "contents"}

    # Every wire-errors vector signs with a distinct, non-self-authored
    # writer key (illegal_identity()), so "writer" should always appear.
    wire_errors = [e for e in vector_set.manifest if e.category == "wire-errors"]
    assert wire_errors and all(e.writer is not None for e in wire_errors)

    # The baseline vector is plain self-authored: neither flag applies.
    baseline = next(e for e in vector_set.manifest if e.category == "baseline")
    assert baseline.invalid is None
    assert baseline.writer is None


# ── General sweep: every vector, read back from disk ───────────────────────────

def test_every_vector_round_trips_from_disk(vector_set: gtv.VectorSet) -> None:
    """Every stored file is exactly DATA_LENGTH bytes and re-decodes
    without crashing; every wire-errors vector produces at least one
    decode error (some fatal -- e.g. BAD_SIGNATURE -- others per-record
    only -- e.g. TRUNCATED_TUPLE, see test_wire_errors_produce_expected_codes
    for exactly which), and every other category decodes with no fatal
    error (a couple, like to-self-vs-not, still carry a non-fatal one by
    design)."""
    for entry in vector_set.manifest:
        errors, _triples = _decode_entry(vector_set, entry)
        has_fatal = any(e.fatal for e in errors)
        if entry.category == "wire-errors":
            assert errors, "{}/{} should report at least one error, got none".format(
                entry.category, entry.name)
        else:
            assert not has_fatal, "{}/{} should decode cleanly, got {}".format(
                entry.category, entry.name, errors)


# ── Spot checks: precise outcomes for the trickier categories ──────────────────

def test_wire_errors_produce_expected_codes(vector_set: gtv.VectorSet) -> None:
    expected = {
        "bad-wkey": CMDataErrorCode.BAD_WKEY,
        "bad-reader-id": CMDataErrorCode.BAD_READER_ID,
        "bad-signature": CMDataErrorCode.BAD_SIGNATURE,
        "bad-aes-tag": CMDataErrorCode.BAD_AES_TAG,
        "bad-zlib": CMDataErrorCode.BAD_ZLIB,
        "truncated-zlib": CMDataErrorCode.TRUNCATED_ZLIB,
        "oversize-zlib": CMDataErrorCode.OVERSIZE_ZLIB,
        "truncated-tuple": CMDataErrorCode.TRUNCATED_TUPLE,
        "invalid-utf8": CMDataErrorCode.INVALID_UTF8,
        "overlength-name": CMDataErrorCode.OVERLENGTH_NAME,
    }
    by_name = {e.name: e for e in vector_set.manifest if e.category == "wire-errors"}
    assert set(by_name) == set(expected)
    for name, code in expected.items():
        entry = by_name[name]
        errors, _triples = _decode_entry(vector_set, entry)
        assert errors and errors[0].code == code, "{}: expected {}, got {}".format(name, code, errors)


def test_gen_ordering_keeps_both_generations_on_disk(vector_set: gtv.VectorSet) -> None:
    entries = {e.name: e for e in vector_set.manifest if e.category == "gen-ordering"}
    assert set(entries) == {"gen-0", "gen-5"}
    for name, gen in (("gen-0", 0), ("gen-5", 5)):
        entry = entries[name]
        assert entry.gen == gen
        errors, triples = _decode_entry(vector_set, entry)
        assert not any(e.fatal for e in errors)
        assert len(triples) == 1


def test_next_derivation_chain_links_via_load(vector_set: gtv.VectorSet) -> None:
    n0 = next(e for e in vector_set.manifest if e.category == "next-derivation" and e.name == "valid-chain-n0")
    n1 = next(e for e in vector_set.manifest if e.category == "next-derivation" and e.name == "valid-chain-n1")
    id0 = _identity_for_entry(n0)
    id1 = _identity_for_entry(n1)

    doc = CenturyMetadata()
    errors0, next_n = doc.load(id0, 0, _read_full_record(vector_set, n0))
    assert not any(e.fatal for e in errors0)
    assert next_n == 1
    errors1, next_n2 = doc.load(id1, 1, _read_full_record(vector_set, n1))
    assert not any(e.fatal for e in errors1)
    assert next_n2 is None
    assert len(doc.records) == 2


def test_next_derivation_bad_contents_drop_the_link_not_the_file(vector_set: gtv.VectorSet) -> None:
    for name in ("bad-contents-not-decimal", "bad-contents-not-greater", "duplicate-records"):
        entry = next(e for e in vector_set.manifest if e.category == "next-derivation" and e.name == name)
        identity = _identity_for_entry(entry)
        doc = CenturyMetadata()
        errors, next_n = doc.load(identity, 0, _read_full_record(vector_set, entry))
        assert not any(e.fatal for e in errors)
        if name == "duplicate-records":
            assert next_n == 1
        else:
            assert next_n is None


def test_priority_ordering_writes_decreasing_priority(vector_set: gtv.VectorSet) -> None:
    entry = next(e for e in vector_set.manifest if e.category == "priority-ordering" and e.name == "mixed-types")
    _errors, triples = _decode_entry(vector_set, entry)
    assert [t for t, _, _ in triples] == [
        "bitcoin output script descriptor", "bitcoin psbt", "bitcoin transaction", "bitcoin wallet labels",
    ]


def test_priority_split_chain_round_trips(vector_set: gtv.VectorSet) -> None:
    n0 = next(e for e in vector_set.manifest
              if e.category == "priority-ordering" and e.name == "oversized-split-n0")
    n1 = next(e for e in vector_set.manifest
              if e.category == "priority-ordering" and e.name == "oversized-split-n1")
    id0 = _identity_for_entry(n0)
    id1 = _identity_for_entry(n1)

    doc = CenturyMetadata()
    errors0, next_n = doc.load(id0, 0, _read_full_record(vector_set, n0))
    assert not any(e.fatal for e in errors0)
    assert next_n == 1
    errors1, next_n2 = doc.load(id1, 1, _read_full_record(vector_set, n1))
    assert not any(e.fatal for e in errors1)
    assert next_n2 is None
    assert len(doc.records) == 2
    # Genuinely split, not everything landing on one file (see the
    # deterministic_filler sizing comment in gen_test_vectors.py).
    assert len(n0.records) == 2  # descriptor + next-derivation-path
    assert len(n1.records) == 1  # transaction


def test_unknown_type_round_trips_via_load(vector_set: gtv.VectorSet) -> None:
    entry = next(e for e in vector_set.manifest if e.category == "unknown-type")
    identity = _identity_for_entry(entry)
    doc = CenturyMetadata()
    errors, _next_n = doc.load(identity, 0, _read_full_record(vector_set, entry))
    assert not any(e.fatal for e in errors)
    unknowns = doc.unknown_records()
    assert len(unknowns) == 1
    assert unknowns[0].rtype == "_experimental widget"


def test_to_self_continues_past_error_not_to_self_stops(vector_set: gtv.VectorSet) -> None:
    to_self = next(e for e in vector_set.manifest
                   if e.category == "to-self-vs-not" and e.name == "to-self-continues")
    not_self = next(e for e in vector_set.manifest
                    if e.category == "to-self-vs-not" and e.name == "not-to-self-may-stop")

    to_self_identity = _identity_for_entry(to_self)
    errors, triples = centurymetadata.decode(
        to_self_identity.reader_secp_privkey, to_self_identity.reader_mlkem_privkey,
        to_self_identity.reader_mlkem_pubkey, to_self_identity.writer_privkey.pubkey,
        _read_full_record(vector_set, to_self))
    assert any(e.code == CMDataErrorCode.INVALID_UTF8 for e in errors)
    assert ("text", "before", "valid tuple before the error") in triples
    assert ("text", "after", "valid tuple after the error") in triples

    # not_self's own "reader" identity is the *reader's* own writer key
    # (used here as the "own pubkey" for to-self detection); the file
    # itself was actually signed with an unrelated, foreign writer (see
    # its "writer" manifest field), which is exactly what makes it
    # not-to-self.
    not_self_identity = _identity_for_entry(not_self)
    errors2, triples2 = centurymetadata.decode(
        not_self_identity.reader_secp_privkey, not_self_identity.reader_mlkem_privkey,
        not_self_identity.reader_mlkem_pubkey, not_self_identity.writer_privkey.pubkey,
        _read_full_record(vector_set, not_self))
    assert any(e.code == CMDataErrorCode.INVALID_UTF8 for e in errors2)
    assert ("text", "before", "valid tuple before the error") in triples2
    assert ("text", "after", "valid tuple after the error") not in triples2
    assert not_self.writer is not None


def test_per_type_contents_validate_py_agrees(vector_set: gtv.VectorSet) -> None:
    from centurymetadata import validate

    expect_valid = {
        "psbt-valid": True, "psbt-invalid": False,
        "transaction-valid": True, "transaction-invalid": False,
        "descriptor-valid": True, "descriptor-bad-checksum": False,
        "descriptor-unsupported-expression": False,
        "wallet-labels-valid": True, "wallet-labels-invalid-json": False,
    }
    by_name = {e.name: e for e in vector_set.manifest if e.category == "per-type-contents"}
    for name, valid in expect_valid.items():
        entry = by_name[name]
        _errors, triples = _decode_entry(vector_set, entry)
        content_triple = next(t for t in triples if t[0] != "text")
        err = validate.validate_triples([content_triple])
        if valid:
            assert err is None, "{}: expected valid, got error {!r}".format(name, err)
        else:
            assert err is not None, "{}: expected invalid, but validate_triples() accepted it".format(name)
