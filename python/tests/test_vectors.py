#!/usr/bin/env python3
"""
Validate centurymetadata test vectors against canned JSON.

The canned vectors live at the repository root (test_vectors.json).
Regenerate them by running from the python/ subdirectory:

    uv run python ../tools/generate_test_vectors.py

Or set GENERATE_VECTORS=1 to regenerate automatically before testing:

    GENERATE_VECTORS=1 uv run pytest tests/test_vectors.py
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
VECTORS_PATH = REPO_ROOT / "test_vectors.json"
GENERATOR = REPO_ROOT / "tools" / "generate_test_vectors.py"

sys.path.insert(0, str(REPO_ROOT / "tools"))
from generate_test_vectors import generate_vector, CASES  # noqa: E402


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def canned_vectors() -> list:
    if os.environ.get("GENERATE_VECTORS"):
        subprocess.run(
            [sys.executable, str(GENERATOR)],
            cwd=str(REPO_ROOT / "python"),
            check=True,
        )
    if not VECTORS_PATH.exists():
        pytest.skip(
            f"{VECTORS_PATH} not found — run: "
            "cd python && uv run python ../tools/generate_test_vectors.py"
        )
    return json.loads(VECTORS_PATH.read_text())


# ── parametrised tests ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "idx,mnemonic,n",
    [(i, mnemonic, n) for i, (mnemonic, n) in enumerate(CASES)],
)
def test_vector_fields(idx: int, mnemonic: str, n: int, canned_vectors: list) -> None:
    """Every computed field must match the canned vector exactly."""
    canned = canned_vectors[idx]
    fresh = generate_vector(mnemonic, n)

    # provided_values must be identical
    assert fresh["provided_values"] == canned["provided_values"]

    # results compared field-by-field for precise failure messages
    canned_results = canned["results"]
    fresh_results = fresh["results"]
    for name, entry in canned_results.items():
        assert fresh_results[name]["value"] == entry["value"], (
            f"Vector {idx} result {name!r} mismatch:\n"
            f"  expected: {str(entry['value'])[:80]}\n"
            f"  got:      {str(fresh_results.get(name, {}).get('value'))[:80]}"
        )


@pytest.mark.parametrize(
    "idx,mnemonic,n",
    [(i, mnemonic, n) for i, (mnemonic, n) in enumerate(CASES)],
)
def test_vector_record_decodes(idx: int, mnemonic: str, n: int, canned_vectors: list) -> None:
    """The RECORD in each canned vector must decode to the expected type/name/contents."""
    from secp256k1 import PrivateKey, PublicKey
    import centurymetadata

    steps = canned_vectors[idx]
    pv = steps["provided_values"]
    res = steps["results"]

    reader_secp_key = PrivateKey(bytes.fromhex(res["READER_SECP_PRIVKEY"]["value"]))
    reader_mlkem_sk = bytes.fromhex(res["READER_MLKEM_PRIVKEY"]["value"])
    reader_mlkem_pk = bytes.fromhex(res["READER_MLKEM_PUBKEY"]["value"])
    writer_pubkey = PublicKey(bytes.fromhex(res["WRITER_PUBKEY"]["value"]), raw=True)
    record = bytes.fromhex(res["RECORD"]["value"])

    errors, decoded = centurymetadata.decode(reader_secp_key, reader_mlkem_sk, reader_mlkem_pk,
                                             writer_pubkey, record)
    assert errors == [], f"centurymetadata.decode() returned errors: {errors}"
    assert decoded == [(pv["TYPE"]["value"], pv["NAME"]["value"], pv["CONTENTS"]["value"])]
