"""Content-compliance validation for the test server.

Enforces the record spec documented in README.md: TYPE must be one of
the five accepted literal strings, and CONTENTS must be valid for that
type. Real per-type CONTENTS validators are registered in _VALIDATORS
as they're implemented; a type with no registered validator still gets
the baseline TYPE/NAME/CONTENTS checks below.
"""
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from embit import bip32
from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum as descriptor_checksum
from embit.descriptor.miniscript import Miniscript
from embit.psbt import PSBT
from embit.script import Script
from embit.transaction import Transaction

Triple = Tuple[str, str, str]
ValidatorFn = Callable[[str], Optional[str]]

ACCEPTED_TYPES = (
    "bitcoin psbt",
    "bitcoin transaction",
    "bitcoin miniscript",
    "bitcoin output script descriptor",
    "bitcoin wallet labels",
)

_VALIDATORS: Dict[str, ValidatorFn] = {}


# ── bitcoin wallet labels (BIP-329 JSONL) ────────────────────────────────────

_LABEL_TYPES = {"tx", "addr", "pubkey", "input", "output", "xpub", "spscan"}
_TXID_RE = re.compile(r"^[0-9a-f]{64}$")
_TX_INDEX_REF_RE = re.compile(r"^[0-9a-f]{64}:[0-9]+$")
_PUBKEY_HEX_RE = re.compile(r"^([0-9a-f]{64}|[0-9a-f]{66}|[0-9a-f]{130})$")
# Abbreviated output descriptor (BIP-380): key origin info only, no actual
# key material -- e.g. wpkh([d34db33f/84'/0'/0']) or sh(wpkh([...])).
_ORIGIN_RE = re.compile(r"^[a-z]+\((?:[a-z]+\()*\[[0-9a-f]{8}(?:/[0-9]+'?)*\]\)+$")


def _validate_label_ref(rtype: str, ref: str) -> Optional[str]:
    if rtype == "tx":
        if not _TXID_RE.match(ref):
            return "'tx' ref must be a 64-hex-character transaction id"
    elif rtype in ("input", "output"):
        if not _TX_INDEX_REF_RE.match(ref):
            return "'{}' ref must be txid:index".format(rtype)
    elif rtype == "pubkey":
        if not _PUBKEY_HEX_RE.match(ref):
            return "'pubkey' ref must be 32, 33 or 65 bytes of hex"
    elif rtype == "addr":
        try:
            Script.from_address(ref)
        except Exception as e:
            return "'addr' ref must be a valid base58 or bech32 address ({})".format(e)
    elif rtype == "xpub":
        try:
            key = bip32.HDKey.from_base58(ref)
        except Exception as e:
            return "'xpub' ref must be a valid BIP-32 extended public key ({})".format(e)
        if key.is_private:
            return "'xpub' ref must not be a private extended key"
    elif rtype == "spscan":
        if not ref.startswith("spscan1"):
            return "'spscan' ref must be a silent payments scan key expression"
    return None


def validate_bip329_labels(contents: str) -> Optional[str]:
    """Validate CONTENTS as BIP-329 wallet-labels JSONL."""
    for lineno, line in enumerate(contents.split("\n"), start=1):
        if line == "":
            continue
        try:
            obj: Any = json.loads(line)
        except json.JSONDecodeError as e:
            return "line {}: invalid JSON ({})".format(lineno, e)
        if not isinstance(obj, dict):
            return "line {}: must be a JSON object".format(lineno)

        if "type" not in obj or "ref" not in obj:
            return "line {}: missing required 'type' or 'ref'".format(lineno)
        rtype = obj["type"]
        if rtype not in _LABEL_TYPES:
            return "line {}: unknown type {!r}".format(lineno, rtype)
        ref = obj["ref"]
        if not isinstance(ref, str):
            return "line {}: 'ref' must be a string".format(lineno)

        err = _validate_label_ref(rtype, ref)
        if err is not None:
            return "line {}: {}".format(lineno, err)

        if "label" in obj and not isinstance(obj["label"], str):
            return "line {}: 'label' must be a string".format(lineno)

        if "spendable" in obj:
            if rtype != "output":
                return "line {}: 'spendable' only applies to type 'output'".format(lineno)
            if not isinstance(obj["spendable"], bool):
                return "line {}: 'spendable' must be a boolean".format(lineno)

        if "origin" in obj:
            origin = obj["origin"]
            if not isinstance(origin, str) or not _ORIGIN_RE.match(origin):
                return "line {}: 'origin' must be an abbreviated output descriptor".format(lineno)
    return None


_VALIDATORS["bitcoin wallet labels"] = validate_bip329_labels


# ── bitcoin psbt ──────────────────────────────────────────────────────────────

def validate_bitcoin_psbt(contents: str) -> Optional[str]:
    """Validate CONTENTS as a base64-encoded PSBT (BIP-174)."""
    try:
        PSBT.from_string(contents)
    except Exception as e:
        return "not a valid PSBT: {}".format(e)
    return None


_VALIDATORS["bitcoin psbt"] = validate_bitcoin_psbt


# ── bitcoin transaction ───────────────────────────────────────────────────────

def validate_bitcoin_transaction(contents: str) -> Optional[str]:
    """Validate CONTENTS as a hex-encoded Bitcoin transaction."""
    try:
        Transaction.from_string(contents)
    except Exception as e:
        return "not a valid transaction: {}".format(e)
    return None


_VALIDATORS["bitcoin transaction"] = validate_bitcoin_transaction


# ── bitcoin output script descriptor ─────────────────────────────────────────

def validate_bitcoin_descriptor(contents: str) -> Optional[str]:
    """Validate CONTENTS as an output script descriptor (BIP-380).

    embit.descriptor.Descriptor.from_string parses the descriptor
    grammar itself but doesn't verify a trailing #checksum matches, so
    that's checked here explicitly when one is present.
    """
    if "#" in contents:
        body, _, given_checksum = contents.partition("#")
        expected_checksum = descriptor_checksum(body)
        if given_checksum != expected_checksum:
            return "checksum mismatch: expected #{}".format(expected_checksum)

    try:
        Descriptor.from_string(contents)
    except Exception as e:
        return "not a valid output descriptor: {}".format(e)
    return None


_VALIDATORS["bitcoin output script descriptor"] = validate_bitcoin_descriptor


# ── bitcoin miniscript ────────────────────────────────────────────────────────

def validate_bitcoin_miniscript(contents: str) -> Optional[str]:
    """Validate CONTENTS as a miniscript expression.

    A standalone miniscript must be usable as a top-level spending
    script, which requires embit's inferred type to be B (Base) --
    e.g. a v: or n:-wrapped fragment alone isn't a complete script.
    """
    try:
        ms = Miniscript.from_string(contents)
    except Exception as e:
        return "not a valid miniscript: {}".format(e)
    if ms.type != "B":
        return "top-level miniscript must have type B (Base), got type {}".format(ms.type)
    return None


_VALIDATORS["bitcoin miniscript"] = validate_bitcoin_miniscript


def validate_triples(triples: List[Triple]) -> Optional[str]:
    """Validate TYPE\\0NAME\\0CONTENTS\\0 triples against the record spec.

    Returns None if every triple is compliant, else a human-readable
    error string for the first non-compliant one.
    """
    for rtype, name, contents in triples:
        if rtype not in ACCEPTED_TYPES:
            return "Unrecognized TYPE {!r}".format(rtype)
        if not name:
            return "Empty NAME for TYPE {!r}".format(rtype)
        if not contents:
            return "Empty CONTENTS for TYPE {!r} NAME {!r}".format(rtype, name)

        validator = _VALIDATORS.get(rtype)
        if validator is not None:
            err = validator(contents)
            if err is not None:
                return "Invalid {} CONTENTS for NAME {!r}: {}".format(rtype, name, err)
    return None
