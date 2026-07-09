"""Content-compliance validation for the test server.

Enforces the record spec documented in README.md: TYPE must be one of
the five accepted literal strings, and CONTENTS must be valid for that
type. Real per-type CONTENTS validators are registered in _VALIDATORS
as they're implemented; a type with no registered validator still gets
the baseline TYPE/NAME/CONTENTS checks below.
"""
from typing import Callable, Dict, List, Optional, Tuple

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
