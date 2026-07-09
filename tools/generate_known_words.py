#!/usr/bin/env python3
"""Regenerate python/centurymetadata/server/known_words.txt.

The list of "known" words (those whose 12x-repeated BIP-39 mnemonic
happens to checksum) is a deterministic function of the public BIP-39
wordlist, but is checked in rather than recomputed by known_keys.py so
it can double as a small, stable, publishable reference for people
testing their own implementation against the test server.

Run from the python/ subdirectory (which has the venv and dependencies):

    cd python && uv run python3 ../tools/generate_known_words.py
"""
import sys
from pathlib import Path

from centurymetadata.bip39 import WORDLIST, checksum_valid

REPO_ROOT = Path(__file__).parent.parent
WORDS_PATH = REPO_ROOT / "python" / "centurymetadata" / "server" / "known_words.txt"


if __name__ == "__main__":
    words = [word for word in WORDLIST if checksum_valid([word] * 12)]
    WORDS_PATH.write_text("\n".join(words) + "\n")
    print(f"Wrote {len(words)} known words to {WORDS_PATH}", file=sys.stderr)
