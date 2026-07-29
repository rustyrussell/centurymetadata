"""The CenturyMetadata class: a high-level, mutable collection of records.

Wraps the low-level compress/encode/decode primitives with the
bookkeeping SPECIFICATION.md expects of a writer: keeping records in
priority order, splitting an oversized record set across a chain of
files linked by `next cmdata derivation path` records, and preserving
records of a TYPE this code doesn't recognize across a read-modify-write
round trip.
"""
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Type

from secp256k1 import PrivateKey, PublicKey

from .constants import PLAINTEXT_LENGTH
from .decode import decode, deconstruct, CMDataError
from .encode import compress, encode, get_reader_id

Triple = Tuple[str, str, str]

NEXT_DERIVATION_TYPE = "next cmdata derivation path"


class Identity:
    """All the keys needed to write, and to read back, one derivation slot N.

    How these are derived (e.g. from a BIP-39 seed, or a hardware
    device) is deliberately outside this module's concern: build an
    IdentitySource however suits the caller.
    """

    def __init__(self, writer_privkey: PrivateKey, reader_secp_privkey: PrivateKey,
                 reader_mlkem_pubkey: bytes, reader_mlkem_privkey: bytes) -> None:
        self.writer_privkey = writer_privkey
        self.reader_secp_privkey = reader_secp_privkey
        self.reader_mlkem_pubkey = reader_mlkem_pubkey
        self.reader_mlkem_privkey = reader_mlkem_privkey

    @property
    def reader_secp_pubkey(self) -> PublicKey:
        return self.reader_secp_privkey.pubkey

    @property
    def reader_id(self) -> bytes:
        return get_reader_id(self.reader_secp_pubkey, self.reader_mlkem_pubkey)


IdentitySource = Callable[[int], Identity]


class Record:
    """One centurymetadata record: a TYPE\\0NAME\\0CONTENTS\\0 tuple, plus
    the bookkeeping CenturyMetadata needs. Use a subclass (PsbtRecord,
    TransactionRecord, DescriptorRecord, WalletLabelsRecord), or
    UnknownRecord for a TYPE this implementation doesn't recognize.
    """

    def __init__(self, contents: str, name: str = "") -> None:
        self.contents = contents
        self.name = name
        # (slot_n, index within that file's records), identifying where
        # this record currently lives -- set by CenturyMetadata.load()
        # and CenturyMetadata.save(). None if never read or written.
        self.location: Optional[Tuple[int, int]] = None

    @property
    def rtype(self) -> str:
        raise NotImplementedError

    def as_triple(self) -> Triple:
        return (self.rtype, self.name, self.contents)

    def __repr__(self) -> str:
        return "{}(name={!r}, contents={!r})".format(
            type(self).__name__, self.name, self.contents[:40])


class PsbtRecord(Record):
    @property
    def rtype(self) -> str:
        return "bitcoin psbt"


class TransactionRecord(Record):
    @property
    def rtype(self) -> str:
        return "bitcoin transaction"


class DescriptorRecord(Record):
    @property
    def rtype(self) -> str:
        return "bitcoin output script descriptor"


class WalletLabelsRecord(Record):
    def __init__(self, contents: str, name: str) -> None:
        # CMDATA-SPEC:
        # - MUST set `NAME` to match the name of the wallet these labels apply to.
        super().__init__(contents, name)

    @property
    def rtype(self) -> str:
        return "bitcoin wallet labels"


class UnknownRecord(Record):
    """A record of a TYPE this implementation doesn't recognize: either a
    foreign/future type read back from a file (preserved untouched), or
    a new non-standard type of our own (which SPECIFICATION.md requires
    to start with '_')."""

    def __init__(self, rtype: str, contents: str, name: str = "") -> None:
        super().__init__(contents, name)
        self._rtype = rtype

    @property
    def rtype(self) -> str:
        return self._rtype


_TYPE_TO_CLASS: Dict[str, Type[Record]] = {
    "bitcoin psbt": PsbtRecord,
    "bitcoin transaction": TransactionRecord,
    "bitcoin output script descriptor": DescriptorRecord,
    "bitcoin wallet labels": WalletLabelsRecord,
}

# CMDATA-SPEC/Suggested Type Priorities:
# 1. `next cmdata derivation path`.  This doesn't take up much space, omitting this means truncating data, and so it
#    gains more space than it takes.
# 2. `bitcoin output script descriptor`.  This is the wallet definition itself, though if the wallet contains no
#    funds and has issued no addresses, it could be omitted.
# 3. `bitcoin transaction` and `bitcoin psbt`.  This may be omitted if it does not deliver funds to the wallet
#    itself, or is invalid (i.e. spending long-spent outputs).
# 4. `bitcoin wallet labels`.  This is the lowest priority, but may be *reduced* if necessary by omitting some
#    labels.  How to choose which to omit is currently an exercise for the reader.
# 5. Other types.  Without other knowledge, we assume these are mere annotations and so are least important.
_PRIORITY = {
    NEXT_DERIVATION_TYPE: 0,
    "bitcoin output script descriptor": 1,
    "bitcoin transaction": 2,
    "bitcoin psbt": 2,
    "bitcoin wallet labels": 3,
}
_UNKNOWN_PRIORITY = 4


def _priority(record: Record) -> int:
    return _PRIORITY.get(record.rtype, _UNKNOWN_PRIORITY)


def _sorted_records(records: List[Record]) -> List[Record]:
    # CMDATA-SPEC/Writer Requirements:
    # - MUST write tuples in decreasing priority order (see [Suggested Type Priorities](#suggested-type-priorities)).
    indexed = list(enumerate(records))
    indexed.sort(key=lambda item: (_priority(item[1]), item[0]))
    return [rec for _, rec in indexed]


def _fits_triples(triples: List[Triple]) -> bool:
    return len(compress(triples)) <= PLAINTEXT_LENGTH


def _common_prefix_bits(a: bytes, b: bytes) -> int:
    """Number of leading bits shared between a and b."""
    count = 0
    for x, y in zip(a, b):
        if x == y:
            count += 8
            continue
        count += 8 - (x ^ y).bit_length()
        break
    return count


def _record_for_triple(rtype: str, name: str, contents: str) -> Record:
    cls = _TYPE_TO_CLASS.get(rtype)
    if cls is not None:
        return cls(contents, name)
    return UnknownRecord(rtype, contents, name)


class CenturyMetadata:
    """An ordered collection of centurymetadata records.

    Handles the parts of SPECIFICATION.md that a raw list of triples
    doesn't: writing records back out in priority order, splitting an
    oversized set across a chain of files, and round-tripping records
    of an unrecognized TYPE unchanged.
    """

    def __init__(self, records: Optional[List[Record]] = None) -> None:
        self._records: List[Record] = list(records) if records else []
        # Derivation slots this document is known to occupy: from load()
        # (a file we successfully fetched there, whatever it contained)
        # and authorize_slot() (a slot we've paid for but not
        # fetched/used yet). save() writes to exactly this set of slots.
        self._slots: Set[int] = set()
        # GEN last observed (via load()) or last written (via save()) at
        # each slot. A slot with no entry here has never been loaded or
        # saved, so save() starts it at GEN 0.
        self._gens: Dict[int, int] = {}

    def authorize_slot(self, n: int) -> None:
        """Register derivation slot `n` as one we're currently authorized
        to write to (e.g. just paid for), even with nothing loaded for
        it yet. save() must use every such slot: chaining through it is
        the only record we have that it was ever authorized."""
        self._slots.add(n)

    @property
    def slots(self) -> List[int]:
        """Derivation slots this document currently knows about (from
        load() and authorize_slot()), in ascending order -- the fixed set
        save() writes into."""
        return sorted(self._slots)

    def next_slot(self, identity_source: IdentitySource, match_bits: int = 10,
                  timeout: float = 1.0) -> int:
        """Pick a derivation slot index not already in `slots`, suitable
        for authorize_slot(): one whose READER_ID shares its leading
        `match_bits` bits with slot 0's, so it's likely to land in the
        same server-side fetch bundle as the rest of the chain.

        Grinds candidate indices upward from max(slots) + 1 (or 0, for
        the very first slot -- which trivially matches itself) until it
        finds one, or until `timeout` seconds have elapsed, whichever
        comes first. On timeout, returns the candidate that got closest
        (the longest matching prefix seen), not just the last one tried:
        still not guaranteed to share slot 0's bundle, but the best
        available for that."""
        target = identity_source(0).reader_id
        n = max(self._slots) + 1 if self._slots else 0
        deadline = time.monotonic() + timeout
        best_n, best_bits = n, -1
        while True:
            if n not in self._slots:
                common = _common_prefix_bits(identity_source(n).reader_id, target)
                # CMDATA-SPEC:
                # - SHOULD choose the next `N` such that the reader key has a similar prefix.
                if common >= match_bits:
                    return n
                if common > best_bits:
                    best_n, best_bits = n, common
            if time.monotonic() >= deadline:
                return best_n
            n += 1

    def add(self, record: Record) -> None:
        if record.rtype == NEXT_DERIVATION_TYPE:
            raise ValueError(
                "{!r} records are generated automatically by save()".format(NEXT_DERIVATION_TYPE))
        known_cls = _TYPE_TO_CLASS.get(record.rtype)
        if known_cls is not None and not isinstance(record, known_cls):
            raise ValueError("Use {} for TYPE {!r}, not {}".format(
                known_cls.__name__, record.rtype, type(record).__name__))
        # CMDATA-SPEC/Writer Requirements:
        # - If it uses a `TYPE` not defined in this specification:
        #   - MUST begin the type string with `_`.
        if known_cls is None and not record.rtype.startswith('_'):
            raise ValueError(
                "Unrecognized TYPE {!r}: types not in SPECIFICATION.md must start with '_'".format(record.rtype))
        # CMDATA-SPEC/Writer Requirements:
        # - MUST only use valid [UTF-8](#ref-utf-8) strings without NULs for `TYPE`, `NAME` and `CONTENTS`.
        for field, value in (("TYPE", record.rtype), ("NAME", record.name), ("CONTENTS", record.contents)):
            if '\0' in value:
                raise ValueError("{} must not contain a NUL character".format(field))
        # CMDATA-SPEC/Writer Requirements:
        # - MUST limit `NAME` fields to 255 bytes.
        if len(record.name.encode('utf8')) > 255:
            raise ValueError("NAME must be at most 255 bytes")
        self._add(record)

    def _add(self, record: Record) -> None:
        """Append a record without validation -- trusted callers (load()) only."""
        self._records.append(record)

    def remove(self, record: Record) -> None:
        self._records.remove(record)

    def by_type(self, rtype: str) -> List[Record]:
        return [r for r in self._records if r.rtype == rtype]

    def psbts(self) -> List[PsbtRecord]:
        return [r for r in self._records if isinstance(r, PsbtRecord)]

    def transactions(self) -> List[TransactionRecord]:
        return [r for r in self._records if isinstance(r, TransactionRecord)]

    def descriptors(self) -> List[DescriptorRecord]:
        return [r for r in self._records if isinstance(r, DescriptorRecord)]

    def wallet_labels(self) -> List[WalletLabelsRecord]:
        return [r for r in self._records if isinstance(r, WalletLabelsRecord)]

    def unknown_records(self) -> List[UnknownRecord]:
        return [r for r in self._records if isinstance(r, UnknownRecord)]

    @property
    def records(self) -> List[Record]:
        """All records, in the priority order SPECIFICATION.md requires writers to use."""
        return _sorted_records(self._records)

    def split(self, slots: List[int]) -> Optional[List[List[Record]]]:
        """Pack records (in priority order) into at most len(slots) chunks,
        one per entry of `slots` in order: a chunk that isn't landing on
        the last of `slots` reserves the exact real `next cmdata
        derivation path` CONTENTS for the slot after it, since save()
        chains through every one of `slots` regardless of whether
        content needs it -- a chunk isn't reservation-free just because
        there's nothing left to put in the next one, only the chunk
        landing on the last of `slots` truly needs none.

        Returns None if the records don't fit even using every slot in
        `slots`. This deliberately doesn't say how many more would be
        needed: the real CONTENTS of a slot beyond `slots` isn't known
        yet, and there's no honest way to bound its worst-case
        compressed contribution ahead of time. DEFLATE's stored-block
        fallback only guarantees the compressed size of a whole block
        won't exceed storing it raw -- it says nothing about any one
        symbol's Huffman code length within a block that, overall, still
        compresses well (RFC 1951 allows up to 15 bits per symbol). So
        rather than reserve for a guess that a well-compressing block
        makes look safe until it isn't, the caller (save()/trim()) is
        expected to authorize_slot() one real slot and retry, at which point
        its real value is used exactly, not estimated.
        """
        remaining = _sorted_records(self._records)
        groups: List[List[Record]] = []
        for index in range(len(slots)):
            is_last = (index == len(slots) - 1)
            tail: List[Triple] = [] if is_last else [(NEXT_DERIVATION_TYPE, "", str(slots[index + 1]))]

            if _fits_triples([r.as_triple() for r in remaining] + tail):
                groups.append(remaining)
                return groups

            fitted: List[Record] = []
            for rec in remaining:
                trial = [r.as_triple() for r in fitted] + [rec.as_triple()] + tail
                if not _fits_triples(trial):
                    break
                fitted.append(rec)
            if not fitted:
                raise ValueError(
                    "Record too large to fit in a file even alone: {!r}".format(remaining[0]))
            if is_last:
                # Packed as tightly as this last slot allows and there's
                # still something left over: genuinely not enough slots,
                # not an oversized record (that would have raised above).
                return None
            groups.append(fitted)
            remaining = remaining[len(fitted):]

        # Only reachable if slots is empty: trivially fine if there was
        # nothing to write anyway, otherwise every record is unplaced.
        return None if remaining else groups

    def _encode_slots(self, identity_source: IdentitySource, slots: List[int], groups: List[List[Record]],
                      gen_for: Callable[[int], int]) -> List[Tuple[int, bytes]]:
        """Encode groups[i] into slots[i] for each i (same length, same
        order), chaining each non-final file to the next via a
        `next cmdata derivation path` record."""
        files: List[Tuple[int, bytes]] = []
        for i, (n, group) in enumerate(zip(slots, groups)):
            identity = identity_source(n)
            triples: List[Triple] = [r.as_triple() for r in group]
            if i + 1 < len(slots):
                triples.append((NEXT_DERIVATION_TYPE, "", str(slots[i + 1])))

            data = encode(identity.writer_privkey, identity.reader_secp_pubkey,
                          identity.reader_mlkem_pubkey, gen_for(n), *triples)
            files.append((n, data))
            for index, record in enumerate(group):
                record.location = (n, index)
        return files

    def save(self, identity_source: IdentitySource) -> Tuple[List[Tuple[int, bytes]], bool]:
        """Encode this document into exactly the chain of slots it already
        knows about -- from load() and authorize_slot() -- no more, no fewer.

        Returns (files, need_more). On success, files is the encoded
        chain and need_more is False. If the records need more files
        than there are authorized slots, nothing is encoded or written:
        files is [] and need_more is True -- call authorize_slot() to
        register another paid-for slot (or trim() to shed low-priority
        records instead), then save() again. This doesn't say how many
        more slots are needed; see split()'s docstring for why that
        can't be answered honestly ahead of knowing the real slot value.

        Every known slot gets written, even a trailing one with nothing
        left to put in it -- chaining through it is the only record we
        have that it was ever authorized.

        GEN increments automatically for each slot: one past whatever
        load() last observed there, or 0 for a slot only registered via
        authorize_slot(), never loaded. [NOTE: this will matter once
        save() only rewrites slots whose contents actually changed -- an
        unwritten slot's GEN must not move, and a rewritten one must
        still increment from what was last on file, not from what we
        happened to overwrite it with in memory.]
        """
        slots = self.slots
        groups = self.split(slots)
        if groups is None:
            return [], True
        groups += [[] for _ in range(len(slots) - len(groups))]

        # CMDATA-SPEC/Writer Requirements:
        # - If a previous file for this `WRITER_PUBKEY` and `READER_ID` exists:
        #   - MUST set `GEN` to a number greater than all previous such files.
        # - Otherwise:
        #   - SHOULD set `GEN` to 0.
        used_gens = {n: (self._gens[n] + 1 if n in self._gens else 0) for n in slots}

        files = self._encode_slots(identity_source, slots, groups, used_gens.__getitem__)
        self._gens.update(used_gens)
        return files, False

    def trim(self) -> List[Record]:
        """Drop the lowest-priority records (unknown types, then wallet
        labels, then transactions/psbts, then the descriptor) until what
        remains fits in the slots currently authorized (see
        authorize_slot() and load()), mutating self. Returns the records
        that were dropped, so the caller can tell the user what was omitted.

        Stops once nothing is left to drop, even if that's still over
        budget -- a subsequent save() will report need_more if so."""
        dropped: List[Record] = []
        while self.split(self.slots) is None and self._records:
            worst = _sorted_records(self._records)[-1]
            self.remove(worst)
            dropped.append(worst)
        return dropped

    def load(self, identity: Identity, n: int, raw: bytes) -> Tuple[List[CMDataError], Optional[int]]:
        """Decode one already-fetched century metadata file at derivation
        slot `n` into this document, using `identity` to decrypt it.

        This works for a file signed by any WRITER_PUBKEY, not just a
        to-self one: decode() itself already only relaxes error recovery
        (continuing past a malformed record instead of stopping) once the
        file turns out to be to-self.

        Returns (errors, next_n): `next_n` is the slot named by this
        file's `next cmdata derivation path` record, if any, else None.
        Fetching and the loop are the caller's responsibility -- so is
        deciding whether/how far to keep following a chain (e.g. via
        deconstruct() on `raw`, to see whether next_n came from a file we
        trust), e.g.:

            doc = CenturyMetadata()
            n: Optional[int] = start_n
            while n is not None:
                identity = identity_source(n)
                raw = fetch(identity.reader_id)
                if raw is None:
                    break
                errors, n = doc.load(identity, n, raw)
                if any(e.fatal for e in errors):
                    break
        """
        self._slots.add(n)
        # GEN sits outside the encrypted payload, so we can learn it even
        # if decode() below fails (wrong keys, bad signature, ...) --
        # save() needs it to keep GEN increasing on this slot. Only a
        # malformed preamble/length/WRITER_PUBKEY leaves it unreadable.
        try:
            _wkey, _reader_id, gen, _after_preamble = deconstruct(raw)
            self._gens[n] = gen
        except ValueError:
            pass

        errors, triples = decode(identity.reader_secp_privkey, identity.reader_mlkem_privkey,
                                 identity.reader_mlkem_pubkey, identity.writer_privkey.pubkey, raw)
        if any(e.fatal for e in errors):
            return errors, None

        next_n: Optional[int] = None
        index = 0
        for rtype, name, contents in triples:
            if rtype == NEXT_DERIVATION_TYPE:
                # CMDATA-SPEC:
                # - MUST NOT follow multiple `next cmdata derivation path` records in the same file.
                if next_n is not None:
                    continue
                # CMDATA-SPEC:
                # - MUST fail to parse the record if `CONTENTS` is not a valid decimal number, or is not greater than
                #   `N` for this file.
                if contents.isdigit() and int(contents) > n:
                    next_n = int(contents)
                continue
            # CMDATA-SPEC/Writer Requirements:
            # - If it has read tuples from a previous version of the file:
            #   - MUST write back all tuples which it did not deliberately remove or alter.
            record = _record_for_triple(rtype, name, contents)
            record.location = (n, index)
            self._add(record)
            index += 1

        return errors, next_n
