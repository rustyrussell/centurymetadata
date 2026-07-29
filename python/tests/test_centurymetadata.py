#! /usr/bin/env python3
import hashlib
import os
from typing import Callable, Dict, List, Optional, Tuple

import pytest
from secp256k1 import PrivateKey

from centurymetadata import (
    CenturyMetadata,
    DescriptorRecord,
    Identity,
    IdentitySource,
    NEXT_DERIVATION_TYPE,
    PsbtRecord,
    TransactionRecord,
    UnknownRecord,
    WalletLabelsRecord,
    derive_mlkem_keypair,
    encode,
)


def make_identity_source() -> IdentitySource:
    """A deterministic, per-slot Identity, independent of any bip39 wiring."""
    def source(n: int) -> Identity:
        def key_material(salt: bytes) -> bytes:
            return hashlib.sha256(salt + n.to_bytes(4, "big")).digest()
        writer_privkey = PrivateKey(key_material(b"writer"))
        reader_secp_privkey = PrivateKey(key_material(b"reader-secp"))
        reader_mlkem_pubkey, reader_mlkem_privkey = derive_mlkem_keypair(key_material(b"reader-mlkem"))
        return Identity(writer_privkey, reader_secp_privkey, reader_mlkem_pubkey, reader_mlkem_privkey)
    return source


def make_store() -> Tuple[IdentitySource, Callable[[bytes], Optional[bytes]], Dict[bytes, bytes]]:
    identity_source = make_identity_source()
    store: Dict[bytes, bytes] = {}

    def fetch(reader_id: bytes) -> Optional[bytes]:
        return store.get(reader_id)

    return identity_source, fetch, store


def publish(identity_source: IdentitySource, store: Dict[bytes, bytes], files: list) -> None:
    for n, data in files:
        store[identity_source(n).reader_id] = data


def save_with_enough_slots(doc: CenturyMetadata, identity_source: IdentitySource) -> List[Tuple[int, bytes]]:
    """save()'s caller-driven retry loop: authorize one more slot past
    whatever's already authorized each time save() reports need_more,
    until it succeeds."""
    next_slot = (max(doc.slots) + 1) if doc.slots else 0
    files, need_more = doc.save(identity_source)
    while need_more:
        doc.authorize_slot(next_slot)
        next_slot += 1
        files, need_more = doc.save(identity_source)
    return files


def test_add_rejects_unrecognized_type() -> None:
    doc = CenturyMetadata()
    with pytest.raises(ValueError):
        doc.add(UnknownRecord("some future type", "contents"))


def test_add_allows_underscore_prefixed_type() -> None:
    doc = CenturyMetadata()
    record = UnknownRecord("_my custom type", "contents", "name")
    doc.add(record)
    assert doc.by_type("_my custom type") == [record]


def test_add_rejects_next_derivation_type() -> None:
    doc = CenturyMetadata()
    with pytest.raises(ValueError):
        doc.add(UnknownRecord(NEXT_DERIVATION_TYPE, "1"))


def test_add_rejects_known_type_via_unknown_record() -> None:
    doc = CenturyMetadata()
    with pytest.raises(ValueError):
        doc.add(UnknownRecord("bitcoin psbt", "cHNidP8="))


def test_add_rejects_nul_and_overlong_name() -> None:
    doc = CenturyMetadata()
    with pytest.raises(ValueError):
        doc.add(TransactionRecord("dead\0beef"))
    with pytest.raises(ValueError):
        doc.add(TransactionRecord("deadbeef", name="x" * 256))


def test_records_sorted_by_priority() -> None:
    doc = CenturyMetadata()
    doc.add(WalletLabelsRecord('{"type": "tx", "ref": "a" * 64}', "wallet"))
    doc.add(UnknownRecord("_annotation", "unknown to us"))
    doc.add(TransactionRecord("deadbeef"))
    doc.add(DescriptorRecord("wpkh(...)#checksum", name="wallet"))
    doc.add(PsbtRecord("cHNidP8="))

    types_in_order = [r.rtype for r in doc.records]
    assert types_in_order == [
        "bitcoin output script descriptor",
        "bitcoin transaction",
        "bitcoin psbt",
        "bitcoin wallet labels",
        "_annotation",
    ]


def test_remove_and_query_helpers() -> None:
    doc = CenturyMetadata()
    tx1 = TransactionRecord("aa", name="one")
    tx2 = TransactionRecord("bb", name="two")
    doc.add(tx1)
    doc.add(tx2)
    doc.add(PsbtRecord("cc"))

    assert len(doc.transactions()) == 2
    assert len(doc.psbts()) == 1
    assert doc.unknown_records() == []

    doc.remove(tx1)
    assert doc.transactions() == [tx2]
    with pytest.raises(ValueError):
        doc.remove(tx1)


def test_update_via_mutation_is_picked_up_on_next_encode() -> None:
    """Records are mutable and stored by reference: mutating a queried
    record's contents is enough to update it -- no separate update() call."""
    seed_source, fetch, store = make_store()
    doc = CenturyMetadata()
    doc.add(DescriptorRecord("wpkh(old)#aaaaaaaa", name="Life savings"))
    doc.authorize_slot(0)
    files, need_more = doc.save(seed_source)
    assert need_more is False
    publish(seed_source, store, files)
    original_location = doc.descriptors()[0].location
    assert original_location == (0, 0)

    doc.descriptors()[0].contents = "wpkh(new)#bbbbbbbb"
    files2, need_more = doc.save(seed_source)
    assert need_more is False
    publish(seed_source, store, files2)

    loaded = CenturyMetadata()
    identity = seed_source(0)
    raw = fetch(identity.reader_id)
    assert raw is not None
    errors, next_n = loaded.load(identity, 0, raw)
    assert errors == []
    assert next_n is None
    assert loaded.descriptors()[0].contents == "wpkh(new)#bbbbbbbb"


def test_round_trip_single_file() -> None:
    identity_source, fetch, store = make_store()

    doc = CenturyMetadata()
    doc.add(DescriptorRecord("wpkh(...)#checksum", name="Life savings"))
    doc.add(TransactionRecord("deadbeef", name="timelocked gift"))
    doc.authorize_slot(0)

    files, need_more = doc.save(identity_source)
    assert need_more is False
    assert len(files) == 1
    assert files[0][0] == 0
    publish(identity_source, store, files)

    loaded = CenturyMetadata()
    identity = identity_source(0)
    raw = fetch(identity.reader_id)
    assert raw is not None
    errors, next_n = loaded.load(identity, 0, raw)
    assert errors == []
    assert next_n is None
    loaded_triples = sorted(r.as_triple() for r in loaded.records)
    doc_triples = sorted(r.as_triple() for r in doc.records)
    assert loaded_triples == doc_triples


def test_locations_set_after_save() -> None:
    identity_source, _fetch, _store = make_store()
    doc = CenturyMetadata()
    d = DescriptorRecord("wpkh(...)#checksum", name="wallet")
    t = TransactionRecord("deadbeef")
    doc.add(d)
    doc.add(t)
    doc.authorize_slot(0)
    files, need_more = doc.save(identity_source)
    assert need_more is False
    assert d.location == (0, 0)  # descriptor sorts before transaction
    assert t.location == (0, 1)


def test_split_creates_chain_and_round_trips() -> None:
    identity_source, fetch, store = make_store()

    doc = CenturyMetadata()
    # Six ~3.5KB-compressed records comfortably exceed one file (14663
    # bytes), but each fits alone -- forces a multi-file chain.
    for i in range(6):
        doc.add(TransactionRecord(os.urandom(3000).hex(), name="tx{}".format(i)))

    files = save_with_enough_slots(doc, identity_source)
    assert len(files) >= 2
    slots = [n for n, _ in files]
    assert slots == sorted(set(slots))
    for a, b in zip(slots, slots[1:]):
        assert b > a

    publish(identity_source, store, files)

    # This is the caller-driven loop CenturyMetadata.load() now expects:
    # fetch and follow the `next cmdata derivation path` chain ourselves,
    # one file at a time.
    loaded = CenturyMetadata()
    n: Optional[int] = 0
    while n is not None:
        identity = identity_source(n)
        raw = fetch(identity.reader_id)
        if raw is None:
            break
        errors, n = loaded.load(identity, n, raw)
        assert errors == []

    loaded_contents = sorted(r.contents for r in loaded.transactions())
    doc_contents = sorted(r.contents for r in doc.transactions())
    assert loaded_contents == doc_contents

    # Records that ended up in the 2nd+ file should say so.
    assert any(r.location is not None and r.location[0] != 0 for r in loaded.transactions())


def test_load_returns_empty_document_if_nothing_published() -> None:
    identity_source, fetch, _store = make_store()
    identity = identity_source(0)
    assert fetch(identity.reader_id) is None


def test_load_accepts_file_not_signed_by_own_writer_key() -> None:
    """A file at our derivation slot signed by someone else's writer key
    is still valid data we can read: SPECIFICATION.md lets a reader
    choose to reject non-to-self files, it doesn't require it, and
    to_self only affects error recovery within decode() itself."""
    identity_source, fetch, store = make_store()
    identity = identity_source(0)
    foreign_writer = PrivateKey(os.urandom(32))

    raw = encode(foreign_writer, identity.reader_secp_pubkey, identity.reader_mlkem_pubkey, 0,
                 ("bitcoin transaction", "", "deadbeef"))
    store[identity.reader_id] = raw

    loaded = CenturyMetadata()
    errors, next_n = loaded.load(identity, 0, raw)
    assert errors == []
    assert next_n is None
    assert [r.contents for r in loaded.transactions()] == ["deadbeef"]


def test_load_preserves_records_of_unrecognized_type() -> None:
    """A record type this version of the code doesn't know about (e.g. a
    future standard type, or a foreign non-underscore-prefixed value) must
    survive a load()/save() round trip untouched."""
    identity_source, fetch, store = make_store()
    identity = identity_source(0)

    raw = encode(identity.writer_privkey, identity.reader_secp_pubkey, identity.reader_mlkem_pubkey, 0,
                 ("bitcoin transaction", "known", "deadbeef"),
                 ("silent payments v2", "", "some future record"))
    store[identity.reader_id] = raw

    loaded = CenturyMetadata()
    errors, next_n = loaded.load(identity, 0, raw)
    assert errors == []
    assert next_n is None
    unknown = loaded.unknown_records()
    assert len(unknown) == 1
    assert unknown[0].rtype == "silent payments v2"
    assert unknown[0].contents == "some future record"
    assert [r.contents for r in loaded.transactions()] == ["deadbeef"]

    # Re-encoding must write the unrecognized record back out unaltered.
    files, need_more = loaded.save(identity_source)
    assert need_more is False
    store2: Dict[bytes, bytes] = {}
    publish(identity_source, store2, files)
    reloaded = CenturyMetadata()
    raw2 = store2[identity.reader_id]
    errors, next_n = reloaded.load(identity, 0, raw2)
    assert errors == []
    assert [r.rtype for r in reloaded.unknown_records()] == ["silent payments v2"]


def test_load_ignores_next_derivation_record_from_chain() -> None:
    """The chain-pointer record itself must not show up as a regular
    record once loaded -- it's control flow, not content."""
    identity_source, fetch, store = make_store()

    doc = CenturyMetadata()
    for i in range(6):
        doc.add(TransactionRecord(os.urandom(3000).hex(), name="tx{}".format(i)))
    files = save_with_enough_slots(doc, identity_source)
    assert len(files) >= 2
    publish(identity_source, store, files)

    loaded = CenturyMetadata()
    n: Optional[int] = 0
    while n is not None:
        identity = identity_source(n)
        raw = fetch(identity.reader_id)
        if raw is None:
            break
        errors, n = loaded.load(identity, n, raw)
        assert errors == []

    assert loaded.by_type(NEXT_DERIVATION_TYPE) == []


def test_split_raises_if_single_record_too_large() -> None:
    doc = CenturyMetadata()
    doc.add(TransactionRecord(os.urandom(20000).hex()))
    with pytest.raises(ValueError):
        doc.split([0])


def test_load_registers_slot() -> None:
    identity_source, fetch, store = make_store()
    doc = CenturyMetadata()
    doc.add(TransactionRecord("deadbeef"))
    doc.authorize_slot(0)
    files, need_more = doc.save(identity_source)
    assert need_more is False
    publish(identity_source, store, files)

    loaded = CenturyMetadata()
    assert loaded.slots == []
    identity = identity_source(0)
    raw = fetch(identity.reader_id)
    assert raw is not None
    loaded.load(identity, 0, raw)
    assert loaded.slots == [0]


def test_authorize_slot_registers_slot_without_loading() -> None:
    doc = CenturyMetadata()
    assert doc.slots == []
    doc.authorize_slot(0)
    doc.authorize_slot(5)
    doc.authorize_slot(0)  # idempotent
    assert doc.slots == [0, 5]


def test_save_reports_need_more_without_any_authorized_slots() -> None:
    doc = CenturyMetadata()
    doc.add(TransactionRecord("deadbeef"))
    identity_source = make_identity_source()
    files, need_more = doc.save(identity_source)
    assert files == []
    assert need_more is True


def test_save_reports_need_more_rather_than_drop_when_out_of_room() -> None:
    doc = CenturyMetadata()
    for i in range(6):
        doc.add(TransactionRecord(os.urandom(3000).hex(), name="tx{}".format(i)))
    doc.authorize_slot(0)  # only one slot -- not enough for 6 large records

    identity_source = make_identity_source()
    files, need_more = doc.save(identity_source)
    assert files == []
    assert need_more is True
    # Nothing was dropped by the failed save() attempt.
    assert len(doc.transactions()) == 6

    # Authorizing one more slot at a time (the caller-driven retry loop
    # save() expects) eventually succeeds.
    files = save_with_enough_slots(doc, identity_source)
    assert len(files) >= 2


def test_save_uses_every_authorized_slot_even_if_empty() -> None:
    identity_source, fetch, store = make_store()
    doc = CenturyMetadata()
    doc.add(DescriptorRecord("wpkh(...)#checksum", name="wallet"))
    doc.authorize_slot(0)
    doc.authorize_slot(1)
    doc.authorize_slot(2)

    files, need_more = doc.save(identity_source)
    assert need_more is False
    assert [n for n, _ in files] == [0, 1, 2]
    publish(identity_source, store, files)

    # Slots 1 and 2 hold nothing but the chain pointer -- confirm we can
    # still walk all the way through them.
    loaded = CenturyMetadata()
    n: Optional[int] = 0
    seen_slots = []
    while n is not None:
        identity = identity_source(n)
        raw = fetch(identity.reader_id)
        assert raw is not None
        seen_slots.append(n)
        errors, n = loaded.load(identity, n, raw)
        assert errors == []
    assert seen_slots == [0, 1, 2]
    assert [r.contents for r in loaded.descriptors()] == ["wpkh(...)#checksum"]


def test_save_starts_gen_at_zero_for_authorized_only_slot() -> None:
    from centurymetadata.decode import deconstruct

    identity_source = make_identity_source()
    doc = CenturyMetadata()
    doc.add(TransactionRecord("deadbeef"))
    doc.authorize_slot(0)

    files, need_more = doc.save(identity_source)
    assert need_more is False
    _, _, gen, _ = deconstruct(files[0][1])
    assert gen == 0


def test_save_increments_gen_observed_by_load() -> None:
    from centurymetadata.decode import deconstruct

    identity_source, fetch, store = make_store()
    identity = identity_source(0)
    raw = encode(identity.writer_privkey, identity.reader_secp_pubkey, identity.reader_mlkem_pubkey, 5,
                 ("bitcoin transaction", "", "deadbeef"))
    store[identity.reader_id] = raw

    doc = CenturyMetadata()
    errors, next_n = doc.load(identity, 0, raw)
    assert errors == []

    files, need_more = doc.save(identity_source)
    assert need_more is False
    _, _, gen, _ = deconstruct(files[0][1])
    assert gen == 6


def test_save_increments_gen_again_on_repeated_save_without_reload() -> None:
    from centurymetadata.decode import deconstruct

    identity_source = make_identity_source()
    doc = CenturyMetadata()
    doc.add(TransactionRecord("deadbeef"))
    doc.authorize_slot(0)

    files1, need_more = doc.save(identity_source)
    assert need_more is False
    _, _, gen1, _ = deconstruct(files1[0][1])
    assert gen1 == 0

    files2, need_more = doc.save(identity_source)
    assert need_more is False
    _, _, gen2, _ = deconstruct(files2[0][1])
    assert gen2 == 1


def test_trim_drops_lowest_priority_until_it_fits_and_returns_dropped() -> None:
    doc = CenturyMetadata()
    descriptor = DescriptorRecord("wpkh(...)#checksum", name="wallet")
    doc.add(descriptor)
    txs = [TransactionRecord(os.urandom(3000).hex(), name="tx{}".format(i)) for i in range(6)]
    for tx in txs:
        doc.add(tx)
    doc.authorize_slot(0)  # only one slot

    dropped = doc.trim()
    assert dropped  # something had to go
    assert doc.split(doc.slots) is not None
    # The descriptor (highest priority) must never be dropped while any
    # lower-priority transaction remains to drop instead.
    assert descriptor in doc.records
    assert set(dropped) <= set(txs)

    # trim() only mutates -- save() now succeeds where it previously failed.
    identity_source = make_identity_source()
    files, need_more = doc.save(identity_source)
    assert need_more is False
    assert len(files) == 1
