#! /usr/bin/env python3
from centurymetadata import validate

# ── bitcoin wallet labels (BIP-329) ──────────────────────────────────────────

VALID_TXID = "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd"
VALID_ADDR = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c"
VALID_PUBKEY = "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448"
VALID_XPUB = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8Nq"
              "twybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")


def test_bip329_spec_test_vector_is_valid() -> None:
    # Verbatim from BIP-329's own test vectors section.
    lines = "\n".join([
        '{{ "type": "tx", "ref": "{}", "label": "Transaction", "origin": "wpkh([d34db33f/84\'/0\'/0\'])" }}'.format(VALID_TXID),
        '{{ "type": "addr", "ref": "{}", "label": "Address" }}'.format(VALID_ADDR),
        '{{ "type": "pubkey", "ref": "{}", "label": "Public Key" }}'.format(VALID_PUBKEY),
        '{{ "type": "input", "ref": "{}:0", "label": "Input" }}'.format(VALID_TXID),
        '{{ "type": "output", "ref": "{}:1", "label": "Output", "spendable": false }}'.format(VALID_TXID),
        '{{ "type": "xpub", "ref": "{}", "label": "Extended Public Key" }}'.format(VALID_XPUB),
    ])
    assert validate.validate_bip329_labels(lines) is None


def test_bip329_rejects_bad_json() -> None:
    assert validate.validate_bip329_labels('{not valid json') is not None


def test_bip329_rejects_non_object() -> None:
    assert validate.validate_bip329_labels('["type", "tx"]') is not None


def test_bip329_rejects_missing_fields() -> None:
    assert validate.validate_bip329_labels('{"type": "tx"}') is not None
    assert validate.validate_bip329_labels('{"ref": "%s"}' % VALID_TXID) is not None


def test_bip329_rejects_unknown_type() -> None:
    assert validate.validate_bip329_labels('{"type": "bogus", "ref": "x"}') is not None


def test_bip329_rejects_bad_txid() -> None:
    assert validate.validate_bip329_labels('{"type": "tx", "ref": "deadbeef"}') is not None


def test_bip329_rejects_bad_addr() -> None:
    assert validate.validate_bip329_labels('{"type": "addr", "ref": "not-an-address"}') is not None


def test_bip329_rejects_bad_pubkey() -> None:
    assert validate.validate_bip329_labels('{"type": "pubkey", "ref": "1234"}') is not None


def test_bip329_rejects_bad_input_output_ref() -> None:
    assert validate.validate_bip329_labels('{"type": "input", "ref": "%s"}' % VALID_TXID) is not None
    assert validate.validate_bip329_labels('{"type": "output", "ref": "notatxid:0"}') is not None


def test_bip329_rejects_xprv_as_xpub() -> None:
    # A real, valid BIP-32 extended *private* key (from embit.bip32.HDKey.from_seed).
    xprv = ("xprv9s21ZrQH143K2Jgq9GCETH5m5V6fzA9dr1yG5mQ2mKzQUr8Ssrw5Rj629Lx"
            "Xid8btoM3RAetKqFu3YZLY6cZAxvssDoaGAgXG4zs3gsj9E9")
    assert validate.validate_bip329_labels('{"type": "xpub", "ref": "%s"}' % xprv) is not None


def test_bip329_rejects_spendable_on_wrong_type() -> None:
    assert validate.validate_bip329_labels(
        '{"type": "addr", "ref": "%s", "spendable": true}' % VALID_ADDR) is not None


def test_bip329_rejects_non_bool_spendable() -> None:
    assert validate.validate_bip329_labels(
        '{"type": "output", "ref": "%s:0", "spendable": "yes"}' % VALID_TXID) is not None


def test_bip329_rejects_bad_origin() -> None:
    assert validate.validate_bip329_labels(
        '{"type": "tx", "ref": "%s", "origin": "not a descriptor"}' % VALID_TXID) is not None


def test_bip329_accepts_nested_origin() -> None:
    assert validate.validate_bip329_labels(
        '{{"type": "tx", "ref": "{}", "origin": "sh(wpkh([d34db33f/49\'/0\'/0\']))"}}'.format(VALID_TXID)
    ) is None


def test_bip329_ignores_blank_lines() -> None:
    assert validate.validate_bip329_labels(
        '{{"type": "tx", "ref": "{}"}}\n\n'.format(VALID_TXID)
    ) is None


# ── bitcoin psbt ──────────────────────────────────────────────────────────────

def _make_psbt() -> str:
    from embit.psbt import PSBT
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    tx = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(100000, Script(bytes.fromhex('0014' + '00' * 20)))],
    )
    return PSBT(tx).to_string()


def test_psbt_valid_accepted() -> None:
    assert validate.validate_bitcoin_psbt(_make_psbt()) is None


def test_psbt_rejects_garbage() -> None:
    assert validate.validate_bitcoin_psbt("not a psbt at all") is not None


def test_psbt_rejects_non_base64() -> None:
    assert validate.validate_bitcoin_psbt("!!!not-base64!!!") is not None


def test_psbt_rejects_wrong_magic() -> None:
    import base64
    assert validate.validate_bitcoin_psbt(
        base64.b64encode(b'notpsbt!' + bytes(20)).decode()
    ) is not None


def test_psbt_rejects_truncated() -> None:
    valid = _make_psbt()
    assert validate.validate_bitcoin_psbt(valid[:len(valid) // 2]) is not None


# ── bitcoin transaction ───────────────────────────────────────────────────────

def _make_tx_hex() -> str:
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    tx = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(100000, Script(bytes.fromhex('0014' + '00' * 20)))],
    )
    return tx.serialize().hex()


def test_transaction_valid_accepted() -> None:
    assert validate.validate_bitcoin_transaction(_make_tx_hex()) is None


def test_transaction_rejects_non_hex() -> None:
    assert validate.validate_bitcoin_transaction("not hex at all") is not None


def test_transaction_rejects_truncated() -> None:
    assert validate.validate_bitcoin_transaction("deadbeef") is not None


# ── bitcoin output script descriptor ─────────────────────────────────────────

def _make_descriptor() -> str:
    from embit.descriptor.checksum import add_checksum
    body = "wpkh([d34db33f/84h/0h/0h]{}/0/*)".format(VALID_XPUB)
    return add_checksum(body)


def test_descriptor_valid_accepted() -> None:
    assert validate.validate_bitcoin_descriptor(_make_descriptor()) is None


def test_descriptor_valid_without_checksum_accepted() -> None:
    body = _make_descriptor().split("#")[0]
    assert validate.validate_bitcoin_descriptor(body) is None


def test_descriptor_rejects_bad_checksum() -> None:
    body, _, _ = _make_descriptor().partition("#")
    assert validate.validate_bitcoin_descriptor(body + "#00000000") is not None


def test_descriptor_rejects_garbage() -> None:
    assert validate.validate_bitcoin_descriptor("not a descriptor at all") is not None


def test_descriptor_rejects_malformed_grammar() -> None:
    assert validate.validate_bitcoin_descriptor("wpkh(not-a-key)") is not None


def test_transaction_rejects_trailing_garbage() -> None:
    assert validate.validate_bitcoin_transaction(_make_tx_hex() + "ff") is not None
