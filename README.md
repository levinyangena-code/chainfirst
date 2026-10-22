from decimal import Decimal

import pytest

from chainfirst.core import analyze_event, normalize_address, validate_amount


def test_normalize_address_evm_like_value():
    assert normalize_address(" 0xAbCdEf1234567890ABCDEF1234567890ABCDEF12 ") == "0xabcdef1234567890abcdef1234567890abcdef12"


def test_normalize_address_rejects_invalid_hex():
    with pytest.raises(ValueError):
        normalize_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")


def test_validate_amount_rejects_non_positive():
    with pytest.raises(ValueError):
        validate_amount("0")


def test_analyze_event_is_high_risk_for_large_transfer():
    summary = analyze_event(
        source_wallet="0xAbCdEf1234567890ABCDEF1234567890ABCDEF12",
        destination_wallet="0x1234567890ABCDEF1234567890ABCDEF12345678",
        amount="25000",
        suspicious_labels=["rapid-transfer"],
    )
    assert summary["is_high_risk"] is True
    assert summary["risk_score"] >= 70
    assert summary["source"] == "0xabcdef1234567890abcdef1234567890abcdef12"
