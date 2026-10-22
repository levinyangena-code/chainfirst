from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Iterable

_VALID_HEX = set("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class AddressRecord:
    """Normalized wallet data for incident analysis."""

    raw: str
    normalized: str
    is_probable_contract: bool = False


def normalize_address(address: str) -> str:
    """Normalize a wallet address while rejecting obvious invalid values.

    The initial repository was a bootstrap with no implementation. This helper
    keeps the logic deterministic, explicit, and safe for downstream analysis.
    """
    if not isinstance(address, str):
        raise TypeError("address must be a string")

    cleaned = address.strip()
    if not cleaned:
        raise ValueError("address cannot be empty")

    if cleaned.lower().startswith("0x"):
        body = cleaned[2:]
        if len(body) != 40:
            raise ValueError("Ethereum-like addresses must have 40 hexadecimal characters after 0x")
        if any(ch not in _VALID_HEX for ch in body):
            raise ValueError("Ethereum-like addresses must contain only hexadecimal digits")
        return "0x" + body.lower()

    if len(cleaned) < 26 or len(cleaned) > 62:
        raise ValueError("address length is outside the expected wallet range")

    if any(not (ch.isalnum() or ch in "-_") for ch in cleaned):
        raise ValueError("address contains invalid characters")

    return cleaned


def validate_amount(amount: str | int | float | Decimal) -> Decimal:
    """Validate and normalize a numeric amount for incident summaries."""
    if isinstance(amount, Decimal):
        value = amount
    elif isinstance(amount, (int, float, str)):
        try:
            value = Decimal(str(amount))
        except (InvalidOperation, ValueError) as exc:  # pragma: no cover - defensive branch
            raise ValueError("amount must be a finite numeric value") from exc
    else:
        raise TypeError("amount must be numeric or a decimal-like string")

    if not value.is_finite():
        raise ValueError("amount must be finite")
    if value <= 0:
        raise ValueError("amount must be greater than zero")
    return value


def analyze_event(
    source_wallet: str,
    destination_wallet: str,
    amount: str | int | float | Decimal,
    suspicious_labels: Iterable[str] | None = None,
) -> dict:
    """Create a compact, typed summary for a suspected theft event."""
    source = AddressRecord(raw=source_wallet, normalized=normalize_address(source_wallet))
    destination = AddressRecord(raw=destination_wallet, normalized=normalize_address(destination_wallet))
    value = validate_amount(amount)

    labels = tuple((suspicious_labels or ()))
    risk = 15
    if labels:
        risk += len(labels) * 15
    if value > Decimal("10000"):
        risk += 20
    if source.normalized == destination.normalized:
        risk += 10

    risk = max(0, min(risk, 100))

    return {
        "source": source.normalized,
        "destination": destination.normalized,
        "amount": str(value),
        "risk_score": risk,
        "is_high_risk": risk >= 70,
        "evidence_labels": list(labels),
    }
