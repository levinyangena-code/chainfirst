"""ChainFirst package.

This lightweight project provides a safe-by-default toolkit for tracing and
summarizing crypto incident data without requiring external network access.
"""

from .core import AddressRecord, analyze_event, normalize_address, validate_amount

__all__ = [
    "AddressRecord",
    "analyze_event",
    "normalize_address",
    "validate_amount",
]
