from __future__ import annotations

import argparse
import json

from .core import analyze_event


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Victim-first tracing and incident summary utility.")
    parser.add_argument("--source", required=True, help="The victim or source wallet address.")
    parser.add_argument("--destination", required=True, help="The destination wallet address.")
    parser.add_argument("--amount", required=True, help="Transaction amount to assess.")
    parser.add_argument(
        "--risk-label",
        action="append",
        default=[],
        help="Add a suspicious label such as 'rapid-transfer' or 'peel-chain'.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    summary = analyze_event(
        source_wallet=args.source,
        destination_wallet=args.destination,
        amount=args.amount,
        suspicious_labels=args.risk_label,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
