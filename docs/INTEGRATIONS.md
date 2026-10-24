# Integrations reference

This file documents the supported categories of integrations and the safety constraints that apply to each one.

## 1. Integrity policy

- ChainFirst is a victim-first, passive toolkit.
- It performs analysis and reporting without touching funds or wallet secrets.
- All data that enters the tool must pass through the guard before it is stored or logged.

## 2. External network policy

- Any network transfer is opt-in per run with `--allow-external`.
- Third-party tools are optional and pinned.
- If a tool is outside the Core requirements, it must be disabled unless explicitly enabled by the user.
- Findings are leads with a confidence score only.

## 3. Enrichers

### 3.1 Supported enrichers

- `crtsh` — passive CT log lookup for certificate mentions
- `rdap` — passive registration data requests
- `subfinder` — external binary, passive mode only; preserve version in manifest

### 3.2 Safety rules

- Accept only non-person entity types.
- Refuse person, username, email, phone, location, and mac.
- Raw snapshots are stored with hashes in `api_snapshots`.
- Each run is logged to `custody_log`.

## 4. Exporters

- `csv_json` exporter for JSON/CSV reporting
- `stix21` exporter using `stix2`
- Output must be derived from trusted incident data, not raw wallet or disk data

## 5. Custody hash chain

The custody ledger is the append-only record of incident activity.

Requirements:
- `custody_log` table with unique ordering by incident and sequence
- append-only triggers reject update or delete
- `append()` receives an event type and sanitized payload
- `verify()` recomputes the chain and fails immediately when any entry is tampered with

## 6. DFIR importers

Supported importers:
- Plaso CSV
- Velociraptor JSON/CSV
- TSK bodyfile

Safety rules:
- Accept only derived text exports
- Reject raw disk images, memory dumps, and wallet files
- Apply a strict size limit
- Use guard redaction on any imported content that may contain secrets
- Merge imported timeline entries with on-chain transfer times; device times remain unverified

## 7. Umbra bridge (optional)

- Wrapper is optional and disabled by default
- Allowlist infrastructure entity types only
- Depth limit of 1
- Passive mode only
- All CLI details unresolved at implementation time are tagged `TODO-VERIFY`

## 8. Source-of-truth implementation order

The implementation order is:

1. Custody hash chain
2. Enricher framework
3. Exporters
4. DFIR importers
5. Umbra bridge

The project must be built in this order and each phase must be completed and verified before the next begins.
