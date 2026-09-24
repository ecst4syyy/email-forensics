# email-forensics

A tool for forensic analysis of email: headers, bodies and attachments. We build it one day at a time. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the research notes and the day-by-day plan.

## Status: Day 1 (header analysis)

- Read-only evidence loading with SHA-256 / MD5 hashes, file size, analysis timestamp and tool version
- Header extraction (From/Sender/Reply-To/Return-Path/To/Cc, Date, Message-ID, X-Mailer), with RFC 2047 decoding done safely *after* address parsing
- `Received` chain parser: hosts, connecting IP (v4/v6), protocol, queue id, timestamps, hop delays, private vs public IPs, earliest public origin IP
- `Authentication-Results` (RFC 8601) parsing for SPF / DKIM / DMARC / ARC verdicts
- Rule engine with stable finding codes and severities (see below)
- CLI with text and JSON output
- Only uses the Python standard library (3.10+)

## Usage

```bash
pip install -e ".[dev]"
email-forensics analyze suspicious.eml
email-forensics analyze --json --min-severity medium *.eml
# or without installing:
PYTHONPATH=src python -m email_forensics analyze tests/fixtures/bec_spoof.eml
```

Exit code: `0` on success, `2` if an input file could not be loaded.

## Finding codes

| Code | Severity | Meaning |
|---|---|---|
| `HDR_DISPLAY_NAME_SPOOF` | high | Display name contains an address from a different domain than the real sender |
| `AUTH_<METHOD>_<RESULT>` | high/medium/low | SPF/DKIM/DMARC/ARC verdict that is not `pass` (e.g. `AUTH_SPF_FAIL`) |
| `HDR_REPLY_TO_MISMATCH` | medium | Reply-To domain differs from From domain (BEC) |
| `HDR_DUPLICATE` | medium | A header that must appear once appears several times |
| `HDR_MULTIPLE_FROM_ADDRESSES` | medium | From contains more than one address |
| `HDR_MISSING_FROM` | medium | No From header |
| `HDR_DATE_AFTER_DELIVERY` | medium | Date header is later than final delivery |
| `RCV_TIME_REVERSAL` | medium | A hop is timestamped before the previous hop |
| `HDR_RETURN_PATH_MISMATCH` | low | Envelope sender domain differs from From domain |
| `HDR_SENDER_MISMATCH` | low | Sender domain differs from From domain |
| `AUTH_DKIM_NOT_ALIGNED` | low | DKIM passed only for domains unrelated to From |
| `HDR_DATE_SKEW` | low | Date differs from first hop by more than 1h |
| `RCV_LONG_DELAY` | low | A hop took more than 1h |
| `RCV_BAD_TIMESTAMP`, `HDR_BAD_DATE`, `HDR_MISSING_DATE`, `HDR_MISSING_MESSAGE_ID`, `RCV_NO_HOPS`, `PARSE_DEFECTS` | low | Structural problems |
| `RCV_ORIGIN_IP`, `HDR_X_ORIGINATING_IP`, `HDR_MESSAGE_ID_DOMAIN_MISMATCH`, `AUTH_MULTIPLE_SERVERS`, `AUTH_RESULTS_MISSING` | info | Context for the investigator |

## Known limitations (planned)

- Organizational-domain matching is approximate. We plan to use the Public Suffix List later.
- Authentication verdicts are read from headers, not re-verified. DKIM/SPF re-verification is planned for Day 5.
- There is no trust boundary configuration yet. `Received` hops below your own MX can be forged by the sender.
- Only `.eml` files are supported so far. `.msg` and `.mbox` support is planned for Day 7.

## Development

```bash
python -m pytest
```

Layout: `src/email_forensics/` contains `loader` → `headers` (extraction) → `rules` (findings) → `report` / `cli`.
