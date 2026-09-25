# email-forensics

A tool for forensic analysis of email: headers, bodies and attachments. We build it one day at a time. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the research notes and the day-by-day plan.

## Status: Day 2 (MIME structure & body analysis)

**Day 2**
- MIME tree walker with IMAP-style part paths (`1.2.1`), per-part SHA-256, size, charset, encoding and filename. Depth (20) and part-count (1000) limits
- Safe payload decoding: unknown or hostile charsets, broken base64/QP and bad bytes are reported, not fatal
- Static HTML analysis (never rendered, nothing fetched): visible vs CSS-hidden text, links with anchor text, forms and password fields, `<script>` and `on*` handlers, iframes/objects, meta-refresh, `<base href>`, tracking pixels, remote resources, URLs inside scripts
- URL extraction from text and HTML (`a`, `img`, `form`, `iframe`, `script`, `link`, `background`, CSS `url()`, meta refresh), deduplicated with every source recorded
- URL heuristics: link-text vs destination mismatch, `user@host` trick, IP-literal hosts (including decimal/hex forms), punycode/IDN, shorteners, `javascript:`/`data:` schemes, odd ports, deep subdomains
- Zero-width and bidirectional-override characters in subject, sender name and body
- Malformed RFC 2047 encoded-words in headers

**Day 1**
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
| `URL_TEXT_MISMATCH` | high | Link text shows one domain but the link goes to another |
| `URL_USERINFO` | high | `http://trusted.com@evil.com/` style URL |
| `URL_DANGEROUS_SCHEME` | high | `javascript:`, `vbscript:`, `data:` or `file:` link |
| `HTML_CREDENTIAL_FORM` | high | HTML form with a password field |
| `TEXT_BIDI_CONTROL` | high (subject/sender) / medium (body) | Bidirectional control characters that reverse displayed text |
| `URL_IP_HOST`, `URL_IDN_HOST`, `URL_ENCODED_HOST` | medium | Raw IP host, punycode/non-ASCII host, percent-encoded host |
| `HTML_SCRIPT`, `HTML_EVENT_HANDLERS`, `HTML_FORM`, `HTML_EMBEDDED_FRAME`, `HTML_META_REFRESH` | medium | Active or interactive HTML content |
| `HTML_HIDDEN_TEXT` | medium (≥20 words) / low | CSS-hidden text (filter poisoning or smuggling) |
| `TEXT_ZERO_WIDTH` | medium (subject/sender) / low (body) | Zero-width characters splitting words |
| `MIME_TOO_DEEP`, `MIME_TOO_MANY_PARTS` | medium | Analysis limits hit (possible evasion or DoS) |
| `URL_SHORTENER`, `URL_NONSTANDARD_PORT`, `URL_DEEP_SUBDOMAIN`, `URL_MALFORMED` | low | URL traits worth a look |
| `HTML_BASE_HREF`, `HTML_TRUNCATED`, `BODY_IMAGE_ONLY`, `BODY_CHARSET_PROBLEM`, `MIME_PART_DEFECTS`, `MIME_UNKNOWN_TRANSFER_ENCODING`, `HDR_ENCODED_WORD_ERROR` | low | Structural or evasion signals |
| `HTML_TRACKING_PIXEL`, `HTML_REMOTE_RESOURCES`, `BODY_NO_TEXT` | info | Context |
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
- Attachments are listed in the MIME tree (with hashes) but not yet inspected. Attachment analysis is planned for Day 3.
- Lookalike detection is limited to flagging punycode hosts. Homoglyph and edit-distance checks are planned for Day 4.
- Hidden-text detection covers inline styles and the `hidden` attribute, not `<style>` class rules.

## Development

```bash
python -m pytest
```

Layout of `src/email_forensics/`:

| Module | Role |
|---|---|
| `loader` | Read evidence, hash it, parse it |
| `headers` → `rules` | Header extraction → header findings |
| `mime` | MIME tree walk, safe decoding |
| `html_analysis`, `urls`, `textcheck` | HTML, URL and Unicode analysis |
| `body` | Body orchestration and body findings |
| `domains` | Shared domain helpers |
| `analyzer` | Runs everything and builds the `Report` |
| `report`, `cli` | Output |
