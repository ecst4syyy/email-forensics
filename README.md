# email-forensics

A tool for forensic analysis of email: headers, bodies and attachments. We build it one day at a time. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the research notes and the day-by-day plan.

## Status: Day 4 (sender identity)

**Day 4**
- **Lookalike domains** for From / Reply-To / Return-Path / Sender and every URL host (body and HTML attachments): homoglyphs (`paypa1`, `rnicrosoft`, Cyrillic `аррӏе`), typos (`microsfot`), combosquatting (`paypal-secure`, `secure-paypa1`), brand in a subdomain (`paypal.com.evil.net`), mixed-script labels, and TLD swaps of your own domain (`acme-corp.co`)
- Compared against a built-in list of commonly impersonated brands **plus the recipient's own domain** (from To/Cc/Delivered-To) and any domains you pass with `--protected-domain` / `--protected-domains-file`. Your own domains get stricter checks than brands
- **Display-name impersonation**: a brand name ("Microsoft Support") or your organisation's name in the display name with an unrelated or free-mail address
- **Sending software**: phishing-kit mailers, mass mailers, scripts/libraries, obsolete clients, and `X-PHP-Originating-Script` (mail sent from a web server)
- **Provider consistency**: From claims Gmail/Outlook.com/Yahoo/iCloud, or the Message-ID looks Google/Microsoft-generated, but no such server appears in the delivery path
- **Provider verdicts**: Microsoft 365 (`X-Forefront-Antispam-Report` CAT/SCL/SFV, BCL, `AuthAs: Anonymous` for an internal-looking sender) and SpamAssassin

**Day 3**
- Every attachment (and inline non-text part) gets MD5 / SHA-1 / SHA-256 and a **true file type from its bytes**: PE/ELF/Mach-O, PDF, RTF, OLE, OOXML (Word/Excel/PowerPoint), ODF, JAR/APK, ZIP/RAR/7z/gzip/bzip2/xz/tar/CAB/ACE, ISO/VHD/VHDX, LNK, OneNote, CHM, HTML, SVG, images, scripts
- Detected type is compared with the extension and the declared Content-Type
- Filename tricks: double extensions (`invoice.pdf.exe`), whitespace padding, RTLO/zero-width characters, path characters, and Content-Type `name` vs Content-Disposition `filename` conflicts. RFC 2231 names are decoded
- Risky formats: executables, disk images (Mark-of-the-Web bypass), OneNote, macro-enabled Office, VBA projects in OLE/OOXML, remote template injection, RTF embedded objects
- HTML/SVG attachments are run through the Day 2 HTML analyzer, plus **HTML smuggling** detection (`atob`/`Blob`/`createObjectURL` with large base64 blobs)
- Archives are listed **without writing to disk**: ZIP/JAR/APK, tar, gzip/bzip2/xz, nested up to 3 levels, member hashes and types. Flags password protection, path traversal, risky members and zip bombs (ratio, total size, overlapping entries). Hard limits on members, bytes read and nesting
- Password-protected archive + "password" in the body (multi-language) → escalated to high
- `--extract-dir DIR` writes attachments as read-only `<sha256>.bin` files with a `manifest.json` (original names never touch the filesystem)
- Attacker-controlled text (filenames, subject, URLs) is escaped in text output so RTLO and control characters can't alter the display

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
email-forensics analyze suspicious.eml --extract-dir ./case42/attachments
email-forensics analyze suspicious.eml --protected-domain acme-corp.com --protected-domains-file partners.txt
# or without installing:
PYTHONPATH=src python -m email_forensics analyze tests/fixtures/bec_spoof.eml
```

Exit code: `0` on success, `2` if an input file could not be loaded.

## Finding codes

| Code | Severity | Meaning |
|---|---|---|
| `HDR_DISPLAY_NAME_SPOOF` | high | Display name contains an address from a different domain than the real sender |
| `LOOKALIKE_HOMOGLYPH`, `LOOKALIKE_TYPO` | high | Domain visually confusable with / one typo from a protected domain |
| `LOOKALIKE_BRAND_IN_SUBDOMAIN` | high (full domain) / medium (name) | `paypal.com.evil.net` |
| `LOOKALIKE_COMBO` | high (look-alike spelling) / medium | `paypal-secure.com`, `acme-corp-invoices.com` |
| `LOOKALIKE_MIXED_SCRIPT` | high (Latin + Cyrillic/Greek/Armenian) / medium | Label mixes writing systems |
| `LOOKALIKE_TLD_SWAP` | medium | Your domain's name on another suffix |
| `HDR_DISPLAY_NAME_BRAND`, `HDR_DISPLAY_NAME_ORG` | high (free-mail) / medium | Brand or your organisation's name in the display name, unrelated address |
| `HDR_MAILER_PHISHING_KIT` | high | Mailer bundled with phishing kits |
| `PROVIDER_PHISH_VERDICT`, `PROVIDER_EXTERNAL_CLAIMS_INTERNAL` | high | Microsoft 365 phish/spoof verdict; unauthenticated external mail with an internal From |
| `HDR_PROVIDER_PATH_MISMATCH`, `HDR_MESSAGE_ID_PROVIDER_MISMATCH`, `HDR_PHP_SCRIPT`, `PROVIDER_SPAM_VERDICT` | medium | Provider claims not backed by the path; PHP web-server sending; spam verdicts |
| `HDR_MAILER_SCRIPT`, `HDR_MAILER_BULK`, `HDR_MAILER_OUTDATED`, `PROVIDER_BULK_VERDICT` | low | Sending-software context |
| `PROVIDER_FILTER_BYPASSED` | info | Spam filtering skipped by allow list or mail-flow rule |
| `ATT_EXECUTABLE` | high | Executable by extension or by content |
| `ATT_TYPE_MISMATCH` | high (executable/disk/HTML content) / medium | Content doesn't match the extension |
| `ATT_DOUBLE_EXTENSION` | high | `invoice.pdf.exe` style name |
| `ATT_DISK_IMAGE`, `ATT_ONENOTE` | high | ISO/IMG/VHD(X), OneNote |
| `ATT_OFFICE_MACRO`, `ATT_REMOTE_TEMPLATE`, `ATT_RTF_OBJECT` | high | VBA project, external template, RTF OLE objects |
| `ATT_HTML_SMUGGLING` | high | HTML attachment that assembles a file in the browser |
| `ATT_ARCHIVE_RISKY_MEMBER`, `ATT_ZIP_BOMB` | high | Risky file inside an archive; decompression bomb |
| `ATT_ENCRYPTED_ARCHIVE` | medium (high if body mentions a password) | Password-protected archive members |
| `ATT_HTML`, `ATT_MACRO_EXTENSION`, `ATT_DECLARED_TYPE_MISMATCH`, `ATT_FILENAME_CONFLICT`, `ATT_FILENAME_PADDING`, `ATT_FILENAME_PATH`, `ATT_ARCHIVE_PATH_TRAVERSAL` | medium | Attachment traits worth a look |
| `ATT_ARCHIVE_NESTED`, `ATT_ARCHIVE_UNINSPECTED`, `ATT_ARCHIVE_CORRUPT`, `ATT_ARCHIVE_TRUNCATED` | low | Archive could not be fully inspected |
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
- RAR / 7z / CAB / ISO contents are not listed (flagged as uninspected). Optional extras could add them later.
- Office/PDF analysis is presence-based (VBA project exists, RTF has objects). Macro source extraction and PDF JavaScript/OpenAction analysis are planned for Day 6.
- Lookalike detection uses a practical subset of Unicode confusables and an approximate organisational-domain rule (no Public Suffix List yet), so multi-level suffixes beyond `co.uk`-style may be compared imperfectly.
- Provider verdict headers are only trustworthy if your own tenant or gateway added them. The tool reports them but can't verify who added them.
- Hidden-text detection covers inline styles and the `hidden` attribute, not `<style>` class rules.

## Development

```bash
python -m pytest
python tests/fixtures/build_attachments_fixture.py   # regenerate the (inert) attachment fixture
```

Test samples in `tests/samples.py` only imitate the structure of malicious files (headers, archive layout, markers). They contain no working code.

Layout of `src/email_forensics/`:

| Module | Role |
|---|---|
| `loader` | Read evidence, hash it, parse it |
| `headers` → `rules` | Header extraction → header findings |
| `mime` | MIME tree walk, safe decoding |
| `html_analysis`, `urls`, `textcheck` | HTML, URL and Unicode analysis |
| `brands`, `lookalike`, `mailer`, `identity` | Reference data, lookalike engine, mailer fingerprints, identity findings |
| `filetype`, `archives`, `attachments` | Magic-byte detection, bounded archive listing, attachment findings and extraction |
| `body` | Body orchestration and body findings |
| `domains` | Shared domain helpers |
| `analyzer` | Runs everything and builds the `Report` |
| `report`, `cli` | Output |
