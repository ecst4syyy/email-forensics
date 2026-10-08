# Email Forensics Tool: Research Notes & Development Plan

## 1. What the tool needs to answer

When someone hands an investigator a suspicious email, they usually want to know:

1. **Where did it really come from?** The true origin (IP, host, provider), not what the `From:` line claims.
2. **Is it authentic?** Did SPF, DKIM, DMARC and ARC pass? Was the message changed in transit?
3. **When was it sent?** A reliable timeline, including clock skew and unusual delays between relays.
4. **What does it try to make the reader do?** Links, lures, impersonation tricks, urgency.
5. **Is the payload malicious?** Attachment type, hashes, macros, embedded scripts, archives.
6. **Can the findings be trusted in a report or in court?** Evidence integrity (hashes), reproducibility, chain of custody.

Each module below maps back to one of these questions.

## 2. Research summary

### 2.1 Standards the tool must understand

| Area | RFC / spec | Why it matters |
|---|---|---|
| Message format | RFC 5322 | Header syntax, `Date`, `Message-ID`, address lists |
| SMTP transport | RFC 5321 | `Received:` / `Return-Path:` trace fields: the hop-by-hop route |
| MIME | RFC 2045–2049, 2231 | Multipart structure, encodings, attachment filenames |
| Encoded words | RFC 2047 | `=?UTF-8?B?...?=` in subjects/names, often used to hide spoofing |
| Authentication-Results | RFC 8601 | Receiver's verdict on SPF/DKIM/DMARC |
| SPF | RFC 7208 | Was the sending IP allowed for the envelope domain |
| DKIM | RFC 6376 | Cryptographic signature over headers and body |
| DMARC | RFC 7489 (DMARCbis in progress) | Alignment between `From:` domain and SPF/DKIM domains |
| ARC | RFC 8617 | Keeps auth results across forwarders and mailing lists |
| BIMI / VMC | draft / industry | Brand logo indicators; relevant for brand-impersonation cases |
| Outlook `.msg` | MS-OXMSG (CFB/OLE) | Common evidence format from corporate environments |
| mbox / PST | RFC 4155 / MS-PST | Bulk mailbox exports |

### 2.2 Lessons from existing tools

- **Google/MXToolbox Message Header Analyzers**: mainly visualize the `Received` chain and hop delays. The hop timeline is the feature investigators use most.
- **`eml_parser`, `emlAnalyzer`, `mail-parser`** (Python): good at extraction (URLs, IPs, attachments, hashes), weak at *interpretation*. A findings or verdict layer on top of extraction adds the most value.
- **`oletools`, `pdfid`/`peepdf`, YARA**: the standard toolkit for Office macros, PDFs and pattern matching on attachments.
- **`dkimpy`, `pyspf`, `checkdmarc`, `dnspython`**: let us *re-verify* authentication instead of trusting the receiver's `Authentication-Results`.
- **`extract-msg`, `libpff`/`pypff`**: parse `.msg` and `.pst`.
- **Commercial suites (e.g. MailXaminer, Aid4Mail)**: add case management, bulk ingest, keyword search and court-ready reports. These are later features for us.

### 2.3 What makes a forensic tool robust

1. **Never trust input.** Email is attacker-controlled. We need to handle malformed headers, bad charsets, broken MIME boundaries, duplicate headers, header folding tricks, nested `message/rfc822`, zip bombs and very large files without crashing. We should also report every anomaly we find.
2. **Read-only evidence.** Hash the original bytes (SHA-256 + MD5 for legacy case systems) before parsing. Never modify the source file. Record tool version and timestamp in every report.
3. **Trust boundaries in the `Received` chain.** Only hops added by infrastructure *you* trust (your own MX and downstream) are reliable. Anything below the first external hop can be forged by the sender. The tool should mark where that boundary is.
4. **Separate facts from verdicts.** Keep raw extracted data, then a findings layer (`severity`, `code`, `evidence`). Investigators need to see *why* something was flagged.
5. **Offline by default.** DNS lookups, WHOIS, VirusTotal and similar services leak investigation activity and results change over time (DKIM keys rotate, SPF records change). Online enrichment should be opt-in, and the report should record the lookup time.
6. **Deterministic output.** The same input should always give the same JSON. This makes regression tests possible and lets results be reproduced in court.
7. **Never execute or render content.** No HTML rendering with remote loads, no macro execution. Static analysis only; dynamic analysis goes to an external sandbox.
8. **Test on a real corpus.** Use a fixture set of tricky real-world samples (redacted), plus fuzzing of the parser.

### 2.4 High-value detections (from phishing/BEC research)

**Headers**
- `From` vs `Return-Path` / `Sender` / `Reply-To` domain mismatch (classic BEC reply-to redirect)
- Display-name spoofing: `"ceo@company.com" <attacker@gmail.com>`
- SPF / DKIM / DMARC / ARC failures, and DKIM `d=` not aligned with `From`
- `Received` timestamps out of order, large hop delays, `Date` far from first-hop time
- `Message-ID` domain unrelated to sender, or missing
- Suspicious `X-Mailer` / `User-Agent` (mass mailers, scripting libraries)
- Lookalike / homoglyph / punycode sender domains (`rnicrosoft.com`, `xn--...`)
- Newly registered domains (WHOIS age, opt-in online)

**Body**
- URL extraction from text, HTML, and attachments. Flag `href` vs visible-text mismatch
- URL shorteners, IP-literal URLs, `data:` URIs, credential-harvesting keywords
- Hidden text (CSS `display:none`, zero-size fonts, white-on-white), zero-width characters
- Tracking pixels / remote resources
- Urgency and payment-change language (BEC indicators)

**Attachments**
- True file type by magic bytes vs extension vs declared MIME type (`invoice.pdf.exe`, RTLO trick)
- Hashes (MD5/SHA-1/SHA-256, plus ssdeep/TLSH for similarity)
- Office macros / DDE / remote templates (`oletools`)
- PDF JavaScript / OpenAction / embedded files
- Archives: nested, password-protected, and zip-bomb ratio
- HTML / SVG attachments with scripts (current phishing trend), `.lnk`, `.iso`, `.img`, `.one`
- YARA rule scanning

## 3. Architecture

```
          ┌──────────────┐
evidence →│  loader      │  hash original bytes, detect format (.eml/.msg/.mbox)
          └──────┬───────┘
                 ▼
          ┌──────────────┐
          │  parser      │  email.message.EmailMessage (stdlib, policy=default)
          └──────┬───────┘
     ┌───────────┼─────────────┬──────────────┐
     ▼           ▼             ▼              ▼
 headers      auth          body          attachments        ← analyzers (pure functions)
 (routing,  (SPF/DKIM/    (URLs, HTML,   (type, hashes,
  timeline)  DMARC/ARC)    lures)         macros, YARA)
     └───────────┴─────────────┴──────────────┘
                 ▼
          ┌──────────────┐
          │  findings    │  severity + code + message + evidence
          └──────┬───────┘
                 ▼
          ┌──────────────┐
          │  reporters   │  text, JSON (later: HTML, PDF, STIX/MISP IOCs)
          └──────────────┘
```

Design principles:
- Core has **no required third-party dependencies**. Optional extras (`[auth]`, `[attachments]`, `[yara]`) add heavier libraries.
- Each analyzer is a pure function: `(message) -> (data, findings)`. This makes them easy to test and to add.
- Stable finding codes (e.g. `HDR_REPLY_TO_MISMATCH`) so downstream tooling and tests can depend on them.

## 4. Day-by-day plan

We add one small, tested piece per day. Each day ends with passing tests and a working CLI.

| Day | Theme | Deliverables |
|---|---|---|
| **1** ✅ | **Foundation + header analysis** | Project scaffold, `.eml` loader with SHA-256/MD5 evidence hashing, header extraction, `Received` chain parser + hop timeline, `Authentication-Results` parsing, first rule set (address mismatches, display-name spoofing, auth failures, timeline anomalies), text/JSON CLI, tests + fixtures |
| **2** ✅ | **MIME structure & body** | MIME tree walker, RFC 2047 decoding anomalies, plain/HTML body extraction, static HTML analysis (hidden text, forms, scripts, pixels), invisible Unicode, URL extraction (text + HTML `href`/`src`), link-text vs `href` mismatch, IP-literal / shortener / punycode URLs |
| **3** ✅ | **Attachments (static)** | Attachment extraction to a safe output dir, RFC 2231 filename anomalies, hashes, magic-byte type detection vs extension vs MIME type, double-extension & RTLO detection, risky types (`.html`, `.svg`, `.lnk`, `.iso`, `.one`), archive listing + zip-bomb guard |
| **4** ✅ | **Sender-identity heuristics** | Lookalike / homoglyph domain detection (confusables + edit distance against a protected-domains list), `X-Mailer` / `User-Agent` fingerprinting, `Message-ID` analysis, provider-specific headers (Exchange/O365 `X-MS-*`, Gmail) |
| **5** ✅ | **Authentication re-verification (opt-in online)** | DKIM signature verification (`dkimpy`), SPF evaluation for the first external hop IP (`pyspf`), DMARC policy + alignment, ARC chain validation, DNS lookup timestamps recorded in the report |
| **6** ✅ | **Office / PDF / script payloads** | `oletools` (VBA macros, DDE, remote templates), PDF keyword scan (JS, OpenAction, EmbeddedFile, Launch), HTML/SVG attachment script detection |
| **7** ✅ | **Additional input formats** | Outlook `.msg` (pure Python via the CFB reader), `.mbox` batch mode with `--summary`, nested `message/rfc822` / `.eml` / `.msg` recursion |
| **8** ✅ | **Scoring & reporting** | Weighted risk score with explanations, HTML report, IOC export (CSV, STIX 2.1, MISP JSON) |
| **9** ✅ | **Enrichment (opt-in)** | IP geolocation / ASN, WHOIS domain age, VirusTotal / URLhaus / AbuseIPDB hash & URL lookups with caching and rate limiting |
| **10** ✅ | **YARA & custom rules** | YARA scanning of bodies and attachments, user-defined rules file (YAML) for header/body conditions |
| **11** ✅ | **Hardening** | Fuzzing (Hypothesis / atheris), size and recursion limits, timeouts, malformed-corpus regression suite, performance on large mailboxes |
| **12** ✅ | **Case management** | Case folders, chain-of-custody log, bulk ingest, search across a case, report signing |
| 13+ | UI / integrations | Web UI or TUI, REST API, SIEM/SOAR integration, PST ingestion (`libpff`) |

Carried forward from Day 7: native PST/OST reading (currently: convert with readpst), RTF de-encapsulation of HTML bodies in .msg.

Carried forward from Day 6: BIFF8 (.xls) XLM macros, PowerPoint binary VBA, PDF LZW/ASCII85 filters, QR-code decoding, VBA p-code disassembly.

Carried forward from Day 4: full Unicode TR39 confusables table, newly-registered-domain checks (Day 9 enrichment), Google Workspace / Proofpoint / Mimecast verdict headers.

Carried forward from Day 3: RAR/7z/ISO listing via optional extras, ssdeep/TLSH similarity hashes, correlating attachment and body URLs into one IOC list.

Carried forward from Day 2: done (Day 11: `<style>` class rules, text/html divergence; Day 5: Public Suffix List).

We can reorder these as priorities change. Days 2–4 give the most value for phishing triage.

## 5. Definition of done (every day)

- New analyzer has unit tests with at least one positive and one negative fixture
- `python -m pytest` passes
- CLI output documented in `README.md`
- No new *required* dependency without discussion
