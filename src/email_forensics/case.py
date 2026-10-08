"""Case management: evidence intake, chain of custody, reports, search and signing.

Layout of a case directory::

    case.json                case id, name, examiner, created, signing public key
    custody.jsonl            append-only, hash-chained (and signed) log of every action
    evidence/<sha256>.<ext>  read-only copies of the evidence
    reports/<sha256>.json|.html|.txt  (+ .sig signatures)
    index.json               searchable summary of every analysed message
    case-report.html, iocs.csv, iocs.stix.json, iocs.misp.json

The custody log is tamper-evident: every entry contains the hash of the previous
one, and (with a signing key) an Ed25519 signature over its own hash. ``verify``
recomputes the chain, re-hashes the evidence and checks every report signature.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import secrets
import shutil
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import AnalysisOptions, analyze_path
from .crypto import ed25519_public_key, ed25519_sign, ed25519_verify
from .iocs import csv_safe, extract_iocs
from .loader import detect_format
from .models import Report
from .report import to_text
from .report_html import defang, esc, html_head, render_html

CASE_FILE, CUSTODY_FILE, INDEX_FILE = "case.json", "custody.jsonl", "index.json"
GENESIS = "0" * 64


class CaseError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "backslashreplace")


def _examiner(name: str | None) -> str:
    if name:
        return name
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user database in some containers
        return "unknown"


@dataclass
class Problem:
    kind: str
    detail: str


@dataclass
class VerifyResult:
    entries: int = 0
    evidence: int = 0
    reports: int = 0
    problems: list[Problem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


class Case:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        meta = self.root / CASE_FILE
        if not meta.is_file():
            raise CaseError(f"{self.root} is not a case directory (no {CASE_FILE}); run 'case init' first")
        self.meta = json.loads(meta.read_text(encoding="utf-8"))

    # -- creation ----------------------------------------------------------------------
    @classmethod
    def init(cls, root: str | Path, name: str, examiner: str | None = None, signing_key: bool = True,
             key_path: str | Path | None = None) -> "Case":
        root = Path(root)
        if (root / CASE_FILE).exists():
            raise CaseError(f"{root} already contains a case")
        for sub in ("evidence", "reports"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        meta = {"id": str(uuid.uuid4()), "name": name, "examiner": _examiner(examiner), "created": _now(),
                "tool_version": __version__, "public_key": None, "key_path": None}
        if signing_key:
            key_file = Path(key_path) if key_path else root / "keys" / "signing.key"
            key_file.parent.mkdir(parents=True, exist_ok=True)
            seed = secrets.token_bytes(32)
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(seed.hex() + "\n")
            meta["public_key"] = ed25519_public_key(seed).hex()
            meta["key_path"] = str(key_file if key_path else key_file.relative_to(root))
        (root / CASE_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        case = cls(root)
        case._log("case_created", meta["examiner"], {"name": name, "case_id": meta["id"],
                                                     "public_key": meta["public_key"]})
        return case

    # -- signing -------------------------------------------------------------------------
    def _seed(self) -> bytes | None:
        if not self.meta.get("key_path"):
            return None
        path = Path(self.meta["key_path"])
        path = path if path.is_absolute() else self.root / path
        try:
            return bytes.fromhex(path.read_text().strip())
        except (OSError, ValueError):
            return None

    def _sign(self, data: bytes) -> str | None:
        seed = self._seed()
        return ed25519_sign(seed, data).hex() if seed else None

    # -- custody log ---------------------------------------------------------------------
    def entries(self) -> list[dict]:
        path = self.root / CUSTODY_FILE
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _log(self, action: str, examiner: str | None, details: dict) -> dict:
        entries = self.entries()
        entry = {"seq": len(entries) + 1, "time": _now(), "action": action,
                 "examiner": examiner or self.meta.get("examiner") or _examiner(None),
                 "details": details, "prev_hash": entries[-1]["hash"] if entries else GENESIS}
        entry["hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
        signature = self._sign(bytes.fromhex(entry["hash"]))
        if signature:
            entry["signature"] = signature
        with open(self.root / CUSTODY_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    # -- evidence ------------------------------------------------------------------------
    def evidence(self) -> list[dict]:
        """Evidence items as recorded at intake (from the custody log)."""
        return [e["details"] for e in self.entries() if e["action"] == "evidence_added"]

    def add(self, source: str | Path, examiner: str | None = None, note: str | None = None) -> dict:
        source = Path(source)
        if not source.is_file():
            raise CaseError(f"not a file: {source}")
        sha = _sha256_file(source)
        if any(e["sha256"] == sha for e in self.evidence()):
            raise CaseError(f"{source} is already in the case (sha256 {sha})")
        fmt = detect_format(source)
        suffix = {"msg": ".msg", "mbox": ".mbox"}.get(fmt, ".eml")
        target = self.root / "evidence" / f"{sha}{suffix}"
        tmp = target.with_suffix(target.suffix + ".tmp")
        shutil.copyfile(source, tmp)
        if _sha256_file(tmp) != sha:
            tmp.unlink()
            raise CaseError(f"copy of {source} does not match its hash; the source changed during intake")
        os.chmod(tmp, 0o444)
        tmp.replace(target)
        st = source.stat()
        details = {"sha256": sha, "md5": hashlib.md5(target.read_bytes()).hexdigest(), "size": st.st_size,
                   "format": fmt, "stored_as": f"evidence/{target.name}", "original_path": str(source.resolve()),
                   "original_mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                   "note": note}
        self._log("evidence_added", examiner, details)
        return details

    # -- analysis ------------------------------------------------------------------------
    def analyze(self, options: AnalysisOptions | None = None, examiner: str | None = None,
                only_new: bool = True) -> list[Report]:
        options = options or AnalysisOptions()
        index = self._load_index()
        done = {i["container_sha256"] for i in index.values()}
        reports: list[Report] = []
        for item in self.evidence():
            if only_new and item["sha256"] in done:
                continue
            path = self.root / item["stored_as"]
            if _sha256_file(path) != item["sha256"]:
                raise CaseError(f"evidence {item['stored_as']} no longer matches its recorded hash")
            for report in analyze_path(path, options):
                reports.append(report)
                rid = self._report_id(report)
                written = self._write_report(report, rid)
                index[rid] = self._index_entry(report, item, written)
                self._log("analyzed", examiner, {
                    "evidence_sha256": item["sha256"], "message_sha256": report.evidence.sha256,
                    "message": report.evidence.path.replace(str(self.root) + os.sep, ""), "report_id": rid,
                    "verdict": report.assessment.verdict if report.assessment else None,
                    "score": report.assessment.score if report.assessment else None,
                    "reports": written, "tool_version": __version__,
                    "online": bool(options.resolver or options.enricher)})
        self._save_index(index)
        return reports

    def _report_id(self, report: Report) -> str:
        """Message hash plus where it sits: identical messages delivered twice stay separate items."""
        where = report.evidence.path.replace(str(self.root) + os.sep, "")
        return f"{report.evidence.sha256}-{hashlib.sha256(where.encode('utf-8', 'backslashreplace')).hexdigest()[:8]}"

    def _write_report(self, report: Report, rid: str) -> dict:
        sha = rid
        outputs = {"json": json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
                   "html": render_html([report]), "txt": to_text(report)}
        written = {}
        for ext, text in outputs.items():
            path = self.root / "reports" / f"{sha}.{ext}"
            data = text.encode("utf-8", "backslashreplace")
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            written[ext] = {"file": f"reports/{path.name}", "sha256": digest}
            signature = self._sign(bytes.fromhex(digest))
            if signature:
                sig = {"file": path.name, "sha256": digest, "signature": signature,
                       "public_key": self.meta["public_key"], "algorithm": "ed25519", "signed_at": _now()}
                (path.parent / f"{path.name}.sig").write_text(json.dumps(sig, indent=2), encoding="utf-8")
        return written

    # -- index & search ------------------------------------------------------------------
    def _load_index(self) -> dict:
        path = self.root / INDEX_FILE
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    def _save_index(self, index: dict) -> None:
        (self.root / INDEX_FILE).write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _index_entry(report: Report, item: dict, written: dict) -> dict:
        h, a = report.headers, report.assessment
        return {"message_sha256": report.evidence.sha256, "container_sha256": item["sha256"],
                "evidence": report.evidence.path, "format": report.evidence.format,
                "subject": h.subject, "from": h.from_address, "date": h.date.isoformat() if h.date else None,
                "verdict": a.verdict if a else None, "score": a.score if a else None,
                "reports": {k: v["file"] for k, v in written.items()},
                "indicators": [{"type": i.type, "value": i.value, "role": i.role} for i in extract_iocs(report)]}

    def search(self, query: str, kind: str | None = None) -> list[dict]:
        q = query.lower()
        hits = []
        for rid, entry in self._load_index().items():
            sha = entry["message_sha256"]
            for field_name in ("subject",):  # senders are matched through their indicators below
                if kind is None and q in (entry.get(field_name) or "").lower():
                    hits.append({"message_sha256": sha, "report_id": rid, "match": field_name, "value": entry[field_name],
                                 "subject": entry["subject"], "verdict": entry["verdict"]})
            for ind in entry["indicators"]:
                if (kind is None or ind["type"] == kind) and q in ind["value"].lower():
                    hits.append({"message_sha256": sha, "report_id": rid, "match": f"{ind['type']} ({ind['role']})",
                                 "value": ind["value"], "subject": entry["subject"], "verdict": entry["verdict"]})
        return hits

    def shared_indicators(self, minimum: int = 2) -> list[dict]:
        """Indicators seen in several messages: the threads that tie a campaign together."""
        seen: dict[tuple[str, str], set[str]] = {}
        for sha, entry in self._load_index().items():
            for ind in entry["indicators"]:
                if ind["type"] in ("subject", "message-id"):
                    continue
                seen.setdefault((ind["type"], ind["value"].lower()), set()).add(sha)
        shared = [{"type": t, "value": v, "messages": sorted(shas)} for (t, v), shas in seen.items() if len(shas) >= minimum]
        return sorted(shared, key=lambda x: (-len(x["messages"]), x["type"], x["value"]))

    # -- case-level report ----------------------------------------------------------------
    def build_report(self, examiner: str | None = None) -> dict:
        index = self._load_index()
        indicators = [i for e in index.values() for i in e["indicators"]]
        csv_rows = ["type,value,role,message_sha256,verdict"] + [
            ",".join(_csv_cell(x) for x in (i["type"], i["value"], i["role"], sha, e["verdict"] or ""))
            for sha, e in index.items() for i in e["indicators"]]
        (self.root / "iocs.csv").write_text("\n".join(csv_rows) + "\n", encoding="utf-8")
        (self.root / "case-report.html").write_text(self._case_html(index), encoding="utf-8")
        outputs = {"case-report.html": None, "iocs.csv": None}
        for name in outputs:
            outputs[name] = _sha256_file(self.root / name)
        self._log("case_report", examiner, {"files": outputs, "messages": len(index), "indicators": len(indicators)})
        return {"messages": len(index), "indicators": len(indicators), "files": outputs}

    def _case_html(self, index: dict) -> str:
        rows = []
        for _, e in sorted(index.items(), key=lambda kv: -(kv[1]["score"] or 0)):
            sev = {"malicious": "high", "suspicious": "medium", "caution": "low"}.get(e["verdict"], "info")
            rows.append(f'<tr><td><span class="sev {sev}">{esc(e["verdict"])}</span> {e["score"]}</td>'
                        f'<td class="n">{esc((e["date"] or "-")[:16])}</td><td class="msg">{esc(e["from"] or "-")}</td>'
                        f'<td class="msg"><a href="{esc(e["reports"]["html"])}">{esc(e["subject"] or "(no subject)")}</a></td>'
                        f'<td><code>{esc(e["message_sha256"][:16])}</code></td></tr>')
        shared = "".join(f'<tr><td>{esc(s["type"])}</td><td><code>{esc(defang(s["value"]))}</code></td>'
                         f'<td>{len(s["messages"])}</td></tr>' for s in self.shared_indicators()[:200])
        custody = self.entries()
        return (html_head(f"Case: {self.meta['name']}")
                + f'<main><div class="banner"><h1>Case: {esc(self.meta["name"])}</h1><div class="muted">'
                f'{esc(self.meta["id"])} · examiner {esc(self.meta["examiner"])} · created {esc(self.meta["created"])}'
                f' · {len(index)} message(s) · {len(custody)} custody entries</div></div>'
                '<section><h2>Messages</h2><div class="wrap"><table class="stack"><tr><th>Verdict</th><th>Date</th>'
                f'<th>From</th><th>Subject</th><th>SHA-256</th></tr>{"".join(rows)}</table></div></section>'
                '<section><h2>Indicators shared by several messages</h2>'
                + (f'<div class="wrap"><table class="stack"><tr><th>Type</th><th>Value</th><th>Messages</th></tr>{shared}'
                   '</table></div>' if shared else '<p class="muted">None.</p>')
                + '</section><p class="muted">Links open the per-message reports in this case folder. '
                  'Indicators are defanged.</p></main></body></html>')

    # -- verification ---------------------------------------------------------------------
    def verify(self) -> VerifyResult:
        res = VerifyResult()
        public = bytes.fromhex(self.meta["public_key"]) if self.meta.get("public_key") else None
        prev = GENESIS
        entries = self.entries()
        res.entries = len(entries)
        for e in entries:
            body = {k: v for k, v in e.items() if k not in ("hash", "signature")}
            if e.get("prev_hash") != prev:
                res.problems.append(Problem("custody", f"entry {e.get('seq')} does not follow entry {e.get('seq', 1) - 1} "
                                                       "(an entry was removed, reordered or inserted)"))
            if hashlib.sha256(_canonical(body)).hexdigest() != e.get("hash"):
                res.problems.append(Problem("custody", f"entry {e.get('seq')} was modified after it was written"))
            if public is not None:
                sig = e.get("signature")
                try:
                    valid = bool(sig) and ed25519_verify(public, bytes.fromhex(e["hash"]), bytes.fromhex(sig))
                except ValueError:
                    valid = False
                if not valid:
                    res.problems.append(Problem("custody", f"entry {e.get('seq')} has a missing or invalid signature"))
            prev = e.get("hash")
        for item in self.evidence():
            res.evidence += 1
            path = self.root / item["stored_as"]
            if not path.is_file():
                res.problems.append(Problem("evidence", f"{item['stored_as']} is missing"))
            elif _sha256_file(path) != item["sha256"]:
                res.problems.append(Problem("evidence", f"{item['stored_as']} no longer matches sha256 {item['sha256']}"))
            elif stat.S_IMODE(path.stat().st_mode) & 0o222:
                res.problems.append(Problem("evidence", f"{item['stored_as']} is writable (expected read-only)"))
        latest: dict[str, dict] = {}  # re-analysis overwrites report files: check the newest record
        for e in entries:
            if e["action"] == "analyzed":
                for meta in e["details"].get("reports", {}).values():
                    latest[meta["file"]] = meta
        for meta in latest.values():
            res.reports += 1
            path = self.root / meta["file"]
            if not path.is_file():
                res.problems.append(Problem("report", f"{meta['file']} is missing"))
                continue
            if _sha256_file(path) != meta["sha256"]:
                res.problems.append(Problem("report", f"{meta['file']} was changed after analysis"))
            if public is not None:
                sig_path = path.parent / f"{path.name}.sig"
                try:
                    sig = json.loads(sig_path.read_text())
                    ok = ed25519_verify(public, bytes.fromhex(meta["sha256"]), bytes.fromhex(sig["signature"]))
                except (OSError, ValueError, KeyError):
                    ok = False
                if not ok:
                    res.problems.append(Problem("report", f"{meta['file']} has a missing or invalid signature"))
        return res


def _csv_cell(value: str) -> str:
    value = csv_safe(str(value))
    if any(c in value for c in ',"\n\r'):
        value = '"' + value.replace('"', '""') + '"'
    return value


def verify_signature(file: str | Path, signature_file: str | Path | None = None, public_key: str | None = None) -> bool:
    """Verify a report signature (for recipients of an exported report)."""
    file = Path(file)
    sig = json.loads(Path(signature_file or f"{file}.sig").read_text(encoding="utf-8"))
    key = bytes.fromhex(public_key or sig["public_key"])
    digest = _sha256_file(file)
    return digest == sig["sha256"] and ed25519_verify(key, bytes.fromhex(digest), bytes.fromhex(sig["signature"]))
