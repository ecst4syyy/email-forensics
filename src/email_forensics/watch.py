"""Drop-folder automation: ``email-forensics watch INBOX --output-dir OUT``.

Polls a directory for new .eml/.msg/mbox files and analyses each exactly once
(tracked by SHA-256 in ``OUT/.processed``, so renames and restarts do not cause
re-analysis). For every file it writes a report next to the others in OUT
(``<sha256>.<ext>``) and appends one JSON line per message to ``OUT/events.jsonl``
for a SIEM forwarder (Filebeat, Splunk UF, ...) to pick up. A file is only read
once its size and mtime have stopped changing, so half-copied files are skipped
until the copy finishes. Input files are never modified or moved.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from .analyzer import AnalysisOptions, analyze_path
from .loader import EvidenceError
from .report import to_json, to_text
from .report_html import render_html
from .siem import to_jsonl

SUFFIXES = {".eml", ".msg", ".mbox", ".mbx", ".txt", ""}
FORMATS = {"json": ".json", "html": ".html", "text": ".txt", "none": ""}


class Watcher:
    def __init__(self, inbox: str | Path, output_dir: str | Path, options: AnalysisOptions | None = None,
                 report_format: str = "json", settle: float = 2.0, all_files: bool = False,
                 on_report: Callable | None = None):
        self.inbox = Path(inbox)
        if not self.inbox.is_dir():
            raise ValueError(f"not a directory: {inbox}")
        self.out = Path(output_dir)
        if self.out.resolve() == self.inbox.resolve():
            raise ValueError("the output directory must not be the watched directory")
        self.out.mkdir(parents=True, exist_ok=True)
        self.options = options or AnalysisOptions()
        self.report_format = report_format
        self.settle = settle
        self.all_files = all_files
        self.on_report = on_report
        self.state_file = self.out / ".processed"
        self.processed: set[str] = set()
        if self.state_file.exists():
            self.processed = {line.split()[0] for line in self.state_file.read_text(encoding="utf-8").splitlines()
                              if line.strip()}
        self._seen: dict[Path, tuple[int, int, float]] = {}  # path -> (size, mtime_ns, first time stable)

    def _candidates(self) -> list[Path]:
        files = []
        for p in sorted(self.inbox.iterdir()):
            if p.name.startswith(".") or not p.is_file() or p.is_symlink():
                continue
            if self.all_files or p.suffix.lower() in SUFFIXES:
                files.append(p)
        return files

    def _stable(self, path: Path, now: float) -> bool:
        st = path.stat()
        key = (st.st_size, st.st_mtime_ns)
        prev = self._seen.get(path)
        if prev is None or prev[:2] != key:
            self._seen[path] = (*key, now)
            return self.settle <= 0
        return now - prev[2] >= self.settle

    def poll(self) -> int:
        """Process every new, settled file once. Returns the number of files processed."""
        now = time.monotonic()
        done = 0
        for path in self._candidates():
            try:
                if not self._stable(path, now):
                    continue
                digest = _sha256(path)
            except OSError:
                continue  # vanished or unreadable; try again next poll
            if digest in self.processed:
                self._seen.pop(path, None)
                continue
            self._process(path, digest)
            self._seen.pop(path, None)
            done += 1
        return done

    def _process(self, path: Path, digest: str) -> None:
        try:
            reports = list(analyze_path(path, self.options))
            error = None
        except (EvidenceError, OSError) as exc:
            reports, error = [], str(exc)
        if reports:
            with open(self.out / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(to_jsonl(reports) + "\n")
            ext = FORMATS[self.report_format]
            if ext:
                text = {"json": lambda: to_json(reports[0]) if len(reports) == 1
                        else json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False),
                        "html": lambda: render_html(reports),
                        "text": lambda: "\n\n".join(to_text(r) for r in reports)}[self.report_format]()
                target = self.out / f"{digest}{ext}"
                tmp = target.with_suffix(ext + ".tmp")
                tmp.write_text(text + "\n", encoding="utf-8", errors="backslashreplace")
                os.replace(tmp, target)
        else:
            with open(self.out / "errors.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"path": str(path), "sha256": digest, "error": error}) + "\n")
        with open(self.state_file, "a", encoding="utf-8") as fh:
            fh.write(f"{digest} {path.name}\n")
        self.processed.add(digest)
        if self.on_report:
            self.on_report(path, reports, error)

    def run(self, interval: float = 5.0, once: bool = False) -> None:
        if once:
            # settle immediately on a one-shot run: files already in the folder are complete
            self.settle, saved = 0.0, self.settle
            try:
                self.poll()
            finally:
                self.settle = saved
            return
        try:
            while True:
                self.poll()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
