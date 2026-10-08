"""Optional YARA scanning (requires ``pip install yara-python``).

Scans the raw message, every decoded body and attachment, and archive members
(read within the archive safety limits). Rule metadata controls the finding:
``severity`` (info/low/medium/high, default high) and ``description``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import filetype as ft
from .archives import INSPECTABLE, inspect_archive
from .mime import MimeTree
from .models import Finding, Severity

SCAN_TIMEOUT = 10  # seconds per target
MAX_TARGETS = 2000
MAX_MATCHES = 200
RULE_SUFFIXES = (".yar", ".yara", ".rule", ".rules")


class YaraUnavailable(RuntimeError):
    pass


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    target: str  # "message", "part 1.2 (invoice.zip)", "part 1.2 (invoice.zip) > docs/a.exe"
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)  # identifiers and offsets, never matched data


def compile_rules(paths: list[str | Path]):
    try:
        import yara
    except ImportError as exc:
        raise YaraUnavailable("YARA scanning needs yara-python: pip install yara-python") from exc
    files: dict[str, str] = {}
    for p in map(Path, paths):
        candidates = sorted(x for x in p.rglob("*") if x.suffix.lower() in RULE_SUFFIXES) if p.is_dir() else [p]
        for f in candidates:
            if not f.is_file():
                raise FileNotFoundError(f"YARA rules not found: {f}")
            ns = f.stem
            while ns in files:
                ns += "_"
            files[ns] = str(f)
    if not files:
        raise FileNotFoundError(f"no YARA rule files in {', '.join(map(str, paths))}")
    try:
        return yara.compile(filepaths=files)
    except yara.Error as exc:
        raise ValueError(f"YARA rules do not compile: {exc}") from exc


def derived_targets(attachments) -> list[tuple[str, bytes]]:
    """Content the analyzers decoded that is invisible in the raw bytes: decompressed VBA
    source, decoded PowerShell, PDF JavaScript and shortcut command lines."""
    out = []
    for att in attachments:
        pa, name = att.payload, att.filename or f"part {att.part}"
        if pa is None:
            continue
        if pa.office:
            out += [(f"{name} VBA {m.name}", m.preview.encode("utf-8", "replace")) for m in pa.office.vba if m.preview]
            out += [(f"{name} XLM", "\n".join(pa.office.xlm_macros).encode())] if pa.office.xlm_macros else []
        if pa.pdf:
            out += [(f"{name} PDF JavaScript #{i}", js.encode("latin-1", "replace")) for i, js in enumerate(pa.pdf.javascript)]
        if pa.script:
            out += [(f"{name} decoded command #{i}", c.encode()) for i, c in enumerate(pa.script.decoded_commands)]
        if pa.lnk and pa.lnk.arguments:
            out.append((f"{name} shortcut command line",
                        f"{pa.lnk.target or ''} {pa.lnk.arguments}".encode("utf-8", "replace")))
    return out


def scan(rules, raw: bytes, tree: MimeTree, body_texts: list[tuple[str, str]],
         attachments=()) -> tuple[list[YaraMatch], list[Finding]]:
    targets: list[tuple[str, bytes]] = [("message", raw)]
    targets += derived_targets(attachments)
    targets += [(f"body {part}", text.encode("utf-8", "replace")) for part, text in body_texts]
    for leaf in tree.leaves:
        info = leaf.info
        label = f"part {info.path}" + (f" ({info.filename})" if info.filename else "")
        targets.append((label, leaf.payload))
        t = ft.detect(leaf.payload)
        if t and t.id in INSPECTABLE:
            inspect_archive(leaf.payload, t, visitor=lambda path, data, label=label: targets.append((f"{label} > {path}", data)))
    matches: list[YaraMatch] = []
    errors: list[str] = []
    for target, data in targets[:MAX_TARGETS]:
        try:
            results = rules.match(data=data, timeout=SCAN_TIMEOUT)
        except Exception as exc:  # yara.TimeoutError, yara.Error
            errors.append(f"{target}: {exc}")
            continue
        for m in results:
            strings = []
            for s in getattr(m, "strings", [])[:10]:
                instances = getattr(s, "instances", None)
                if instances is not None:  # yara-python >= 4.3
                    strings.append(f"{s.identifier}@{instances[0].offset}" if instances else s.identifier)
                else:  # older tuples (offset, identifier, data)
                    strings.append(f"{s[1]}@{s[0]}")
            matches.append(YaraMatch(m.rule, m.namespace, target, list(m.tags), dict(m.meta), strings))
            if len(matches) >= MAX_MATCHES:
                break
    return matches, _findings(matches, errors)


def _findings(matches: list[YaraMatch], errors: list[str]) -> list[Finding]:
    out = []
    for m in matches:
        sev_name = str(m.meta.get("severity", "high")).lower()
        try:
            sev = Severity(sev_name)
        except ValueError:
            sev = Severity.HIGH
        desc = m.meta.get("description") or m.meta.get("desc")
        out.append(Finding("YARA_MATCH", sev, f"YARA rule {m.namespace}:{m.rule} matched {m.target}"
                           + (f": {desc}" if desc else "") + ".",
                           {"rule": m.rule, "namespace": m.namespace, "target": m.target, "tags": m.tags,
                            "meta": m.meta, "strings": m.strings}))
    if errors:
        out.append(Finding("YARA_ERRORS", Severity.LOW, f"YARA could not scan {len(errors)} target(s).",
                           {"errors": errors[:10]}))
    return out
