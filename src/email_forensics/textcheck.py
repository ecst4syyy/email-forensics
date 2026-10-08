"""Detection of invisible and direction-changing Unicode characters."""

from __future__ import annotations

from .models import Finding, Severity

# Zero-width characters used to split keywords past filters ("Pay​Pal").
# U+200D (zero-width joiner) is excluded: emoji sequences use it legitimately.
ZERO_WIDTH = {"​", "‌", "⁠", "᠎", "­", "﻿"}
# Bidirectional controls, e.g. RIGHT-TO-LEFT OVERRIDE makes "gpj.exe" display as "exe.jpg".
BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}


def invisible_char_counts(text: str | None) -> tuple[int, int]:
    """Return (zero_width_count, bidi_count). A leading BOM is ignored."""
    if not text:
        return 0, 0
    text = text.removeprefix("﻿")
    zw = sum(1 for ch in text if ch in ZERO_WIDTH)
    bidi = sum(1 for ch in text if ch in BIDI_CONTROLS)
    return zw, bidi


def invisible_char_findings(location: str, text: str | None, prominent: bool) -> list[Finding]:
    """Findings for invisible characters in `text`.

    `prominent` locations (subject, sender name, filenames) are rated higher than
    body text, since there is no legitimate reason to hide characters there.
    """
    zw, bidi = invisible_char_counts(text)
    out = []
    if bidi:
        out.append(Finding(
            "TEXT_BIDI_CONTROL", Severity.HIGH if prominent else Severity.MEDIUM,
            f"{location} contains {bidi} bidirectional control character(s) that can reverse displayed text.",
            {"location": location, "count": bidi},
        ))
    if zw:
        out.append(Finding(
            "TEXT_ZERO_WIDTH", Severity.MEDIUM if prominent else Severity.LOW,
            f"{location} contains {zw} zero-width/invisible character(s), often used to evade keyword filters.",
            {"location": location, "count": zw},
        ))
    return out


def safe_display(text: str | None, keep_newlines: bool = False) -> str:
    """Escape invisible, bidi and control characters so attacker text can't alter the display."""
    if text is None:
        return ""
    allowed = "\t\n" if keep_newlines else "\t"
    out = []
    for ch in text:
        if ch in ZERO_WIDTH or ch in BIDI_CONTROLS or ch == "\u200d" or (ord(ch) < 32 and ch not in allowed) or 0x7F <= ord(ch) < 0xA0:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)
