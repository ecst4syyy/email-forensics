"""Static analysis of script payloads (JS, VBS, PowerShell, batch, HTA, WSF, shell)."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

SCRIPT_EXTENSIONS = frozenset("js jse vbs vbe ps1 psm1 psd1 bat cmd hta wsf wsh wsc sct sh bash command".split())
MAX_TEXT = 5_000_000

INDICATORS = (
    ("downloader", r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|\bwget\b|curl\s+-|"
                   r"Start-BitsTransfer|bitsadmin\s+/transfer|certutil\s+.*-urlcache|XMLHTTP|WinHttp|"
                   r"URLDownloadToFile|Net\.WebClient|Invoke-RestMethod|\birm\b"),
    ("execution", r"Invoke-Expression|\bIEX\b|Start-Process|WScript\.Shell|Shell\.Application|ShellExecute|"
                  r"\.Run\s*\(|\.Exec\s*\(|cmd(?:\.exe)?\s*/[ck]|mshta|rundll32|regsvr32|wmic\s+process|"
                  r"powershell(?:\.exe)?|pwsh|cscript|wscript|msiexec\s+/[iq]|schtasks\s+/create"),
    ("obfuscation", r"FromBase64String|-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}|\beval\s*\(|unescape\s*\(|"
                    r"String\.fromCharCode|\[char\]\s*\d+|-join\s*\(|\bchr\s*\(\s*\d+\s*\)\s*&|"
                    r"#@~\^|StrReverse|\^.\^.\^|-bxor|\[Convert\]::"),
    ("persistence", r"CurrentVersion\\Run|schtasks|New-ScheduledTask|Startup\\|New-Service|sc\s+create|"
                    r"Register-ScheduledJob|HKCU:|HKLM:"),
    ("defense evasion", r"Set-MpPreference|Add-MpPreference|-ExclusionPath|DisableRealtimeMonitoring|"
                        r"AmsiUtils|amsiInitFailed|-ExecutionPolicy\s+Bypass|-ep\s+bypass|-w(?:indowstyle)?\s+hidden|"
                        r"-nop\b|-NonInteractive|bcdedit|wevtutil\s+cl"),
    ("ransomware", r"vssadmin\s+delete\s+shadows|wbadmin\s+delete|shadowcopy\s+delete|cipher\s+/w"),
    ("system recon", r"whoami|systeminfo|ipconfig|net\s+(?:user|group|view)|nltest|Get-WmiObject|Win32_"),
)
_INDICATORS = [(name, re.compile(p, re.I)) for name, p in INDICATORS]
_ENC_RE = re.compile(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})", re.I)
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>)\]}]+", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


@dataclass
class ScriptAnalysis:
    indicators: dict[str, list[str]] = field(default_factory=dict)
    decoded_commands: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    encoded_script: bool = False  # JScript.Encode / VBScript.Encode
    long_base64: int = 0


def analyze_script(text: str, depth: int = 0) -> ScriptAnalysis:
    text = text[:MAX_TEXT]
    res = ScriptAnalysis()
    for name, regex in _INDICATORS:
        hits = sorted({m.group(0).strip()[:60] for m in regex.finditer(text)}, key=str.lower)
        if hits:
            res.indicators[name] = hits[:10]
    res.encoded_script = "#@~^" in text
    res.long_base64 = len(_LONG_B64_RE.findall(text))
    for m in _ENC_RE.finditer(text):
        decoded = _decode_powershell(m.group(1))
        if decoded:
            res.decoded_commands.append(decoded[:2000])
            if depth < 2:
                inner = analyze_script(decoded, depth + 1)
                for k, v in inner.indicators.items():
                    res.indicators[k] = sorted(set(res.indicators.get(k, [])) | set(v), key=str.lower)[:10]
                text += "\n" + decoded
    res.urls = list(dict.fromkeys(u.rstrip(".,;'\"") for u in _URL_RE.findall(text)))[:100]
    res.ips = list(dict.fromkeys(_IP_RE.findall(text)))[:50]
    return res


def _decode_powershell(value: str) -> str | None:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) > 0.9:
            return text
    return None
