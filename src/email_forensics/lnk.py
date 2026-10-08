"""Windows shortcut (.lnk, MS-SHLLINK) parsing.

Shortcuts are a common email payload: the "document" is a link that runs
PowerShell or mshta. The parser recovers the target, arguments, icon and the
NetBIOS name of the machine that created the file (TrackerDataBlock).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

LNK_HEADER = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"
_SHOW = {1: "normal", 3: "maximized", 7: "minimized (no focus)"}


@dataclass
class LnkInfo:
    target: str | None = None
    arguments: str | None = None
    working_dir: str | None = None
    icon: str | None = None
    name: str | None = None
    relative_path: str | None = None
    env_target: str | None = None
    machine_id: str | None = None
    show_command: str | None = None
    error: str | None = None


def parse_lnk(data: bytes) -> LnkInfo:
    info = LnkInfo()
    try:
        if not data.startswith(LNK_HEADER):
            raise ValueError("not a shell link")
        flags = struct.unpack_from("<I", data, 20)[0]
        show = struct.unpack_from("<I", data, 60)[0]
        info.show_command = _SHOW.get(show, str(show))
        unicode = bool(flags & 0x80)
        pos = 0x4C
        if flags & 0x01:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        if flags & 0x02:  # HasLinkInfo
            size, header_size = struct.unpack_from("<II", data, pos)
            local_off = struct.unpack_from("<I", data, pos + 16)[0]
            if local_off:
                info.target = _cstr(data, pos + local_off)
            if header_size >= 0x24:
                uoff = struct.unpack_from("<I", data, pos + 28)[0]
                if uoff:
                    info.target = _wstr(data, pos + uoff) or info.target
            pos += size
        for flag, attr in ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_dir"),
                           (0x20, "arguments"), (0x40, "icon")):
            if flags & flag:
                count = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                width = 2 if unicode else 1
                raw = data[pos:pos + count * width]
                setattr(info, attr, raw.decode("utf-16-le" if unicode else "cp1252", "replace"))
                pos += count * width
        # ExtraData blocks
        for _ in range(64):
            if pos + 8 > len(data):
                break
            size, sig = struct.unpack_from("<II", data, pos)
            if size < 4:
                break
            if sig == 0xA0000001 and size >= 788:  # EnvironmentVariableDataBlock
                info.env_target = _wstr(data, pos + 268, 260) or _cstr(data, pos + 8, 260)
            elif sig == 0xA0000003 and size >= 96:  # TrackerDataBlock
                info.machine_id = data[pos + 16:pos + 32].split(b"\x00", 1)[0].decode("latin-1") or None
            pos += size
    except (ValueError, struct.error, IndexError) as exc:
        info.error = str(exc)
    return info


def _cstr(data: bytes, pos: int, limit: int = 1024) -> str:
    end = data.find(b"\x00", pos, pos + limit)
    return data[pos:end if end >= 0 else pos + limit].decode("cp1252", "replace")


def _wstr(data: bytes, pos: int, limit: int = 1024) -> str:
    chunk = data[pos:pos + limit * 2]
    for i in range(0, len(chunk) - 1, 2):
        if chunk[i:i + 2] == b"\x00\x00":
            chunk = chunk[:i]
            break
    return chunk.decode("utf-16-le", "replace")
