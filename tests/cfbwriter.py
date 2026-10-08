"""Minimal MS-CFB (version 3) writer for building test fixtures.

Streams smaller than 4096 bytes go to the mini stream, larger ones to regular
sectors, as the specification requires. Output is validated against olefile in
the tests (when installed), so fixtures do not depend on our own reader.
"""

from __future__ import annotations

import struct

SECTOR = 512
MINI = 64
CUTOFF = 4096
ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\x00" * (-len(data) % size)


def _sort_key(name: str):
    return (len(name), name.upper())


def build_cfb(streams: dict[str, bytes], clsids: dict[str, bytes] | None = None) -> bytes:
    """streams: {"Storage/Sub/Stream": data}. Storages are created implicitly."""
    clsids = clsids or {}
    nodes: dict[tuple, dict] = {(): {"name": "Root Entry", "type": 5, "children": []}}
    for path, data in streams.items():
        parts = tuple(path.split("/"))
        for i in range(1, len(parts)):
            key = parts[:i]
            if key not in nodes:
                nodes[key] = {"name": parts[i - 1], "type": 1, "children": []}
                nodes[parts[:i - 1]]["children"].append(key)
        nodes[parts] = {"name": parts[-1], "type": 2, "children": [], "data": data}
        nodes[parts[:-1]]["children"].append(parts)

    order = [()] + [k for k in nodes if k != ()]
    sid = {k: i for i, k in enumerate(order)}

    mini_data, mini_chains = b"", {}
    big = {}
    for k in order:
        n = nodes[k]
        if n["type"] != 2:
            continue
        if len(n["data"]) < CUTOFF:
            start = len(mini_data) // MINI
            count = (len(n["data"]) + MINI - 1) // MINI
            mini_chains[k] = (start, count)
            mini_data += _pad(n["data"], MINI)
        else:
            big[k] = n["data"]
    minifat = []
    for k, (start, count) in mini_chains.items():
        minifat += [start + i + 1 for i in range(count - 1)] + ([ENDOFCHAIN] if count else [])
    minifat_bytes = _pad(struct.pack(f"<{len(minifat)}I", *minifat), SECTOR) if minifat else b""

    dir_sectors = (len(order) * 128 + SECTOR - 1) // SECTOR
    minifat_sectors = len(minifat_bytes) // SECTOR
    ministream_sectors = (len(mini_data) + SECTOR - 1) // SECTOR
    big_sectors = {k: (len(v) + SECTOR - 1) // SECTOR for k, v in big.items()}
    content = dir_sectors + minifat_sectors + ministream_sectors + sum(big_sectors.values())
    num_fat = 1
    while num_fat * (SECTOR // 4) < num_fat + content:
        num_fat += 1

    fat: list[int] = [FATSECT] * num_fat
    pos = num_fat

    def chain(count: int) -> int:
        nonlocal pos
        if count == 0:
            return ENDOFCHAIN
        start = pos
        fat.extend([pos + i + 1 for i in range(count - 1)] + [ENDOFCHAIN])
        pos += count
        return start

    dir_start = chain(dir_sectors)
    minifat_start = chain(minifat_sectors)
    ministream_start = chain(ministream_sectors)
    big_start = {k: chain(c) for k, c in big_sectors.items()}
    fat += [FREESECT] * (num_fat * (SECTOR // 4) - len(fat))

    def entry(k) -> bytes:
        n = nodes[k]
        name = n["name"].encode("utf-16-le") + b"\x00\x00"
        children = sorted(n["children"], key=lambda c: _sort_key(nodes[c]["name"]))
        child = sid[children[0]] if children else NOSTREAM
        right = NOSTREAM
        if k != ():
            sibs = sorted(nodes[k[:-1]]["children"], key=lambda c: _sort_key(nodes[c]["name"]))
            i = sibs.index(k)
            right = sid[sibs[i + 1]] if i + 1 < len(sibs) else NOSTREAM
        if n["type"] == 5:
            start, size = (ministream_start if mini_data else ENDOFCHAIN), len(mini_data)
        elif n["type"] == 2:
            size = len(n["data"])
            start = mini_chains[k][0] if k in mini_chains else big_start[k]
            if size == 0:
                start = ENDOFCHAIN
        else:
            start, size = 0, 0
        clsid = clsids.get("/".join(k), b"\x00" * 16)
        return (_pad(name, 64)[:64] + struct.pack("<HBB", len(name), n["type"], 1)
                + struct.pack("<III", NOSTREAM, right, child) + clsid + b"\x00" * 4
                + b"\x00" * 16 + struct.pack("<III", start, size, 0))

    directory = _pad(b"".join(entry(k) for k in order), SECTOR)
    header = bytearray(SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIII", header, 0x2C, num_fat, dir_start, 0, CUTOFF,
                     minifat_start if minifat_sectors else ENDOFCHAIN, minifat_sectors, ENDOFCHAIN, 0)
    difat = list(range(num_fat)) + [FREESECT] * (109 - num_fat)
    struct.pack_into("<109I", header, 0x4C, *difat)

    body = struct.pack(f"<{len(fat)}I", *fat) + directory + minifat_bytes + _pad(mini_data, SECTOR)
    for k in big:
        body += _pad(big[k], SECTOR)
    return bytes(header) + body


def vba_compress(data: bytes) -> bytes:
    """MS-OVBA 'compression' using literal tokens only (valid, just not smaller)."""
    out = bytearray(b"\x01")
    for i in range(0, len(data), 3640):  # literal-only chunks must stay under 4098 bytes
        chunk = data[i:i + 3640]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            body.append(0)
            body += chunk[j:j + 8]
        out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def build_vba_project(modules: dict[str, str], codepage: int = 1252) -> dict[str, bytes]:
    """Streams for a VBA project storage ("VBA/dir", "VBA/<module>", "PROJECT")."""
    def rec(rid: int, data: bytes) -> bytes:
        return struct.pack("<HI", rid, len(data)) + data

    d = bytearray()
    d += rec(0x0001, struct.pack("<I", 1))  # PROJECTSYSKIND win32
    d += rec(0x0002, struct.pack("<I", 0x409))  # LCID
    d += rec(0x0014, struct.pack("<I", 0x409))
    d += rec(0x0003, struct.pack("<H", codepage))
    d += rec(0x0004, b"VBAProject")
    d += rec(0x0005, b"") + rec(0x0040, b"")
    d += rec(0x0006, b"") + rec(0x003D, b"")
    d += rec(0x0007, struct.pack("<I", 0)) + rec(0x0008, struct.pack("<I", 0))
    d += struct.pack("<HIIH", 0x0009, 4, 0, 0)  # PROJECTVERSION: size says 4, data is 6 bytes
    d += rec(0x000C, b"") + rec(0x003C, b"")  # PROJECTCONSTANTS
    d += rec(0x000F, struct.pack("<H", len(modules))) + rec(0x0013, struct.pack("<H", 0xFFFF))
    streams = {}
    for name, code in modules.items():
        n = name.encode("latin-1")
        d += rec(0x0019, n) + rec(0x0047, name.encode("utf-16-le"))
        d += rec(0x001A, n) + rec(0x0032, name.encode("utf-16-le"))
        d += rec(0x001C, b"") + rec(0x0048, b"")
        d += rec(0x0031, struct.pack("<I", 0))  # MODULEOFFSET: source starts at 0
        d += rec(0x001E, struct.pack("<I", 0)) + rec(0x002C, struct.pack("<H", 0))
        d += rec(0x0021, b"") + rec(0x002B, b"")
        streams[f"VBA/{name}"] = vba_compress(code.encode("cp1252"))
    d += struct.pack("<HI", 0x0010, 0)
    streams["VBA/dir"] = vba_compress(bytes(d))
    streams["VBA/_VBA_PROJECT"] = b"\xcc\x61\xff\xff\x00"
    streams["PROJECT"] = ("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n"
                          + "".join(f"Module={m}\r\n" for m in modules)).encode()
    return streams


def ole10native(filename: str, payload: bytes) -> bytes:
    """An "\\x01Ole10Native" stream packaging a file (how Office embeds files)."""
    name = filename.encode("latin-1") + b"\x00"
    path = (f"C:\\Users\\a\\Desktop\\{filename}").encode("latin-1") + b"\x00"
    temp = (f"C:\\Users\\a\\AppData\\Local\\Temp\\{filename}").encode("latin-1") + b"\x00"
    inner = struct.pack("<H", 2) + name + path + struct.pack("<HH", 0, 3) + struct.pack("<I", len(temp)) + temp
    inner += struct.pack("<I", len(payload)) + payload
    return struct.pack("<I", len(inner)) + inner


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _props_stream(header: bytes, fixed: list[tuple[int, int, bytes]]) -> bytes:
    """__properties_version1.0: header + 16-byte entries (tag, flags, 8-byte value)."""
    return header + b"".join(struct.pack("<II", (pid << 16) | ptype, 6) + value.ljust(8, b"\x00")[:8]
                             for pid, ptype, value in fixed)


def _filetime(epoch_seconds: int) -> bytes:
    return struct.pack("<Q", (epoch_seconds + 11_644_473_600) * 10_000_000)


def msg_streams(prefix: str, *, subject: str, body: str | None = None, html: bytes | None = None,
                transport_headers: str | None = None, sender: tuple[str, str] | None = None,
                recipients: list[tuple[str, str, int]] = (), attachments: list[dict] = (),
                submit_time: int | None = None, rtf: bytes | None = None, embedded: bool = False) -> dict[str, bytes]:
    """Streams for one MAPI message object rooted at `prefix` ("" for the top level)."""
    p = f"{prefix}/" if prefix else ""
    s: dict[str, bytes] = {}
    s[p + "__substg1.0_001A001F"] = _utf16("IPM.Note")
    s[p + "__substg1.0_0037001F"] = _utf16(subject)
    if body is not None:
        s[p + "__substg1.0_1000001F"] = _utf16(body)
    if html is not None:
        s[p + "__substg1.0_10130102"] = html
    if rtf is not None:
        s[p + "__substg1.0_10090102"] = rtf
    if transport_headers is not None:
        s[p + "__substg1.0_007D001F"] = _utf16(transport_headers)
    if sender:
        s[p + "__substg1.0_0C1A001F"] = _utf16(sender[0])
        s[p + "__substg1.0_0C1F001F"] = _utf16(sender[1])
        s[p + "__substg1.0_5D01001F"] = _utf16(sender[1])
    fixed = []
    if submit_time is not None:
        fixed += [(0x0039, 0x0040, _filetime(submit_time)), (0x0E06, 0x0040, _filetime(submit_time + 5))]
    header = (struct.pack("<8xIIII", len(recipients), len(attachments), len(recipients), len(attachments))
              + (b"" if embedded else b"\x00" * 8))
    s[p + "__properties_version1.0"] = _props_stream(header, fixed)
    for i, (name, addr, rtype) in enumerate(recipients):
        r = f"{p}__recip_version1.0_#{i:08X}/"
        s[r + "__substg1.0_3001001F"] = _utf16(name)
        s[r + "__substg1.0_39FE001F"] = _utf16(addr)
        s[r + "__substg1.0_3003001F"] = _utf16(addr)
        s[r + "__properties_version1.0"] = _props_stream(b"\x00" * 8, [(0x0C15, 0x0003, struct.pack("<I", rtype))])
    for i, att in enumerate(attachments):
        a = f"{p}__attach_version1.0_#{i:08X}/"
        s[a + "__substg1.0_3707001F"] = _utf16(att["filename"])
        s[a + "__substg1.0_3704001F"] = _utf16(att["filename"][:12])
        if "message" in att:  # embedded .msg (attach method 5)
            s[a + "__properties_version1.0"] = _props_stream(b"\x00" * 8, [(0x3705, 0x0003, struct.pack("<I", 5))])
            s.update(msg_streams(a + "__substg1.0_3701000D", embedded=True, **att["message"]))
        else:
            s[a + "__substg1.0_370E001F"] = _utf16(att.get("mime", "application/octet-stream"))
            s[a + "__substg1.0_37010102"] = att["data"]
            s[a + "__properties_version1.0"] = _props_stream(b"\x00" * 8, [(0x3705, 0x0003, struct.pack("<I", 1))])
    if not prefix:
        for n in ("00020102", "00030102", "00040102"):
            s[f"__nameid_version1.0/__substg1.0_{n}"] = b""
    return s


def build_msg(**kwargs) -> bytes:
    return build_cfb(msg_streams("", **kwargs))
