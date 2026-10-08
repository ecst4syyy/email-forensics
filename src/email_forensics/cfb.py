"""Read-only parser for Microsoft Compound File Binary (MS-CFB, "OLE2") containers.

Used for legacy Office documents, ``vbaProject.bin`` inside OOXML, and Outlook
``.msg`` files. The format is a small FAT filesystem; every pointer comes from
the (untrusted) file, so chains are bounded and cycles rejected.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAX_STREAM_SIZE = 64 * 1024 * 1024
MAX_ENTRIES = 100_000

TYPE_STORAGE, TYPE_STREAM, TYPE_ROOT = 1, 2, 5


class CfbError(ValueError):
    pass


@dataclass
class DirEntry:
    sid: int
    name: str
    type: int
    left: int
    right: int
    child: int
    clsid: str
    created: datetime | None
    modified: datetime | None
    start: int
    size: int
    path: tuple[str, ...] = ()
    children: list[int] = field(default_factory=list)

    @property
    def is_stream(self) -> bool:
        return self.type == TYPE_STREAM

    @property
    def is_storage(self) -> bool:
        return self.type in (TYPE_STORAGE, TYPE_ROOT)


def _filetime(value: int) -> datetime | None:
    if not value:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


class CompoundFile:
    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or not data.startswith(SIGNATURE):
            raise CfbError("not a compound file")
        self.data = data
        (minor, major, byte_order, sector_shift, mini_shift) = struct.unpack_from("<HHHHH", data, 0x18)
        if byte_order != 0xFFFE or sector_shift not in (9, 12) or mini_shift != 6:
            raise CfbError("unsupported compound file header")
        self.sector_size = 1 << sector_shift
        self.mini_size = 1 << mini_shift
        (self.num_fat, self.first_dir, _, self.mini_cutoff, self.first_minifat, self.num_minifat,
         self.first_difat, self.num_difat) = struct.unpack_from("<IIIIIIII", data, 0x2C)
        self.max_sectors = max(0, (len(data) - self.sector_size) // self.sector_size + 1)
        self.fat = self._load_fat()
        self.entries = self._load_directory()
        root = self.entries[0]
        self._ministream = self._read_chain(root.start, self.fat, root.size) if root.size else b""
        self.minifat = self._load_minifat()
        self._index: dict[tuple[str, ...], DirEntry] = {}
        self._build_tree()

    # -- low level ------------------------------------------------------------------
    def _sector(self, sid: int) -> bytes:
        if sid >= self.max_sectors:
            raise CfbError(f"sector {sid} out of range")
        off = (sid + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    def _load_fat(self) -> list[int]:
        difat = list(struct.unpack_from("<109I", self.data, 0x4C))
        sid, seen = self.first_difat, set()
        per = self.sector_size // 4 - 1
        for _ in range(self.num_difat):
            if sid in (ENDOFCHAIN, FREESECT) or sid in seen:
                break
            seen.add(sid)
            values = struct.unpack(f"<{per + 1}I", self._sector(sid))
            difat.extend(values[:per])
            sid = values[per]
        fat: list[int] = []
        for fsid in difat[: self.num_fat]:
            if fsid in (FREESECT, ENDOFCHAIN):
                continue
            fat.extend(struct.unpack(f"<{self.sector_size // 4}I", self._sector(fsid)))
        return fat

    def _chain(self, start: int, table: list[int], limit: int) -> list[int]:
        chain, seen, sid = [], set(), start
        while sid not in (ENDOFCHAIN, FREESECT) and sid < len(table):
            if sid in seen or len(chain) > limit:
                raise CfbError("sector chain loops or is too long")
            seen.add(sid)
            chain.append(sid)
            sid = table[sid]
        return chain

    def _read_chain(self, start: int, table: list[int], size: int | None = None) -> bytes:
        if size is not None and size > MAX_STREAM_SIZE:
            raise CfbError("stream too large")
        limit = (size // self.sector_size + 2) if size is not None else self.max_sectors
        data = b"".join(self._sector(s) for s in self._chain(start, table, limit))
        return data[:size] if size is not None else data

    def _load_minifat(self) -> list[int]:
        if self.first_minifat in (ENDOFCHAIN, FREESECT) or not self.num_minifat:
            return []
        raw = self._read_chain(self.first_minifat, self.fat, self.num_minifat * self.sector_size)
        return list(struct.unpack(f"<{len(raw) // 4}I", raw[: len(raw) // 4 * 4]))

    def _load_directory(self) -> list[DirEntry]:
        raw = self._read_chain(self.first_dir, self.fat)
        entries = []
        for i in range(min(len(raw) // 128, MAX_ENTRIES)):
            e = raw[i * 128:(i + 1) * 128]
            name_len = struct.unpack_from("<H", e, 64)[0]
            name = e[: max(0, min(name_len, 64) - 2)].decode("utf-16-le", "replace")
            etype = e[66]
            left, right, child = struct.unpack_from("<III", e, 68)
            clsid = e[80:96].hex()
            ctime, mtime = struct.unpack_from("<QQ", e, 100)
            start, size_lo, size_hi = struct.unpack_from("<III", e, 116)
            size = size_lo if self.sector_size == 512 else size_lo | (size_hi << 32)
            entries.append(DirEntry(i, name, etype, left, right, child, clsid,
                                    _filetime(ctime), _filetime(mtime), start, size))
        if not entries or entries[0].type != TYPE_ROOT:
            raise CfbError("missing root directory entry")
        return entries

    def _build_tree(self) -> None:
        visited: set[int] = set()

        def siblings(sid: int, parent: DirEntry, depth: int) -> None:
            stack = [sid]
            while stack:
                cur = stack.pop()
                if cur == NOSTREAM or cur >= len(self.entries) or cur in visited:
                    continue
                visited.add(cur)
                entry = self.entries[cur]
                entry.path = parent.path + (entry.name,)
                parent.children.append(cur)
                self._index[tuple(p.lower() for p in entry.path)] = entry
                stack.extend((entry.left, entry.right))
                if entry.is_storage and depth < 64:
                    siblings(entry.child, entry, depth + 1)

        root = self.entries[0]
        visited.add(0)
        siblings(root.child, root, 0)

    # -- public API -------------------------------------------------------------------
    def streams(self) -> list[DirEntry]:
        return [e for e in self._index.values() if e.is_stream]

    def storages(self) -> list[DirEntry]:
        return [e for e in self._index.values() if e.is_storage]

    def find(self, *path: str) -> DirEntry | None:
        return self._index.get(tuple(p.lower() for p in path))

    def read(self, entry: DirEntry) -> bytes:
        if not entry.is_stream:
            raise CfbError(f"{'/'.join(entry.path)} is not a stream")
        if entry.size > MAX_STREAM_SIZE:
            raise CfbError("stream too large")
        if entry.size < self.mini_cutoff:
            start = entry.start
            chain = self._chain(start, self.minifat, entry.size // self.mini_size + 2)
            data = b"".join(self._ministream[s * self.mini_size:(s + 1) * self.mini_size] for s in chain)
            return data[: entry.size]
        return self._read_chain(entry.start, self.fat, entry.size)

    def read_path(self, *path: str) -> bytes | None:
        entry = self.find(*path)
        return self.read(entry) if entry and entry.is_stream else None


def open_cfb(data: bytes) -> CompoundFile | None:
    """Parse `data`, or return None if it is not a (valid) compound file."""
    try:
        return CompoundFile(data)
    except (CfbError, struct.error, IndexError, ValueError):
        return None
