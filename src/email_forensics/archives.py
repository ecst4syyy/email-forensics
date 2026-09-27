"""Archive listing without extraction to disk.

Archives are the main way payloads are hidden from scanners (password protection,
nesting, zip bombs). Everything here is bounded: member count, bytes decompressed,
and nesting depth. Nothing is ever written to disk.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import tarfile
import zipfile
import zlib

from .filetype import BZIP2, GZIP, JAR, APK, TAR, XZ, ZIP, FileType, detect
from .models import ArchiveInfo, ArchiveMember

MAX_MEMBERS = 10_000
MAX_NESTING = 3
MAX_MEMBER_READ = 20 * 1024 * 1024  # bytes decompressed per member for type detection
MAX_TOTAL_READ = 100 * 1024 * 1024  # bytes decompressed per top-level archive
BOMB_TOTAL_SIZE = 1024 ** 3  # declared uncompressed size that is a bomb on its own
BOMB_RATIO = 100

ZIP_TYPES = {ZIP.id, JAR.id, APK.id}
STREAM_TYPES = {GZIP.id, BZIP2.id, XZ.id}
INSPECTABLE = ZIP_TYPES | STREAM_TYPES | {TAR.id}


class _Budget:
    def __init__(self) -> None:
        self.remaining = MAX_TOTAL_READ
        self.exhausted = False

    def allow(self, size: int) -> bool:
        if size > min(self.remaining, MAX_MEMBER_READ):
            self.exhausted = True
            return False
        return True

    def spend(self, n: int) -> None:
        self.remaining -= n


def inspect_archive(data: bytes, ftype: FileType) -> ArchiveInfo:
    info = ArchiveInfo(format=ftype.id)
    if ftype.id not in INSPECTABLE:
        info.error = f"{ftype.description} listing is not supported without optional tools"
        return info
    budget = _Budget()
    _inspect(data, ftype, None, 0, info, budget)
    info.truncated = info.truncated or budget.exhausted
    return info


def is_bomb(info: ArchiveInfo, compressed_size: int) -> bool:
    if info.overlapping_entries or info.total_uncompressed > BOMB_TOTAL_SIZE:
        return True
    ratio = info.total_uncompressed / max(compressed_size, 1)
    return ratio > BOMB_RATIO and info.total_uncompressed > 50 * 1024 * 1024


def _inspect(data: bytes, ftype: FileType, container: str | None, depth: int,
             info: ArchiveInfo, budget: _Budget) -> None:
    info.max_nesting = max(info.max_nesting, depth)
    try:
        if ftype.id in ZIP_TYPES:
            _zip(data, container, depth, info, budget)
        elif ftype.id == TAR.id or ftype.id in STREAM_TYPES:
            if not _tar(data, container, depth, info, budget) and ftype.id in STREAM_TYPES:
                _stream(data, ftype, container, depth, info, budget)
    except Exception as exc:  # corrupt archives are common and attacker-controlled
        if depth == 0:
            info.error = f"{type(exc).__name__}: {exc}"[:300]


def _add(member: ArchiveMember, payload: bytes | None, depth: int, info: ArchiveInfo, budget: _Budget) -> None:
    if len(info.members) >= MAX_MEMBERS:
        info.truncated = True
        return
    info.members.append(member)
    info.total_uncompressed += member.size
    if member.encrypted:
        info.encrypted_members += 1
    if payload is None:
        return
    member.sha256 = hashlib.sha256(payload).hexdigest()
    ftype = detect(payload)
    member.detected_type = ftype.id if ftype else None
    if ftype and ftype.id in INSPECTABLE:
        if depth + 1 > MAX_NESTING:
            info.truncated = True
            return
        path = f"{member.container}/{member.name}" if member.container else member.name
        _inspect(payload, ftype, path, depth + 1, info, budget)


def _zip(data: bytes, container: str | None, depth: int, info: ArchiveInfo, budget: _Budget) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        entries = zf.infolist()
        # Overlapping entries (several names sharing one compressed stream) are the
        # signature of non-recursive zip bombs.
        offsets = [e.header_offset for e in entries]
        if len(offsets) != len(set(offsets)):
            info.overlapping_entries = True
        for entry in entries:
            if len(info.members) >= MAX_MEMBERS:
                info.truncated = True
                return
            member = ArchiveMember(
                name=entry.filename, size=entry.file_size, compressed_size=entry.compress_size,
                encrypted=bool(entry.flag_bits & 0x1), is_dir=entry.is_dir(), container=container,
            )
            payload = None
            readable = not (member.is_dir or member.encrypted or info.overlapping_entries)
            if readable and budget.allow(entry.file_size):
                try:
                    with zf.open(entry) as fh:
                        payload = fh.read(MAX_MEMBER_READ + 1)
                    budget.spend(len(payload))
                except Exception:
                    payload = None
            _add(member, payload, depth, info, budget)


def _tar(data: bytes, container: str | None, depth: int, info: ArchiveInfo, budget: _Budget) -> bool:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError):
        return False
    with tf:
        count = 0
        while True:
            # tf.next() decompresses through the previous member to reach the next
            # header, so the size guard must run *before* it.
            if len(info.members) >= MAX_MEMBERS or info.total_uncompressed > BOMB_TOTAL_SIZE:
                info.truncated = True
                break
            try:
                entry = tf.next()
            except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError):
                info.truncated = True
                break
            if entry is None:
                break
            count += 1
            member = ArchiveMember(name=entry.name, size=entry.size, is_dir=entry.isdir(), container=container)
            payload = None
            if entry.isfile() and budget.allow(entry.size):
                try:
                    fh = tf.extractfile(entry)
                    payload = fh.read(MAX_MEMBER_READ + 1) if fh else None
                    budget.spend(len(payload or b""))
                except Exception:
                    payload = None
            _add(member, payload, depth, info, budget)
    return count > 0


def _stream(data: bytes, ftype: FileType, container: str | None, depth: int,
            info: ArchiveInfo, budget: _Budget) -> None:
    """Single-file gzip/bzip2/xz: decompress a bounded prefix."""
    limit = min(MAX_MEMBER_READ, budget.remaining)
    if ftype.id == GZIP.id:
        payload = zlib.decompressobj(wbits=47).decompress(data, limit)
    elif ftype.id == BZIP2.id:
        payload = bz2.BZ2Decompressor().decompress(data, max_length=limit)
    else:
        payload = lzma.LZMADecompressor().decompress(data, max_length=limit)
    budget.spend(len(payload))
    truncated = len(payload) >= limit
    info.truncated = info.truncated or truncated
    name = "(compressed stream)"
    if ftype.id == GZIP.id and len(data) > 10 and data[3] & 0x08:  # FNAME flag
        end = data.find(b"\x00", 10)
        if end > 10:
            name = data[10:end].decode("latin-1")
    _add(ArchiveMember(name=name, size=len(payload), compressed_size=len(data), container=container),
         payload, depth, info, budget)
