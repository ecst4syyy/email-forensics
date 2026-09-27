import gzip
import io
import tarfile
import zipfile

from email_forensics import filetype as ft
from email_forensics.archives import MAX_NESTING, inspect_archive, is_bomb
from samples import fake_pe, make_zip


def names(info):
    return [f"{m.container}/{m.name}" if m.container else m.name for m in info.members]


def test_zip_listing_with_nested_archive():
    inner = make_zip({"evil.exe": fake_pe()})
    info = inspect_archive(make_zip({"inner.zip": inner, "a.txt": b"hi"}), ft.ZIP)
    assert names(info) == ["inner.zip", "inner.zip/evil.exe", "a.txt"]
    exe = info.members[1]
    assert exe.detected_type == "pe" and len(exe.sha256) == 64
    assert info.max_nesting == 1


def test_nesting_limit():
    data = make_zip({"x.txt": b"x"})
    for i in range(MAX_NESTING + 3):
        data = make_zip({f"l{i}.zip": data})
    info = inspect_archive(data, ft.ZIP)
    assert info.truncated and info.max_nesting == MAX_NESTING


def test_encrypted_members_are_counted_not_read():
    info = inspect_archive(make_zip({"a.js": b"x", "b.txt": b"y"}, encrypted={"a.js"}), ft.ZIP)
    assert info.encrypted_members == 1
    assert info.members[0].encrypted and info.members[0].sha256 is None


def test_high_ratio_zip_is_bomb_and_not_fully_read():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * (60 * 1024 * 1024))
    data = buf.getvalue()
    info = inspect_archive(data, ft.ZIP)
    assert is_bomb(info, len(data))
    assert info.members[0].sha256 is None  # over the per-member read limit


def test_overlapping_entries_are_bomb():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a", b"x" * 100)
    raw = bytearray(buf.getvalue())
    # Duplicate the central directory entry so two names point at one local header.
    cd = raw.find(b"PK\x01\x02")
    eocd = raw.find(b"PK\x05\x06")
    entry = raw[cd:eocd]
    entry2 = bytearray(entry)
    entry2[46:47] = b"b"
    raw = raw[:eocd] + entry2 + raw[eocd:]
    eocd = raw.find(b"PK\x05\x06")
    raw[eocd + 8:eocd + 10] = (2).to_bytes(2, "little")
    raw[eocd + 10:eocd + 12] = (2).to_bytes(2, "little")
    raw[eocd + 12:eocd + 16] = (len(entry) * 2).to_bytes(4, "little")
    info = inspect_archive(bytes(raw), ft.ZIP)
    assert info.overlapping_entries and is_bomb(info, len(raw))
    assert [m.name for m in info.members] == ["a", "b"]


def test_tar_gz_and_plain_gzip():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = fake_pe()
        ti = tarfile.TarInfo("dir/run.exe")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    info = inspect_archive(buf.getvalue(), ft.GZIP)
    assert names(info) == ["dir/run.exe"] and info.members[0].detected_type == "pe"

    info = inspect_archive(gzip.compress(fake_pe()), ft.GZIP)
    assert info.members[0].detected_type == "pe"


def test_unsupported_and_corrupt():
    assert "not supported" in inspect_archive(b"Rar!\x1a\x07\x00", ft.RAR).error
    assert inspect_archive(b"PK\x03\x04garbage", ft.ZIP).error


def test_tar_gz_with_huge_declared_member_stops_before_decompressing_it():
    hdr = tarfile.TarInfo("huge.bin")
    hdr.size = 2 * 1024 ** 3
    data = gzip.compress(hdr.tobuf() + b"\0" * 4096)
    info = inspect_archive(data, ft.GZIP)
    assert [m.name for m in info.members] == ["huge.bin"]
    assert info.truncated and is_bomb(info, len(data))
