#!/usr/bin/env python3
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ravtools import (PE, SECTION_ORDER, make_object, parse_object,
                      reconstruct_from_exe, split_six)


def test_required_files_exist():
    root = Path(__file__).resolve().parents[1]
    for rel in [
        "build.sh",
        "tools/ravtools.py",
        "author/reconstruct_reference.py",
        "author/verify_challenge.py",
        "player/README.NFO",
        "player/FILE_ID.DIZ",
        "src/main.cpp",
        "src/trace.cpp",
        "src/validation.cpp",
    ]:
        assert (root / rel).exists(), rel


def test_player_text_has_no_spoilers():
    root = Path(__file__).resolve().parents[1]
    text = ((root / "player/README.NFO").read_text() + "\n" +
            (root / "player/FILE_ID.DIZ").read_text()).lower()
    for bad in ["traitor", "location", "securinets_fst{", "pdb"]:
        assert bad not in text


def test_codeview_and_fragment_pipeline():
    # Synthetic PE transport fixture only: no compiler EXE or PDB is claimed here.
    for is64 in (False, True):
        data = bytearray(0x800)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        opt_size = 0xf0 if is64 else 0xe0
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if is64 else 0x14c, 1, 0, 0, 0, opt_size, 2)
        opt = 0x98
        struct.pack_into("<H", data, opt, 0x20b if is64 else 0x10b)
        struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
        struct.pack_into("<II", data, opt + 56, 0x2000, 0x400)
        struct.pack_into("<II", data, opt + (112 if is64 else 96) + 48, 0x1000, 28)
        sec = opt + opt_size
        data[sec:sec + 8] = b".rdata\0\0"
        struct.pack_into("<IIII", data, sec + 8, 0x400, 0x1000, 0x400, 0x400)
        guid, age, path = bytes(range(16)), 1, "C:\\RAVEN\\DEV\\TRACE\\RAVTRACE.PDB"
        rsds = b"RSDS" + guid + struct.pack("<I", age) + path.encode() + b"\0"
        struct.pack_into("<IIII", data, 0x40c, 2, len(rsds), 0x1040, 0x440)
        data[0x440:0x440 + len(rsds)] = rsds
        pe = PE(data)
        assert pe.debug_codeview() == (guid, age, path)
        struct.pack_into("<I", pe.data, 0x418, 0)
        assert pe.debug_codeview() == (guid, age, path)
        original = bytes(range(256)) * 79
        chunks = split_six(original)
        objects = {("trace", i): make_object("trace", i, chunk, guid, age, len(original))
                   for i, chunk in enumerate(chunks)}
        for i in range(2):
            objects[("decoy", i)] = make_object("decoy", i, b"transport decoy" * 97,
                                               b"D" * 16, 2, 65536)
        for key, blob in objects.items():
            obj = parse_object(blob)
            assert obj["seq"] == key[1]
            assert obj["decoded"] == (chunks[key[1]] if key[0] == "trace" else b"transport decoy" * 97)
        corrupted = bytearray(objects[("trace", 5)])
        corrupted[-1] ^= 1
        try:
            parse_object(corrupted)
        except SystemExit as error:
            assert "CRC mismatch" in str(error)
        else:
            raise AssertionError("corrupted fragment accepted")
        pe.add_sections([(name, objects[key]) for name, key in SECTION_ORDER])
        assert PE(pe.data).debug_codeview() == (guid, age, path)
        with tempfile.TemporaryDirectory() as temp:
            exe, rebuilt, source = (Path(temp) / name for name in ("transport.exe", "rebuilt.bin", "original.bin"))
            exe.write_bytes(pe.data)
            source.write_bytes(original)
            fragments = reconstruct_from_exe(exe, rebuilt, original=source)
            assert len(fragments) == 8 and rebuilt.read_bytes() == original


if __name__ == "__main__":
    test_required_files_exist()
    test_player_text_has_no_spoilers()
    test_codeview_and_fragment_pipeline()
    print("PASS: static checks and synthetic PE32/PE32+ fragment transport")
