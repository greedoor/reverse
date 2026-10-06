#!/usr/bin/env python3
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ravtools import (HEADER, PE, SECTION_ORDER, TRANSFORMS, interval_candidates, make_object,
                      parse_object, pdb_identity_bytes, reconstruct_from_exe, split_six)
from msf_fixture import synthetic_pdb


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
        original = synthetic_pdb(guid)
        foreign = synthetic_pdb(b"D" * 16)
        chunks = split_six(original)
        objects, offset = {}, 0
        for i, chunk in enumerate(chunks):
            objects[("trace", i)] = make_object(offset, chunk, len(original), *TRANSFORMS[("trace", i)])
            offset += len(chunk)
        end = len(chunks[0]) + len(chunks[1])
        middle = end * 47 // 100
        for i, (start, stop) in enumerate(((0, middle), (middle, end))):
            objects[("decoy", i)] = make_object(start, foreign[start:stop], len(original), *TRANSFORMS[("decoy", i)])
        for key, blob in objects.items():
            obj = parse_object(blob)
            assert set(obj) == {"offset", "total_size", "decoded", "flags", "stored_size"}
            assert obj["decoded"] == (original if key[0] == "trace" else foreign)[obj["offset"]:obj["offset"] + len(obj["decoded"])]
            assert obj["total_size"] == len(original) and HEADER.size == 24
        covers = list(interval_candidates([parse_object(blob) for blob in objects.values()]))
        assert [len(cover) for cover in covers] == [6, 6]
        assert {pdb_identity_bytes(b"".join(obj["decoded"] for obj in cover))[0] for cover in covers} == {guid, b"D" * 16}
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
            result = reconstruct_from_exe(exe, rebuilt)
            assert len(result["objects"]) == 8 and len(result["selected"]) == 6
            assert len(result["candidates"]) == 2 and rebuilt.read_bytes() == original
            assert {candidate["status"] for candidate in result["candidates"]} == {"match", "identity mismatch"}
            # Author originals are checked only after selection, never used to choose a candidate.
            source.write_bytes(foreign)
            try:
                reconstruct_from_exe(exe, rebuilt, original=source)
            except SystemExit as error:
                assert "differs from original" in str(error)
            else:
                raise AssertionError("author original influenced candidate selection")


def test_pdb_parser_bounds():
    good = synthetic_pdb(bytes(range(16)))
    assert pdb_identity_bytes(good) == (bytes(range(16)), 1)
    malformed = [good[:-1]]
    for offset, value in ((32, 0), (3 * 4096, 80), (79 * 4096, 0xffffffff),
                          (79 * 4096 + 32, 4), (4 * 4096 + 8, 0),
                          (6 * 4096 + 24, 0xffffffff), (5 * 4096 + 12, 0x1001)):
        data = bytearray(good)
        struct.pack_into("<I", data, offset, value)
        malformed.append(data)
    for data in malformed:
        try:
            pdb_identity_bytes(data)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed MSF/PDB accepted")


if __name__ == "__main__":
    test_required_files_exist()
    test_player_text_has_no_spoilers()
    test_codeview_and_fragment_pipeline()
    test_pdb_parser_bounds()
    print("PASS: static checks and synthetic PE32/PE32+ fragment transport")
