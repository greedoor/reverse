#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from ravtools import (DECOY_TAG, TRACE_TAG, PE, pdb_identity, reconstruct_from_exe,
                      sha256)

BAD_WORDS = [
    b"Securinets_fst{",
    b"Microsoft C/C++ MSF 7.00",
    b"traitor",
    b"exchange location",
    b"GetFlag",
    b"DecryptRealFlag",
]
SYMBOLS = [
    b"ValidateCandidate",
    b"TransformCandidate",
    b"DeriveTraceKey",
    b"RestoreDebugBlock",
    b"TRACE_CONTEXT",
    b"VALIDATION_STATE",
]


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def ok(msg):
    print(f"PASS: {msg}")


def read(p):
    return Path(p).read_bytes()


def run_exe(exe, flag):
    if os.name == "nt":
        runner = [str(exe)]
    elif shutil.which("wine"):
        runner = ["wine", str(exe)]
    else:
        print("SKIP: executable launch (no Windows runner or wine)")
        return
    bad = subprocess.run(runner + ["--check", "Securinets_fst{wrong_record}"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if bad.returncode == 0 or "ERR: DEBUG SET MISMATCH" not in bad.stdout:
        fail("wrong flag was not rejected")
    good = subprocess.run(runner + ["--check", flag],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if good.returncode != 0 or "TRACE RECORD VERIFIED" not in good.stdout:
        fail("correct flag was not accepted")
    ok("runtime flag behavior")


def zip_bytes(zip_path):
    out = {}
    with ZipFile(zip_path) as z:
        for name in z.namelist():
            out[name] = z.read(name)
    return out


def main():
    flag = os.environ.get("CTF_FLAG")
    if not flag:
        fail("CTF_FLAG required for full verification")
    dist = ROOT / "dist"
    exe = dist / "author/RAVTRACE.EXE"
    original = dist / "author/RAVTRACE_ORIGINAL.PDB"
    reconstructed = dist / "author/RAVTRACE_RECONSTRUCTED.PDB"
    ravtest = dist / "author/RAVTEST_ORIGINAL.PDB"
    zip_path = dist / "player/RAVTRACE.ZIP"
    for p in (exe, original, reconstructed, ravtest, zip_path):
        if not p.exists():
            fail(f"missing artifact: {p}")

    pe = PE(read(exe))
    guid, age, path = pe.debug_codeview()
    if not path.endswith("RAVTRACE.PDB") or "C:\\RAVEN\\DEV\\TRACE" not in path:
        fail(f"unexpected CodeView path: {path}")
    ok("PE and CodeView debug directory")

    objs = reconstruct_from_exe(exe, reconstructed, guid, age, original)
    real = [o for o in objs if o["tag"] == TRACE_TAG and o["guid"] == guid and o["age"] == age]
    decoy = [o for o in objs if o["tag"] == DECOY_TAG]
    if len(objs) != 8 or len(real) != 6 or len(decoy) != 2:
        fail("fragment real/decoy count mismatch")
    if sorted(o["seq"] for o in real) != list(range(6)):
        fail("real fragment order metadata invalid")
    ok("8 fragments decode and CRC-check")

    if sha256(original) != sha256(reconstructed):
        fail("PDB reconstruction hash mismatch")
    ok("reconstructed PDB byte-for-byte matches original")

    pdb_guid, pdb_age = pdb_identity(reconstructed)
    test_guid, test_age = pdb_identity(ravtest)
    if (pdb_guid, pdb_age) != (guid, age):
        fail("EXE/PDB identity mismatch")
    if (test_guid, test_age) == (guid, age):
        fail("RAVTEST decoy identity unexpectedly matches")
    ok("EXE/PDB identity")

    pdb_data = read(reconstructed)
    missing = [s.decode() for s in SYMBOLS if s not in pdb_data]
    if missing:
        fail("missing expected private symbols/types: " + ", ".join(missing))
    ok("expected private symbols present")

    if flag.encode() in read(exe) or flag.encode() in pdb_data:
        fail("plaintext flag leaked")
    if b"Microsoft C/C++ MSF 7.00" in read(exe):
        fail("full MSF header visible in EXE")
    ok("binary leak checks")

    members = zip_bytes(zip_path)
    expected = {"RAVTRACE.EXE", "README.NFO", "FILE_ID.DIZ"}
    if set(members) != expected:
        fail(f"bad ZIP members: {sorted(members)}")
    joined = b"\n".join(members.values())
    for name in members:
        if name.upper().endswith((".PDB", ".CPP", ".HPP", ".PY")):
            fail(f"author file in player ZIP: {name}")
    for word in BAD_WORDS + [flag.encode(), b"author/", b"/home/", b"\\Users\\"]:
        if word in joined:
            fail(f"player ZIP leak: {word!r}")
    ok("player package contents")

    run_exe(exe, flag)

    report = dist / "author/verification-report.txt"
    report.write_text(
        "CTF 103 - SHATTERED SYMBOLS\n"
        "difficulty: HARD\n"
        f"exe: {exe}\n"
        f"pdb_original_sha256: {sha256(original)}\n"
        f"pdb_reconstructed_sha256: {sha256(reconstructed)}\n"
        "byte_match: YES\n"
        "exe_pdb_identity: YES\n"
        "real_fragments: 6\n"
        "decoys: 2\n"
        "ghidra_symbol_import: MANUAL VERIFICATION REQUIRED\n"
        "flag_leak_scan: PASS\n"
        "story_spoiler_scan: PASS\n"
        "player_package: PASS\n"
    )
    (dist / "author/hashes.txt").write_text(
        f"{sha256(exe)}  RAVTRACE.EXE\n"
        f"{sha256(original)}  RAVTRACE_ORIGINAL.PDB\n"
        f"{sha256(reconstructed)}  RAVTRACE_RECONSTRUCTED.PDB\n"
        f"{sha256(ravtest)}  RAVTEST_ORIGINAL.PDB\n"
    )
    ok(f"wrote {report}")


if __name__ == "__main__":
    main()
