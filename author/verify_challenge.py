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
    b"--check",
    b"CHECK <CODE>",
]
SYMBOLS = [
    b"ValidateCandidate",
    b"TransformCandidate",
    b"DeriveTraceKey",
    b"RestoreDebugBlock",
    b"TRACE_CONTEXT",
    b"VALIDATION_STATE",
    b"TRACE_PROFILE",
    b"TRACE_DISPATCH",
    b"DispatchTraceCommand",
    b"LoadTraceProfile",
    b"BindTraceProfile",
    b"LoadRecordTarget",
    b"ResolveTraceOperation",
    b"ApplyTraceHandler",
    b"RecordTraceResult",
    b"RenderTraceStatus",
]


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def ok(msg):
    print(f"PASS: {msg}")


def read(p):
    return Path(p).read_bytes()


def validate_private_pdb(pdb):
    tool = os.environ.get("LLVM_PDBUTIL") or shutil.which("llvm-pdbutil")
    if not tool:
        fail("llvm-pdbutil required (or set LLVM_PDBUTIL to its path)")
    parsed = subprocess.run([tool, "dump", "--summary", "--streams", "--modules",
                             "--symbols", "--types", str(pdb)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if parsed.returncode:
        fail("llvm-pdbutil rejected reconstructed PDB: " + parsed.stderr.decode(errors="replace"))
    missing = [symbol.decode() for symbol in SYMBOLS if symbol not in parsed.stdout]
    if missing:
        fail("missing parsed private symbols/types: " + ", ".join(missing))
    ok("llvm-pdbutil parses streams, DBI modules, private symbols and types")


def run_exe(exe, flag):
    if os.name == "nt":
        runner = [str(exe)]
    elif shutil.which("wine"):
        runner = ["wine", str(exe)]
    else:
        fail("runtime verification requires Windows or wine")
    bad_record = flag[:-2] + ("y" if flag[-2] == "x" else "x") + "}"
    bad = subprocess.run(runner, input=f"OPEN {bad_record}\nQUIT\n",
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if bad.returncode != 0 or "ERR: DEBUG SET MISMATCH" not in bad.stdout or "TRACE RECORD VERIFIED" in bad.stdout:
        fail("wrong flag was not rejected")
    good = subprocess.run(runner, input=f"OPEN {flag}\nQUIT\n",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if good.returncode != 0 or "TRACE RECORD VERIFIED" not in good.stdout:
        fail("correct flag was not accepted")
    ok("runtime flag behavior")

    removed = subprocess.run(runner + ["--check", flag], input="HELP\nCHECK ignored\nQUIT\n",
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if removed.returncode != 0 or "TRACE RECORD VERIFIED" in removed.stdout or "CHECK <CODE>" in removed.stdout:
        fail("removed check interface remains accessible")
    ok("player exposes no CHECK command or command-line validator")


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
    validate_private_pdb(reconstructed)
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
        "pdb_tool_validation: PASS\n"
        "real_fragments: 6\n"
        "decoys: 2\n"
        "ghidra_symbol_import: MANUAL VERIFICATION REQUIRED\n"
        "flag_leak_scan: PASS\n"
        "story_spoiler_scan: PASS\n"
        "player_package: PASS\n"
        "runtime_verification: PASS\n"
        "player_check_shortcut: ABSENT\n"
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
