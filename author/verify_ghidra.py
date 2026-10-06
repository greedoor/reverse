#!/usr/bin/env python3
"""Prove private symbols and field types appear only after loading the recovered PDB."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ravtools import reconstruct_from_exe, sha256


def verify_ghidra(zip_path, report_dir):
    home = os.environ.get("GHIDRA_HOME")
    if not home:
        raise SystemExit("FAIL: GHIDRA_HOME required for full verification")
    headless = Path(home) / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not headless.is_file():
        raise SystemExit("FAIL: Ghidra headless launcher missing")
    report_dir = Path(report_dir).resolve()
    for name in ("ghidra-before.txt", "ghidra-after.txt", "ghidra-verification.txt"):
        (report_dir / name).unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="ravtrace-ghidra-") as temp:
        work = Path(temp)
        exe, pdb = work / "RAVTRACE.EXE", work / "RAVTRACE.PDB"
        with ZipFile(zip_path) as archive:
            exe.write_bytes(archive.read("RAVTRACE.EXE"))
        reconstruct_from_exe(exe, pdb)
        for mode in ("before", "after"):
            report = report_dir / f"ghidra-{mode}.txt"
            cmd = [str(headless), str(work), mode, "-import", str(exe),
                   "-scriptPath", str(ROOT / "author/ghidra"),
                   "-preScript", "ConfigurePdb.java", "-" if mode == "before" else str(pdb),
                   "-postScript", "AssertSymbols.java", mode, str(report), "-deleteProject"]
            if os.name == "nt":
                cmd = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c"] + cmd
            run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
            (report_dir / f"ghidra-{mode}.log").write_text(run.stdout, encoding="utf-8")
            if run.returncode or not report.is_file() or f"GHIDRA_{mode.upper()}_PASS" not in report.read_text():
                raise SystemExit(f"FAIL: Ghidra {mode} verification; see ghidra-{mode}.log")
        (report_dir / "ghidra-verification.txt").write_text(
            "ghidra_symbol_import: PASS\n"
            f"player_exe_sha256: {sha256(exe)}\n"
            f"reconstructed_pdb_sha256: {sha256(pdb)}\n", encoding="ascii")
    print("PASS: Ghidra before/after private symbols, validator prototype and structure fields")


if __name__ == "__main__":
    verify_ghidra(ROOT / "dist/player/RAVTRACE.ZIP", ROOT / "dist/author")
