#!/usr/bin/env python3
"""Exercise production C++ on the host; this does not substitute for PE/PDB tests."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ravtools import write_generated_constants


def run(cmd, **kwargs):
    # LeakSanitizer cannot run under the sandbox's ptrace; bounds checks remain enabled.
    env = dict(kwargs.pop("env", os.environ), ASAN_OPTIONS="detect_leaks=0")
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, env=env, **kwargs)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout or "host test failed")
    return result


def main():
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ required for host validation tests")
    with tempfile.TemporaryDirectory(prefix="ravtrace-test-") as temp:
        root = Path(temp)
        shutil.copytree(ROOT / "src", root / "src", ignore=shutil.ignore_patterns("generated_constants.hpp"))
        flags = [compiler, "-std=c++11", "-fdeclspec", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I" + str(root / "src")]
        sources = [str(root / "src/trace.cpp"), str(root / "src/validation.cpp")]
        for size in (1, 15, 16, 17, 31, 32, 63, 64):
            inner = "abcdefghijklmnopqrstuvwxyz_0123456789" * 2
            record = "Securinets_fst{" + inner[:size] + "}"
            write_generated_constants(root, record)
            harness = root / "harness"
            run(flags + sources + [str(ROOT / "tests/validation_harness.cpp"), "-o", str(harness)])
            run([str(harness)], env=dict(os.environ, TEST_RECORD=record))
            if size != 17:
                continue
            exe = root / "terminal"
            run(flags + ["-include", "strings.h", "-D_stricmp=strcasecmp", "-D_strnicmp=strncasecmp"] +
                sources + [str(root / "src/main.cpp"), "-o", str(exe)])
            binary = exe.read_bytes()
            for forbidden in (record.encode(), b"Securinets_fst{", b"--check", b"CHECK <CODE>"):
                assert forbidden not in binary
            good = run([str(exe)], input=f"OPEN {record}\nQUIT\n").stdout
            assert good.count("TRACE RECORD VERIFIED") == 1
            removed = run([str(exe), "--check", record], input=f"HELP\nCHECK {record}\nQUIT\n").stdout
            assert "OPEN <RECORD>" in removed and "CHECK <CODE>" not in removed
            assert "TRACE RECORD VERIFIED" not in removed
            malformed = run([str(exe)], input="TRACE -0\nTRACE 100000000\n" + "X" * 300 +
                            f"\nOPEN {record}\nQUIT\n").stdout
            assert malformed.count("ERR: NO RECORD") == 3
            assert malformed.count("TRACE RECORD VERIFIED") == 1
    print("PASS: host validation, context dependencies, bounds and terminal routing (ASan/UBSan)")


if __name__ == "__main__":
    main()
