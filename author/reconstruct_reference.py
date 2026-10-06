#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from ravtools import PE, pdb_identity, reconstruct_from_exe, sha256


def main():
    p = argparse.ArgumentParser(description="Recover RAVTRACE.PDB from the player executable.")
    p.add_argument("exe", nargs="?", default=ROOT / "dist/author/RAVTRACE.EXE")
    p.add_argument("out", nargs="?", default=ROOT / "dist/author/RAVTRACE_RECONSTRUCTED.PDB")
    p.add_argument("--original", help="optional byte comparison after evidence-based candidate selection")
    args = p.parse_args()
    exe = Path(args.exe)
    out = Path(args.out)
    guid, age, path = PE(exe.read_bytes()).debug_codeview()
    print(f"CodeView path : {path}")
    print(f"EXE GUID      : {guid.hex()}")
    print(f"EXE age       : {age}")
    result = reconstruct_from_exe(exe, out, original=args.original)
    for o in sorted(result["objects"], key=lambda x: x["offset"]):
        print(f"{o['section']:7s} range=[{o['offset']},{o['offset'] + len(o['decoded'])}) flags=0x{o['flags']:02x} crc=ok total={o['total_size']}")
    for candidate in result["candidates"]:
        print("CANDIDATE     : " + ",".join(candidate["sections"]) + " -> " + candidate["status"])
    print(f"WROTE         : {out}")
    print(f"SHA256        : {sha256(out)}")
    pdb_guid, pdb_age = pdb_identity(out)
    print(f"PDB ID        : {pdb_guid.hex()} age={pdb_age}")
    if args.original:
        print(f"ORIGINAL      : {sha256(args.original)}")
        print(f"MATCH         : {'YES' if sha256(out) == sha256(args.original) else 'NO'}")


if __name__ == "__main__":
    main()
