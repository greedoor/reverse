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
    p.add_argument("--original", default=ROOT / "dist/author/RAVTRACE_ORIGINAL.PDB")
    args = p.parse_args()
    exe = Path(args.exe)
    out = Path(args.out)
    guid, age, path = PE(exe.read_bytes()).debug_codeview()
    print(f"CodeView path : {path}")
    print(f"EXE GUID      : {guid.hex()}")
    print(f"EXE age       : {age}")
    objs = reconstruct_from_exe(exe, out, guid, age, args.original if Path(args.original).exists() else None)
    for o in sorted(objs, key=lambda x: (x["tag"], x["seq"])):
        print(f"{o['section']:7s} seq={o['seq']} flags=0x{o['flags']:02x} crc=ok guid={o['guid'].hex()} age={o['age']}")
    print(f"WROTE         : {out}")
    print(f"SHA256        : {sha256(out)}")
    if Path(args.original).exists():
        print(f"ORIGINAL      : {sha256(args.original)}")
        print(f"MATCH         : {'YES' if sha256(out) == sha256(args.original) else 'NO'}")
        print(f"PDB ID        : {pdb_identity(out)[0].hex()} age={pdb_identity(out)[1]}")


if __name__ == "__main__":
    main()
