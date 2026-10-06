# Maintainer Review

Baseline: `a25f983ad26fc8838e510933fc31851ad4a82962`, matching GitHub `main`.
The original two checks in `tests/test_static.py` passed before modification.
The checkout contains source/build tooling, but no generated EXE/PDB/ZIP.
This environment has host clang++, but lacks clang-cl, lld-link, Windows SDK
libraries, Wine, and Ghidra. llvm-pdbutil is installed at
`/usr/lib/llvm-18/bin/llvm-pdbutil`, outside PATH. Artifact claims require a Windows build.

## Changes

- Replace CHECK with OPEN and remove the command-line flag checker.
- Populate typed validation context through lot decoding, profile loading,
  profile binding, and target loading. Validation no longer constructs its own
  seed, permutation, or target.
- Resolve three meaningful operations through TRACE_DISPATCH: inventory,
  sealed records, and cache records. Sealed and cache operations share the
  transformer/comparator but use different context settings and targets.
- Map handler status through dispatch and record state before rendering. The
  success-string XREF now reaches a common renderer, shared by sealed and
  inventory openings.
- Correct CodeView parsing: PointerToRawData is at debug-entry offset 24;
  AddressOfRawData at offset 20 is an RVA. Test both layouts and RVA fallback.
- Reject short records before comparing the wrapper; reject malformed lot IDs
  and overlong terminal lines. Check required compilers before deleting any
  existing build output.
- Make artifact verification fail when executable behavior cannot be tested,
  rather than writing a success report after skipping the runner.
- Require llvm-pdbutil to parse streams, DBI modules, symbols, and types before
  accepting the artifact; checking for name bytes alone cannot validate a PDB.

The six-real/two-decoy fragment layout, transforms, CRC, shuffled physical order,
reconstruction, identity checks, reversible sealed-record algorithm, fictional
paths, terminal theme, and three-file player archive remain in place.

## Verification

Run `make test`: existing text checks, synthetic PE32/PE32+ CodeView and fragment
transport checks, and the production C++ compiled on the host with ASan/UBSan.
Host cases cover eight record lengths, same-length wrong records, incomplete
contexts, altered key/target/permutation/rotation fields, profile changes,
removed interfaces, malformed input, and restoration of the default lot.
LeakSanitizer is disabled because it cannot run under the sandbox's ptrace;
AddressSanitizer and UndefinedBehaviorSanitizer remain enabled.

The synthetic transport fixture is not a real PDB and is never packaged.
Host tests do not prove Windows execution, PDB validity, or Ghidra imports.
Build with `CTF_FLAG` using `./build.sh` on the documented Windows toolchain,
then run the full author verifier and follow SOLUTION.md for Ghidra import.
If llvm-pdbutil is outside PATH, set `LLVM_PDBUTIL` to its executable path.

## Remaining Review

Without symbols, reversal remains possible by following context writes and
resolving function pointers. The PDB is intended to reduce that work by naming
profiles, modes, handlers, fields, and result codes. It is not a cryptographic
requirement or a runtime unlock file. Confirm the difficulty with a blind solve
of the rebuilt player ZIP and compare Ghidra views before/after PDB loading.
Neither that blind solve nor the Ghidra comparison is claimed as completed here.
