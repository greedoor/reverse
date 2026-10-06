# Maintainer Review

First-pass baseline: `a25f983ad26fc8838e510933fc31851ad4a82962` (historical).
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

## Final Hardening

Baseline: `d7951dafc2a464219a3c2873a0275a9a9beabe73`, confirmed on local and
GitHub main. `make test` passed before edits.

Fragment headers now contain only marker, transform flags, encoded byte offset,
stored/decoded sizes, decoded CRC32, and encoded total size. Each of the eight
objects advertises the same total. Two contiguous genuine RAVTEST prefix slices
compete with the first two RAVTRACE intervals, using a different shared boundary.
There are two gap-free complete covers, each containing six objects. The
reference reconstructor does not know the genuine count or section map; it
tests both complete candidates and checks identity only after MSF/PDB parsing.
The optional original is consulted solely for a post-selection byte comparison.
The second program uses neutral service/source/symbol names rather than test
labels in its records; RAVTEST remains the author-only artifact filename.

RLE replaces the builder-only compression path. The same literal/run format is
implemented in Python and ExpandTraceBlock, including reverse storage, bounded
expansion, truncated input checks, and exact decoded size. The native harness
enumerates every configured transform and checks production C++ against the
Python encoder under ASan/UBSan. Parser fixtures also check wrong identity after
assembly, block bounds/overlap, invalid DBI/TPI headers, and CRC corruption.
These fixtures are synthetic unit-test data, not claimed compiler artifacts.

The native Windows workflow now targets PE32/x86, preserves all debug routines,
builds genuine private PDBs, reconstructs, checks hashes/identity, uses the LLVM
readers, runs the terminal acceptance/rejection cases, and asserts Ghidra
functions/prototypes/structure fields before and after loading the recovered
PDB. The full verifier requires every stage and writes no success report when
a required tool or runtime is absent. Ghidra itself reconstructs from the player
ZIP without the author original. CI archives verification evidence, not PDBs.

Local Windows/PDB/Ghidra proof is still unavailable: clang-cl, lld-link, the
Windows SDK/runtime libraries, Wine, and Ghidra are absent. LLVM readers are
installed outside PATH. GitHub publishing/execution must succeed before the
new workflow constitutes CI proof. No successful CI run or rebuilt Windows
artifact is claimed merely from adding the workflow. A blind participant solve
and solve-time calibration remain release review requirements.
