# CTF 103 - A New Era: Shattered Symbols

Hard reverse-engineering challenge for the Raven's Horde investigation.

Build:

```sh
CTF_FLAG='Securinets_fst{...}' ./build.sh
```

The build requires a real PDB-capable Windows toolchain:

- `clang-cl`
- `lld-link`
- MSVC/Windows SDK libraries visible to `lld-link`
- `llvm-pdbutil` and `llvm-readobj` (paths may be set through `LLVM_PDBUTIL` and `LLVM_READOBJ`)
- Ghidra 11.4.2 and Java 21, with `GHIDRA_HOME` pointing to the extracted distribution

No fake PDB fallback is provided. If those tools are missing, the build stops
before producing player artifacts.

Run `make test` for host C++ checks (clang++ with ASan/UBSan), including every
fragment transform and malformed RLE, and synthetic PE/MSF reconstruction tests.
These do not replace a real Windows/PDB build. The full artifact verifier requires
Windows or Wine for the interactive `OPEN` path and Ghidra headless analysis for
before/after function and structure assertions. It fails when a required check
cannot run; the player executable has no command-line validation shortcut.

`.github/workflows/verify.yml` runs host checks and a native Windows PE32 build,
real PDB reconstruction, identity/hash checks, llvm-pdbutil, executable behavior,
and Ghidra import. CI uses an ephemeral test flag, never the production flag.
Only verification logs/reports are uploaded. A configured workflow is not proof
of a successful run: its checks must actually finish green for the commit.
See `author/REVIEW.md` for the baseline, changes, and outstanding artifact review.
