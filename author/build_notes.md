# Build Notes

This challenge intentionally requires a genuine Microsoft-compatible PDB.

Known-good route:

```cmd
set CTF_FLAG=Securinets_fst{...}
build.sh
```

Required tools:

- clang-cl
- lld-link
- MSVC runtime libraries or Build Tools
- Windows SDK import libraries
- llvm-pdbutil (or its path in LLVM_PDBUTIL) for full artifact verification
- Windows or wine for interactive runtime verification

Optional validation:

- llvm-readobj
- Ghidra headless analyzer

If `clang-cl` or `lld-link` is missing, the build fails. That is deliberate:
the PDB is part of the challenge object, not documentation.
