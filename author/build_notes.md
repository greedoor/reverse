# Build Notes

This challenge intentionally requires a genuine Microsoft-compatible PDB.

Known-good route:

```cmd
set CTF_FLAG=Securinets_fst{...}
set GHIDRA_HOME=C:\TOOLS\ghidra_11.4.2_PUBLIC
python tools\build.py build --root .
```

Required tools:

- clang-cl
- lld-link
- MSVC runtime libraries or Build Tools
- Windows SDK import libraries
- An x86 MSVC developer environment (`VsDevCmd.bat -arch=x86 -host_arch=x64`)
- llvm-pdbutil (or its path in LLVM_PDBUTIL) for full artifact verification
- llvm-readobj (or its path in LLVM_READOBJ) for independent PE inspection
- Windows or wine for interactive runtime verification
- Ghidra 11.4.2 with Java 21 and GHIDRA_HOME for before/after symbol/type assertions

If `clang-cl` or `lld-link` is missing, the build fails. That is deliberate:
the PDB is part of the challenge object, not documentation.

The build targets i686 explicitly, retains private debug functions, reserves
header space via 4096-byte FileAlignment, and links using relative object paths.
Source/compilation paths are mapped to the fictional development directory.

CI uses the Windows 2022 runner's MSVC/SDK and LLVM, pinned action commits, and a
checksum-verified Ghidra archive. The Ghidra release is pinned to
[11.4.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.2_build),
SHA256 `795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6`.
Its test flag is generated per run and masked; no production secret is required
on pull requests. Reports are uploaded separately from all PDBs and player files.

`author/verify_ghidra.py` uses separate imports, disables PDB analysis in the
before case, and supplies the reconstructed PDB explicitly in the after case.
The reader performs its ordinary identity checks. Java scripts assert private
functions, the validator's context prototype, structure fields, and the 24-byte
TRACE_BLOCK layout; a missing report or failed script fails verification even
if the headless launcher exits zero.

MSF/core stream validation follows the documented
[MSF layout](https://llvm.org/docs/PDB/MsfFile.html),
[DBI layout](https://llvm.org/docs/PDB/DbiStream.html), and
[TPI/IPI layout](https://llvm.org/docs/PDB/TpiStream.html).
This structural filter is followed by the real llvm-pdbutil reader in full
verification; it does not replace semantic symbol parsing.
