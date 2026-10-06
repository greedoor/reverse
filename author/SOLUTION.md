# CTF 103 - Shattered Symbols: Author Solution

The repository contained no kill-chain or handoff file, so the build uses the
author-only `CTF_FLAG` environment variable. The executable prints only a local
verification line on success.

## 1. Basic Inspection

```sh
file RAVTRACE.EXE
strings -a RAVTRACE.EXE | less
```

The program is a Windows console PE. Strings show period service-copy language,
but no plaintext flag and no full PDB header.

## 2. PE Identification

Use `llvm-readobj`, PE-bear, Detect It Easy, or a short Python parser.

```sh
llvm-readobj --file-headers --sections --coff-debug-directory RAVTRACE.EXE
```

## 3. Debug Directory

The PE Debug Directory contains a CodeView `RSDS` record.

## 4. CodeView/PDB Path

The path is:

```text
C:\RAVEN\DEV\TRACE\RAVTRACE.PDB
```

Record the GUID and Age. They identify the matching PDB.

## 5. Unusual Sections

The section table contains eight non-standard data sections:

```text
.cache .old .rvn .tmp .xdat .trace .dbg2 .rsrc2
```

Physical section order is not PDB order.

## 6. Extraction

Extract each suspicious section by RVA/raw file offset. Example with Python:

```python
from pathlib import Path
from author.reconstruct_reference import PE
pe = PE(Path("RAVTRACE.EXE").read_bytes())
for name, blob in pe.custom_sections():
    Path(name[1:] + ".bin").write_bytes(blob)
```

## 7. Fragment Structure

Each object starts with a binary header:

```c
struct TRACE_BLOCK {
    uint16_t marker;
    uint16_t flags;
    uint32_t encoded_sequence;
    uint32_t stored_size;
    uint32_t decoded_size;
    uint32_t crc32;
    uint32_t set_tag;
    uint8_t  pdb_guid[16];
    uint32_t pdb_age;
    uint32_t pdb_size;
};
```

The marker is `0xa7d3`, not a text magic.

## 8. Transformations

`flags & 7` selects the primary transform:

```text
0 raw
1 xor with 92 bf 13 47
2 rotate-left-by-3 storage, so rotate right to decode
3 zlib
4 low-nibble subtract-11 storage, so add 11 to decode
```

`flags & 8` means the stored bytes were reversed after the primary transform.
Undo reversal before undoing the primary transform.

## 9. Fragment Decoding

Decode each section payload after the header. Validate decoded length.

## 10. CRC Validation

The header CRC32 is over the decoded fragment bytes. All eight fragments pass.

## 11. Real/Decoy Separation

Two fragments are real but from `RAVTEST.PDB`. They decode and CRC-check, but
their GUID/Age differs from the `RAVTRACE.EXE` CodeView record.

## 12. Ordering

Logical sequence:

```text
sequence = (encoded_sequence >> 4) ^ 0x41c6
```

Use only the six fragments whose GUID/Age match the executable.

## 13. Reconstruction

Sort matching fragments by sequence and concatenate.

```sh
python3 author/reconstruct_reference.py RAVTRACE.EXE RAVTRACE.PDB
```

## 14. PDB Validation

```sh
llvm-pdbutil dump -summary RAVTRACE.PDB
```

The file is a valid MSF 7.0 Microsoft-compatible PDB.

## 15. EXE/PDB Identity

Compare executable `RSDS` GUID/Age with PDB stream 1 GUID/Age. They match.
`RAVTEST.PDB` does not.

## 16. Ghidra PDB Import

1. Import `RAVTRACE.EXE`.
2. Analyze normally.
3. Place reconstructed `RAVTRACE.PDB` where Ghidra can find it or load it with
   the PDB analyzer.
4. Re-run analysis.

## 17. Private Symbol Analysis

Useful names appear:

```text
LoadTraceContext
DeriveTraceKey
TransformCandidate
ValidateCandidate
CompareRecordDigest
RestoreDebugBlock
VerifyTraceBlock
```

Types such as `TRACE_CONTEXT`, `TRACE_BLOCK`, and `VALIDATION_STATE` clarify
field offsets.

## 18. Final Validation Function

`ValidateCandidate` checks an obfuscated wrapper equivalent to:

```text
Securinets_fst{...}
```

The plaintext full flag is not stored.

## 19. Key Derivation

`DeriveTraceKey` uses an LCG:

```c
state = state * 1103515245 + 12345;
key[i] = (state >> 16) & 0xff;
```

Seed: `0x41c6a7d3`.

## 20. Transformation Recovery

The inner flag bytes are XORed with the rotating 8-byte key, permuted in
16-byte windows, rotated by byte position, then compared with an embedded
transformed byte target.

Permutation:

```text
7,2,13,0,11,4,15,8,1,10,5,14,3,12,9,6
```

For a short final block, ignore permutation entries outside the block and then
append any unused positions in ascending order. The transformed target and
inner length are constants in the binary. Reverse the rotations, inverse
permutation, and XOR key to recover the inner text.

## 21. Flag Recovery

The recovered flag is the author build secret:

```text
$CTF_FLAG
```

Verify:

```sh
RAVTRACE.EXE --check 'Securinets_fst{...}'
```

Expected success:

```text
TRACE RECORD VERIFIED
DEBUG SET    : ACCEPTED
```

## 22. Handoff

No repository handoff specification was present. This room therefore terminates
at flag acceptance and emits no later-stage location, traitor identity, or
extra token.

## Hints

1. Release builds sometimes remember where their symbols lived.
2. Not every section in this PE belongs to ordinary program code.
3. The strange blocks have more structure than their names suggest.
4. A valid fragment is not necessarily part of the correct debug set.
5. The executable and its debugging database share an identity.
6. Once the map is rebuilt, let the symbols rename the problem.
