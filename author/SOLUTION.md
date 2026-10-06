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
LoadTraceProfile
BindTraceProfile
LoadRecordTarget
ResolveTraceOperation
ApplyTraceHandler
DeriveTraceKey
TransformCandidate
ValidateCandidate
CompareRecordDigest
RecordTraceResult
RenderTraceStatus
RestoreDebugBlock
VerifyTraceBlock
```

Types such as `TRACE_CONTEXT`, `TRACE_PROFILE`, `TRACE_DISPATCH`, `TRACE_BLOCK`,
and `VALIDATION_STATE` clarify field offsets. Follow the default lot `0x0711`
through `ReadLotRecord`, `DecodeLotRecord`, profile loading, and binding. The
handler table is physically ordered cache, inventory, sealed. Match its mode
against `ctx->mode`, rather than assuming table order is execution order.

## 18. Final Validation Function

The terminal accepts `OPEN <RECORD>`. Its dispatch calls `ProcessTraceRecord`,
which resolves a typed handler entry from the current context. `ValidateCandidate`
serves both the sealed-record and cache profiles; inventory uses `OpenLotRecord`.
The shared comparator only reads `ctx->target`, `ctx->target_size`, and the
transformed state. It neither creates the profile nor selects the target.

In mode 1, `ValidateCandidate` checks an obfuscated wrapper equivalent to:

```text
Securinets_fst{...}
```

The plaintext full flag is not stored. Mode 2 instead uses a local cache record.
Neither an ordinary lot opening nor cache acceptance recovers the sealed record.
`TRACE_MATCH` passes through the selected dispatch entry, `RecordTraceResult`,
and `RenderTraceStatus`; the success text is shared with inventory openings.
An XREF to that text reaches the renderer, not a standalone flag checker.

## 19. Key Derivation

`DeriveTraceKey` uses an LCG:

```c
state = state * 1103515245 + 12345;
key[i] = (state >> 16) & 0xff;
```

The initial seed is `0x41c6a7d3`. `DecodeLotRecord` unmasks the record's relay
field, and `BindTraceProfile` sets:

```c
ctx->key_state = ctx->seed ^ record->relay_id ^ profile->seed_bias;
```

For the default sealed lot, the decoded relay and bias are both `0x0711`, so
the LCG starts at the initial seed. Other lots can produce different key states.
Key derivation starts from `ctx->key_state`, not directly from `ctx->seed`.

## 20. Transformation Recovery

The inner flag bytes are XORed with the rotating 8-byte key, permuted in
16-byte windows, rotated by byte position, then compared with an embedded
transformed byte target.

Permutation:

```text
7,2,13,0,11,4,15,8,1,10,5,14,3,12,9,6
```

For a short final block, ignore permutation entries outside the block and then
append any unused positions in ascending order. `LoadTraceProfile` supplies
the target length, permutation, key phase, and rotation period. For the default
sealed profile, phase is 0 and period is 5. `LoadRecordTarget` copies the sealed
target into the context; for cache mode it computes a different target using the
same transform. Recover the sealed context's target, reverse its rotations,
inverse permutation, and XOR key to recover the inner text. Examining the
comparator alone leaves these inputs unresolved.

## 21. Flag Recovery

The recovered flag is the author build secret:

```text
$CTF_FLAG
```

Verify:

```text
> OPEN Securinets_fst{...}
TRACE RECORD VERIFIED
```

The default lot is already selected at startup. After experimenting with other
lots, use `TRACE 0711` before opening the recovered sealed record. There is no
player command-line validation mode. Author tests send commands on standard input.

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
