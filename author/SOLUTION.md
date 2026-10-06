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
    uint32_t encoded_offset;
    uint32_t stored_size;
    uint32_t decoded_size;
    uint32_t crc32;
    uint32_t encoded_total_size;
};
```

The marker is `0xa7d3`, not a text magic. The header is 24 bytes. It contains
neither a set classifier nor a GUID/Age, and flags describe only transformations.

## 8. Transformations

`flags & 7` selects the primary transform:

```text
0 raw
1 xor with 92 bf 13 47
2 rotate-left-by-3 storage, so rotate right to decode
3 run-length expansion
4 low-nibble subtract-11 storage, so add 11 to decode
```

`flags & 8` means the stored bytes were reversed after the primary transform.
Undo reversal before undoing the primary transform.

Reverse `ExpandTraceBlock` for transform 3. Control bytes below `0x80` copy
the following `control + 1` literals. Other controls repeat the next byte
`(control & 0x7f) + 3` times. The decoder rejects truncated input, excess output,
or a final decoded length mismatch. Every transform exists in the executable.

## 9. Fragment Decoding

Decode each section payload after the header. Validate decoded length.

## 10. CRC Validation

The header CRC32 is over the decoded fragment bytes. All eight fragments pass.

## 11. Real/Decoy Separation

All eight objects decode and pass CRC. Recover their ranges and common total
size, then follow only chains where each interval starts exactly at the preceding
interval's end. Two intervals with a different internal boundary offer an
alternative to the first two intervals, continuing into the same remaining ranges.
Both complete covers use six objects. Neither count, CRC nor total size
selects the correct path. No object carries an identity to filter in advance.

## 12. Ordering

Logical placement is a byte offset, not a sequence number:

```text
offset = ror32(encoded_offset, 5) ^ 0x41c6a7d3
total_size = encoded_total_size ^ 0x19920711
```

`DecodeTraceOffset` and `DecodeTraceTotalSize` implement these mappings. The
reference script discovers intervals by binary marker, independent of section
names and the author build map. It does not use the expected fragment count to
prune the competing path; that count is an author verification invariant.

## 13. Reconstruction

Construct both gap-free complete candidate files. Both use six fragments; the
competing path replaces two genuine intervals with two foreign intervals having
a different shared boundary. Parse the full MSF block map, stream directory, info stream, DBI and
TPI/IPI streams. Only then extract each structurally valid candidate's GUID/Age
and compare it to the EXE RSDS. A candidate may fail structural checks or have
the wrong identity. The unique matching candidate is the correct reconstruction.
The two foreign payloads are contiguous portions of the genuine RAVTEST PDB;
they are not synthetic debug data and do not form its complete file.

```sh
python3 author/reconstruct_reference.py RAVTRACE.EXE RAVTRACE.PDB
```

## 14. PDB Validation

```sh
llvm-pdbutil dump -summary RAVTRACE.PDB
```

The file must be accepted as an MSF 7.0 Microsoft-compatible PDB. Full build
verification additionally parses private symbols/types with llvm-pdbutil. The
original PDB is used only for a byte-for-byte assertion after candidate selection.

## 15. EXE/PDB Identity

Compare executable `RSDS` GUID/Age with PDB stream 1 GUID/Age. They match.
`RAVTEST.PDB` does not.

## 16. Ghidra PDB Import

1. Import `RAVTRACE.EXE`.
2. Analyze normally.
3. Place reconstructed `RAVTRACE.PDB` where Ghidra can find it or load it with
   the PDB analyzer.
4. Re-run analysis. Confirm ValidateCandidate, TransformCandidate and
   DeriveTraceKey functions and the five private structure types.

Automated author proof (requires `GHIDRA_HOME`):

```sh
python3 author/verify_ghidra.py
```

This reconstructs the PDB again using only the packaged EXE. Separate headless
imports assert that names/types are absent before PDB loading and present after.
It checks the validator's context prototype and TRACE_BLOCK field offsets.

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
