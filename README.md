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

No fake PDB fallback is provided. If those tools are missing, the build stops
before producing player artifacts.
