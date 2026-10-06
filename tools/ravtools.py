#!/usr/bin/env python3
import argparse
import binascii
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

MARKER = 0xA7D3
OFFSET_MASK = 0x41C6A7D3
TOTAL_MASK = 0x19920711
MAX_PDB_SIZE = 0x4000000
RESTORE_KEY = bytes([0x92, 0xBF, 0x13, 0x47])
HEADER = struct.Struct("<HHIIIII")
SECTION_ORDER = [
    (".cache", ("trace", 4)),
    (".old", ("decoy", 0)),
    (".rvn", ("trace", 1)),
    (".tmp", ("trace", 5)),
    (".xdat", ("trace", 0)),
    (".trace", ("decoy", 1)),
    (".dbg2", ("trace", 3)),
    (".rsrc2", ("trace", 2)),
]
TRANSFORMS = {
    ("trace", 0): (1, 0),
    ("trace", 1): (0, 8),
    ("trace", 2): (2, 0),
    ("trace", 3): (3, 0),
    ("trace", 4): (1, 8),
    ("trace", 5): (0, 0),
    ("decoy", 0): (2, 8),
    ("decoy", 1): (4, 0),
}
PERMUTATION = [7, 2, 13, 0, 11, 4, 15, 8, 1, 10, 5, 14, 3, 12, 9, 6]
TRACE_SEED = 0x41C6A7D3


def die(msg):
    raise SystemExit(f"ERR: {msg}")


def align(v, a):
    return (v + a - 1) // a * a


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def flag_inner(flag):
    prefix, suffix = "Securinets_fst{", "}"
    if not flag.startswith(prefix) or not flag.endswith(suffix):
        die("CTF_FLAG must use Securinets_fst{...}")
    inner = flag[len(prefix):-1].encode("ascii")
    if not (1 <= len(inner) <= 64):
        die("flag inner length must be 1..64 bytes")
    return inner


def validation_target(inner):
    state = TRACE_SEED
    key = []
    for _ in range(8):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        key.append((state >> 16) & 0xFF)
    buf = bytearray(64)
    for i, b in enumerate(inner):
        buf[i] = b ^ key[i & 7]
    out = bytearray(buf)
    for base in range(0, len(inner), 16):
        n = min(16, len(inner) - base)
        order = [p for p in PERMUTATION if p < n]
        order += [i for i in range(n) if i not in order]
        tmp = [buf[base + i] for i in order]
        for i, b in enumerate(tmp):
            r = (i % 5) + 1
            out[base + i] = ((b << r) | (b >> (8 - r))) & 0xFF
    return bytes(out[:len(inner)])


def write_generated_constants(root, flag):
    inner = flag_inner(flag)
    target = validation_target(inner).ljust(64, b"\0")
    tmpl = (root / "src/generated_constants.hpp.in").read_text()
    rendered = (tmpl
        .replace("@TRACE_SEED@", str(TRACE_SEED))
        .replace("@INNER_LENGTH@", str(len(inner)))
        .replace("@EXPECTED_TRANSFORMED@", ", ".join(f"0x{x:02x}" for x in target))
        .replace("@PERMUTATION@", ", ".join(str(x) for x in PERMUTATION)))
    (root / "src/generated_constants.hpp").write_text(rendered)


def run(cmd, cwd=None):
    print("+", " ".join(map(str, cmd)))
    subprocess.run(cmd, cwd=cwd, check=True)


def need_tool(name):
    path = shutil.which(name)
    if not path:
        die(f"missing required tool: {name}")
    return path


def compile_windows(root, build):
    clang_cl = need_tool("clang-cl")
    lld_link = need_tool("lld-link")
    obj = build / "obj"
    trace_obj = obj / "ravtrace"
    test_obj = obj / "service"
    trace_obj.mkdir(parents=True, exist_ok=True)
    test_obj.mkdir(parents=True, exist_ok=True)
    common = [
        clang_cl, "/nologo", "/Zi", "/Od", "/MT", "/EHsc",
        "/clang:--target=i686-pc-windows-msvc",
        "/D_CRT_SECURE_NO_WARNINGS", f"/I{root / 'src'}",
        f"/clang:-fdebug-compilation-dir=C:\\RAVEN\\DEV\\TRACE",
        f"/clang:-fdebug-prefix-map={root}=C:\\RAVEN\\DEV\\TRACE",
    ]
    trace_src = ["main.cpp", "trace.cpp", "validation.cpp"]
    trace_objs = []
    for name in trace_src:
        out = (trace_obj / (Path(name).stem + ".obj")).relative_to(root)
        run(common + ["/c", str(Path("src") / name), f"/Fo{out}"], cwd=root)
        trace_objs.append(out)
    test_out = (test_obj / "service.obj").relative_to(root)
    run(common + ["/c", "src/service.cpp", f"/Fo{test_out}"], cwd=root)
    link_options = [lld_link, "/nologo", "/DEBUG:FULL", "/INCREMENTAL:NO", "/OPT:NOREF", "/OPT:NOICF", "/MACHINE:X86", "/FILEALIGN:4096"]
    run(link_options + [f"/PDB:{build / 'RAVTRACE_ORIGINAL.PDB'}",
         "/PDBALTPATH:C:\\RAVEN\\DEV\\TRACE\\RAVTRACE.PDB",
         f"/OUT:{build / 'RAVTRACE_BASE.EXE'}", "/SUBSYSTEM:CONSOLE", *map(str, trace_objs)], cwd=root)
    run(link_options + [f"/PDB:{build / 'RAVTEST_ORIGINAL.PDB'}",
         "/PDBALTPATH:C:\\RAVEN\\DEV\\TRACE\\RAVTEST.PDB",
         f"/OUT:{build / 'RAVTEST.EXE'}", "/SUBSYSTEM:CONSOLE", str(test_out)], cwd=root)


@dataclass
class Section:
    name: str
    vsize: int
    vaddr: int
    raw_size: int
    raw_ptr: int
    chars: int


class PE:
    def __init__(self, data):
        self.data = bytearray(data)
        if self.data[:2] != b"MZ":
            die("not an MZ executable")
        self.peoff = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[self.peoff:self.peoff + 4] != b"PE\0\0":
            die("not a PE image")
        coff = self.peoff + 4
        self.machine, self.nsec, _, _, _, self.optsz, _ = struct.unpack_from("<HHIIIHH", self.data, coff)
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", self.data, self.opt)[0]
        self.is64 = self.magic == 0x20B
        if self.magic not in (0x10B, 0x20B):
            die("unknown PE optional header")
        self.file_align = struct.unpack_from("<I", self.data, self.opt + 36)[0]
        self.sec_align = struct.unpack_from("<I", self.data, self.opt + 32)[0]
        self.size_image_off = self.opt + 56
        self.size_headers = struct.unpack_from("<I", self.data, self.opt + 60)[0]
        self.ddir = self.opt + (112 if self.is64 else 96)
        self.sectab = self.opt + self.optsz
        self.sections = []
        for i in range(self.nsec):
            off = self.sectab + i * 40
            name = self.data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", self.data, off + 8)
            chars = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append(Section(name, vsize, vaddr, raw_size, raw_ptr, chars))

    def rva_to_off(self, rva):
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.vaddr <= rva < s.vaddr + span:
                return s.raw_ptr + (rva - s.vaddr)
        return rva if rva < self.size_headers else None

    def debug_codeview(self):
        rva, size = struct.unpack_from("<II", self.data, self.ddir + 6 * 8)
        if not rva or size < 28:
            die("debug directory missing")
        off = self.rva_to_off(rva)
        for i in range(size // 28):
            e = off + i * 28
            typ = struct.unpack_from("<I", self.data, e + 12)[0]
            if typ != 2:
                continue
            sz, data_rva, raw = struct.unpack_from("<III", self.data, e + 16)
            if not raw:
                raw = self.rva_to_off(data_rva)
            if raw is None or raw + sz > len(self.data):
                die("CodeView data lies outside the file")
            blob = bytes(self.data[raw:raw + sz])
            if blob[:4] == b"RSDS":
                guid = blob[4:20]
                age = struct.unpack_from("<I", blob, 20)[0]
                path = blob[24:].split(b"\0", 1)[0].decode("utf-8", "replace")
                return guid, age, path
        die("RSDS CodeView record missing")

    def add_sections(self, items):
        table_end = self.sectab + (self.nsec + len(items)) * 40
        if table_end > self.size_headers:
            die("not enough PE header slack for extra sections")
        last = max(self.sections, key=lambda s: s.vaddr)
        raw = align(len(self.data), self.file_align)
        if len(self.data) < raw:
            self.data.extend(b"\0" * (raw - len(self.data)))
        va = align(last.vaddr + max(last.vsize, last.raw_size), self.sec_align)
        for name, payload in items:
            if len(name.encode("ascii")) > 8:
                die(f"section name too long: {name}")
            raw_size = align(len(payload), self.file_align)
            off = self.sectab + self.nsec * 40
            self.data[off:off + 8] = name.encode("ascii").ljust(8, b"\0")
            struct.pack_into("<IIIIIIHHI", self.data, off + 8,
                             len(payload), va, raw_size, raw, 0, 0, 0, 0, 0x40000040)
            self.data.extend(payload)
            self.data.extend(b"\0" * (raw_size - len(payload)))
            self.sections.append(Section(name, len(payload), va, raw_size, raw, 0x40000040))
            self.nsec += 1
            raw += raw_size
            va = align(va + len(payload), self.sec_align)
        struct.pack_into("<H", self.data, self.peoff + 6, self.nsec)
        struct.pack_into("<I", self.data, self.size_image_off, va)
        initialized = struct.unpack_from("<I", self.data, self.opt + 8)[0]
        struct.pack_into("<I", self.data, self.opt + 8, initialized + sum(align(len(payload), self.file_align) for _, payload in items))

    def custom_sections(self):
        marker = struct.pack("<H", MARKER)
        return [(s.name, bytes(self.data[s.raw_ptr:s.raw_ptr + s.vsize])) for s in self.sections
                if self.data[s.raw_ptr:s.raw_ptr + 2] == marker]


def pdb_identity_bytes(data):
    """Validate the complete MSF layout and core PDB streams before returning identity."""
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(len(data) >= 56 and data[:32] == b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "invalid MSF header")
    block_size, free_map, block_count, dir_size, reserved, block_map = struct.unpack_from("<6I", data, 32)
    require(block_size in (512, 1024, 2048, 4096) and free_map in (1, 2) and reserved == 0, "invalid MSF parameters")
    require(block_count * block_size == len(data) and len(data) <= MAX_PDB_SIZE, "invalid MSF file size")
    require(4 <= dir_size <= len(data) and 2 < block_map < block_count, "invalid stream directory")
    count = (dir_size + block_size - 1) // block_size
    require(count * 4 <= block_size, "directory block map too large")
    dir_blocks = struct.unpack_from("<" + "I" * count, data, block_map * block_size)
    occupied = {0, 1, 2, block_map}

    def claim(blocks):
        for block in blocks:
            require(block < block_count and block not in occupied, "overlapping/out-of-bounds MSF block")
            occupied.add(block)

    def join(blocks, size):
        return b"".join(data[b * block_size:(b + 1) * block_size] for b in blocks)[:size]

    claim(dir_blocks)
    directory = join(dir_blocks, dir_size)
    stream_count = struct.unpack_from("<I", directory)[0]
    require(5 <= stream_count <= (dir_size - 4) // 4, "invalid stream count")
    sizes = struct.unpack_from("<" + "I" * stream_count, directory, 4)
    pos = 4 + 4 * stream_count
    streams = []
    for size in sizes:
        require(size == 0xffffffff or size <= len(data), "invalid stream length")
        n = 0 if size == 0xffffffff else (size + block_size - 1) // block_size
        require(pos + n * 4 <= dir_size, "truncated stream block list")
        blocks = struct.unpack_from("<" + "I" * n, directory, pos)
        pos += n * 4
        claim(blocks)
        streams.append(join(blocks, 0 if size == 0xffffffff else size))
    require(pos == dir_size, "trailing stream directory data")
    info = streams[1]
    require(len(info) >= 28 and struct.unpack_from("<I", info)[0] == 20000404, "invalid PDB info stream")
    age = struct.unpack_from("<I", info, 8)[0]
    require(age > 0, "invalid PDB age")
    dbi = streams[3]
    require(len(dbi) >= 64, "truncated DBI stream")
    require(struct.unpack_from("<III", dbi) == (0xffffffff, 19990903, age), "invalid DBI header")
    sizes = [struct.unpack_from("<i", dbi, p)[0] for p in (24, 28, 32, 36, 40, 48, 52)]
    require(all(s >= 0 for s in sizes) and 64 + sum(sizes) == len(dbi), "invalid DBI substreams")
    for p in (12, 16, 20):
        index = struct.unpack_from("<H", dbi, p)[0]
        require(index == 0xffff or index < stream_count, "invalid DBI stream reference")
    for types in (streams[2], streams[4]):
        require(len(types) >= 56, "truncated TPI/IPI stream")
        version, header_size, begin, end, record_size = struct.unpack_from("<5I", types)
        require(version == 20040203 and header_size == 56 and begin <= end and
                header_size + record_size <= len(types), "invalid TPI/IPI header")
        pos, records = header_size, 0
        while pos < header_size + record_size:
            require(pos + 4 <= header_size + record_size, "truncated type record")
            size = struct.unpack_from("<H", types, pos)[0] + 2
            require(size >= 4 and pos + size <= header_size + record_size, "invalid type record length")
            pos += size
            records += 1
        require(records == end - begin, "incorrect type record count")
    return info[12:28], age


def pdb_identity(path):
    try:
        return pdb_identity_bytes(Path(path).read_bytes())
    except ValueError as error:
        die(f"{path}: {error}")


def encode_offset(offset):
    value = offset ^ OFFSET_MASK
    return ((value << 5) | (value >> 27)) & 0xffffffff


def decode_offset(encoded):
    return ((encoded >> 5) | ((encoded << 27) & 0xffffffff)) ^ OFFSET_MASK


def encode_rle(data):
    out = bytearray()
    pos = 0
    while pos < len(data):
        run = 1
        while run < 130 and pos + run < len(data) and data[pos + run] == data[pos]:
            run += 1
        if run >= 3:
            out.extend((0x80 | (run - 3), data[pos]))
            pos += run
        else:
            start = pos
            while pos < len(data) and pos - start < 128:
                if pos + 2 < len(data) and data[pos] == data[pos + 1] == data[pos + 2]:
                    break
                pos += 1
            out.append(pos - start - 1)
            out.extend(data[start:pos])
    return bytes(out)


def decode_rle(data, decoded_size):
    out = bytearray()
    pos = 0
    while pos < len(data):
        control = data[pos]
        pos += 1
        count = (control & 0x7f) + 3 if control & 0x80 else control + 1
        consumed = 1 if control & 0x80 else count
        if pos + consumed > len(data) or len(out) + count > decoded_size:
            die("invalid RLE block")
        out.extend(bytes([data[pos]]) * count if control & 0x80 else data[pos:pos + count])
        pos += consumed
    if len(out) != decoded_size:
        die("truncated RLE output")
    return bytes(out)


def encode_payload(decoded, base, rev):
    data = bytearray(decoded)
    if base == 1:
        for i in range(len(data)):
            data[i] ^= RESTORE_KEY[i & 3]
    elif base == 2:
        for i, b in enumerate(data):
            data[i] = ((b << 3) | (b >> 5)) & 0xFF
    elif base == 3:
        data = bytearray(encode_rle(data))
    elif base == 4:
        for i, b in enumerate(data):
            data[i] = (b & 0xF0) | ((b - 11) & 0x0F)
    elif base != 0:
        die("unsupported transform")
    if rev:
        data.reverse()
    return bytes(data)


def decode_payload(stored, base, rev, decoded_size):
    data = bytearray(stored)
    if rev:
        data.reverse()
    if base == 1:
        for i in range(len(data)):
            data[i] ^= RESTORE_KEY[i & 3]
    elif base == 2:
        for i, b in enumerate(data):
            data[i] = ((b >> 3) | (b << 5)) & 0xFF
    elif base == 3:
        data = bytearray(decode_rle(bytes(data), decoded_size))
    elif base == 4:
        for i, b in enumerate(data):
            data[i] = (b & 0xF0) | ((b + 11) & 0x0F)
    elif base != 0:
        die("unsupported transform")
    return bytes(data)


def split_six(data):
    cuts = [len(data) * p // 100 for p in (17, 31, 49, 66, 83)]
    return [data[a:b] for a, b in zip([0] + cuts, cuts + [len(data)])]


def make_object(offset, chunk, full_size, base, rev=0):
    stored = encode_payload(chunk, base, rev)
    flags = base | rev
    hdr = HEADER.pack(MARKER, flags, encode_offset(offset), len(stored), len(chunk),
                      binascii.crc32(chunk) & 0xffffffff, full_size ^ TOTAL_MASK)
    return hdr + stored


def parse_object(blob):
    if len(blob) < HEADER.size:
        die("short fragment object")
    marker, flags, enc, stored_size, decoded_size, crc, encoded_total = HEADER.unpack_from(blob)
    offset, total = decode_offset(enc), encoded_total ^ TOTAL_MASK
    if marker != MARKER or flags & ~0x0f or (flags & 7) > 4:
        die("invalid fragment header")
    if not (0 < stored_size <= 0x400000 and 0 < decoded_size <= 0x400000 and
            0 < total <= MAX_PDB_SIZE and offset < total and decoded_size <= total - offset):
        die("invalid fragment range/size")
    stored = blob[HEADER.size:HEADER.size + stored_size]
    if len(stored) != stored_size:
        die("short fragment payload")
    base, rev = flags & 7, flags & 8
    decoded = decode_payload(stored, base, rev, decoded_size)
    if len(decoded) != decoded_size:
        die("decoded size mismatch")
    if (binascii.crc32(decoded) & 0xFFFFFFFF) != crc:
        die("fragment CRC mismatch")
    return {
        "offset": offset, "total_size": total,
        "decoded": decoded, "flags": flags, "stored_size": stored_size,
    }


def inject_fragments(base_exe, trace_pdb, test_pdb, out_exe):
    trace_data = Path(trace_pdb).read_bytes()
    test_data = Path(test_pdb).read_bytes()
    if pdb_identity(trace_pdb) == pdb_identity(test_pdb):
        die("second PDB identity must differ")
    chunks = split_six(trace_data)
    objects = {}
    offset = 0
    for i, chunk in enumerate(chunks):
        objects[("trace", i)] = make_object(offset, chunk, len(trace_data), *TRANSFORMS[("trace", i)])
        offset += len(chunk)
    # A different boundary makes two foreign pieces compete with two genuine intervals.
    end = len(chunks[0]) + len(chunks[1])
    middle = end * 47 // 100
    if len(test_data) < end or not middle:
        die("second PDB too small for competing prefix")
    for i, (start, stop) in enumerate(((0, middle), (middle, end))):
        objects[("decoy", i)] = make_object(start, test_data[start:stop], len(trace_data), *TRANSFORMS[("decoy", i)])
    pe = PE(Path(base_exe).read_bytes())
    pe.add_sections([(name, objects[key]) for name, key in SECTION_ORDER])
    Path(out_exe).write_bytes(pe.data)


def interval_candidates(objects):
    """Walk only gap-free interval chains; neither section names nor fragment counts select a set."""
    for total in sorted({obj["total_size"] for obj in objects}):
        by_offset = {}
        for obj in objects:
            if obj["total_size"] == total:
                by_offset.setdefault(obj["offset"], []).append(obj)

        def walk(offset, chain):
            if offset == total:
                yield chain
            for obj in by_offset.get(offset, ()):
                yield from walk(offset + len(obj["decoded"]), chain + [obj])

        yield from walk(0, [])


def reconstruct_from_exe(exe, out_pdb, original=None):
    pe = PE(Path(exe).read_bytes())
    expected_guid, expected_age, _ = pe.debug_codeview()
    all_objs = []
    for name, blob in pe.custom_sections():
        obj = parse_object(blob)
        obj["section"] = name
        all_objs.append(obj)
    matches, candidates = [], []
    for chain in interval_candidates(all_objs):
        data = b"".join(obj["decoded"] for obj in chain)
        candidate = {"sections": [obj["section"] for obj in chain]}
        try:
            identity = pdb_identity_bytes(data)
            candidate["guid"], candidate["age"] = identity[0].hex(), identity[1]
            candidate["status"] = "match" if identity == (expected_guid, expected_age) else "identity mismatch"
        except ValueError as error:
            candidate["status"] = "invalid PDB: " + str(error)
        candidates.append(candidate)
        if candidate["status"] == "match":
            matches.append((data, chain))
    if len(matches) != 1:
        die(f"expected one structurally valid matching PDB, got {len(matches)} from {len(candidates)} interval covers")
    data, selected = matches[0]
    Path(out_pdb).write_bytes(data)
    if original and Path(original).read_bytes() != data:
        die("reconstructed PDB differs from original")
    return {"objects": all_objs, "selected": selected, "candidates": candidates}


def package(root, dist):
    player_src = root / "player"
    player_dist = dist / "player"
    player_dist.mkdir(parents=True, exist_ok=True)
    shutil.copy2(dist / "author/RAVTRACE.EXE", player_dist / "RAVTRACE.EXE")
    shutil.copy2(player_src / "README.NFO", player_dist / "README.NFO")
    shutil.copy2(player_src / "FILE_ID.DIZ", player_dist / "FILE_ID.DIZ")
    zip_path = player_dist / "RAVTRACE.ZIP"
    with ZipFile(zip_path, "w", ZIP_DEFLATED) as z:
        for name in ("RAVTRACE.EXE", "README.NFO", "FILE_ID.DIZ"):
            z.write(player_dist / name, name)
    return zip_path


def build(args):
    root = Path(args.root).resolve()
    flag = os.environ.get("CTF_FLAG")
    if not flag:
        die("set CTF_FLAG='Securinets_fst{...}' before building")
    need_tool("clang-cl")
    need_tool("lld-link")
    write_generated_constants(root, flag)
    build_dir = root / "build"
    dist = root / "dist"
    shutil.rmtree(build_dir, ignore_errors=True)
    shutil.rmtree(dist, ignore_errors=True)
    build_dir.mkdir()
    (dist / "author").mkdir(parents=True)
    compile_windows(root, build_dir)
    final_exe = dist / "author/RAVTRACE.EXE"
    inject_fragments(build_dir / "RAVTRACE_BASE.EXE", build_dir / "RAVTRACE_ORIGINAL.PDB",
                     build_dir / "RAVTEST_ORIGINAL.PDB", final_exe)
    shutil.copy2(build_dir / "RAVTRACE_ORIGINAL.PDB", dist / "author/RAVTRACE_ORIGINAL.PDB")
    shutil.copy2(build_dir / "RAVTEST_ORIGINAL.PDB", dist / "author/RAVTEST_ORIGINAL.PDB")
    reconstruct_from_exe(final_exe, dist / "author/RAVTRACE_RECONSTRUCTED.PDB",
                         original=dist / "author/RAVTRACE_ORIGINAL.PDB")
    package(root, dist)
    run([sys.executable, str(root / "author/verify_challenge.py")], cwd=root)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--root", default=Path(__file__).resolve().parents[1])
    i = sub.add_parser("inject")
    i.add_argument("base_exe"); i.add_argument("trace_pdb"); i.add_argument("test_pdb"); i.add_argument("out_exe")
    r = sub.add_parser("reconstruct")
    r.add_argument("exe"); r.add_argument("out_pdb"); r.add_argument("--original")
    args = p.parse_args()
    if args.cmd == "build":
        build(args)
    elif args.cmd == "inject":
        inject_fragments(args.base_exe, args.trace_pdb, args.test_pdb, args.out_exe)
    elif args.cmd == "reconstruct":
        reconstruct_from_exe(args.exe, args.out_pdb, original=args.original)


if __name__ == "__main__":
    main()
