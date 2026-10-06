#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

MARKER = 0xA7D3
SEQ_MASK = 0x41C6
RESTORE_KEY = bytes([0x92, 0xBF, 0x13, 0x47])
TRACE_TAG = 0x1300A11E
DECOY_TAG = 0x0D0C0B0A
HEADER = struct.Struct("<HHIIIII16sII")
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
    test_obj = obj / "ravtest"
    trace_obj.mkdir(parents=True, exist_ok=True)
    test_obj.mkdir(parents=True, exist_ok=True)
    common = [
        clang_cl, "/nologo", "/Zi", "/Od", "/MT", "/EHsc",
        "/D_CRT_SECURE_NO_WARNINGS", f"/I{root / 'src'}",
        f"/clang:-fdebug-compilation-dir=C:\\RAVEN\\DEV\\TRACE",
        f"/clang:-fdebug-prefix-map={root}=C:\\RAVEN\\DEV\\TRACE",
    ]
    trace_src = ["main.cpp", "trace.cpp", "validation.cpp"]
    trace_objs = []
    for name in trace_src:
        out = trace_obj / (Path(name).stem + ".obj")
        run(common + ["/c", str(root / "src" / name), f"/Fo{out}"])
        trace_objs.append(out)
    test_out = test_obj / "ravtest.obj"
    run(common + ["/c", str(root / "src/ravtest.cpp"), f"/Fo{test_out}"])
    run([lld_link, "/nologo", "/DEBUG", f"/PDB:{build / 'RAVTRACE_ORIGINAL.PDB'}",
         "/PDBALTPATH:C:\\RAVEN\\DEV\\TRACE\\RAVTRACE.PDB",
         f"/OUT:{build / 'RAVTRACE_BASE.EXE'}", "/SUBSYSTEM:CONSOLE", *map(str, trace_objs)])
    run([lld_link, "/nologo", "/DEBUG", f"/PDB:{build / 'RAVTEST_ORIGINAL.PDB'}",
         "/PDBALTPATH:C:\\RAVEN\\DEV\\TRACE\\RAVTEST.PDB",
         f"/OUT:{build / 'RAVTEST.EXE'}", "/SUBSYSTEM:CONSOLE", str(test_out)])


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

    def custom_sections(self):
        names = {name for name, _ in SECTION_ORDER}
        return [(s.name, bytes(self.data[s.raw_ptr:s.raw_ptr + s.vsize])) for s in self.sections if s.name in names]


def pdb_identity(path):
    data = Path(path).read_bytes()
    if not data.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0"):
        die(f"{path}: invalid PDB MSF header")
    block_size, free_map, block_count, dir_size = struct.unpack_from("<IIII", data, 32)
    block_map = struct.unpack_from("<I", data, 52)[0]
    dir_blocks = (dir_size + block_size - 1) // block_size
    block_nums = []
    pos = block_map * block_size
    for _ in range(dir_blocks):
        block_nums.append(struct.unpack_from("<I", data, pos)[0])
        pos += 4
    directory = bytearray()
    for b in block_nums:
        directory.extend(data[b * block_size:(b + 1) * block_size])
    stream_count = struct.unpack_from("<I", directory, 0)[0]
    sizes = list(struct.unpack_from("<" + "I" * stream_count, directory, 4))
    pos = 4 + 4 * stream_count
    streams = []
    for size in sizes:
        n = 0 if size == 0xFFFFFFFF else (size + block_size - 1) // block_size
        blocks = list(struct.unpack_from("<" + "I" * n, directory, pos)) if n else []
        pos += 4 * n
        blob = bytearray()
        for b in blocks:
            blob.extend(data[b * block_size:(b + 1) * block_size])
        streams.append(bytes(blob[:0 if size == 0xFFFFFFFF else size]))
    s1 = streams[1]
    age = struct.unpack_from("<I", s1, 8)[0]
    guid = s1[12:28]
    return guid, age


def encode_payload(decoded, base, rev):
    data = bytearray(decoded)
    if base == 1:
        for i in range(len(data)):
            data[i] ^= RESTORE_KEY[i & 3]
    elif base == 2:
        for i, b in enumerate(data):
            data[i] = ((b << 3) | (b >> 5)) & 0xFF
    elif base == 3:
        data = bytearray(zlib.compress(bytes(data), 9))
    elif base == 4:
        for i, b in enumerate(data):
            data[i] = (b & 0xF0) | ((b - 11) & 0x0F)
    if rev:
        data.reverse()
    return bytes(data)


def decode_payload(stored, base, rev):
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
        data = bytearray(zlib.decompress(bytes(data)))
    elif base == 4:
        for i, b in enumerate(data):
            data[i] = (b & 0xF0) | ((b + 11) & 0x0F)
    return bytes(data)


def split_six(data):
    cuts = [len(data) * p // 100 for p in (17, 31, 49, 66, 83)]
    return [data[a:b] for a, b in zip([0] + cuts, cuts + [len(data)])]


def split_decoys(data):
    a = len(data) * 19 // 100
    b = len(data) * 43 // 100
    c = len(data) * 61 // 100
    return [data[a:b], data[b:c]]


def make_object(kind, seq, chunk, guid, age, full_size):
    base, rev = TRANSFORMS[(kind, seq)]
    stored = encode_payload(chunk, base, rev)
    flags = base | rev
    enc_seq = ((seq ^ SEQ_MASK) << 4) | ((len(chunk) ^ (TRACE_TAG if kind == "trace" else DECOY_TAG)) & 0xF)
    hdr = HEADER.pack(MARKER, flags, enc_seq, len(stored), len(chunk), zlib.crc32(chunk) & 0xFFFFFFFF,
                      TRACE_TAG if kind == "trace" else DECOY_TAG, guid, age, full_size)
    return hdr + stored


def parse_object(blob):
    if len(blob) < HEADER.size:
        die("short fragment object")
    marker, flags, enc, stored_size, decoded_size, crc, tag, guid, age, pdb_size = HEADER.unpack_from(blob)
    if marker != MARKER:
        die("bad fragment marker")
    stored = blob[HEADER.size:HEADER.size + stored_size]
    if len(stored) != stored_size:
        die("short fragment payload")
    base, rev = flags & 7, flags & 8
    decoded = decode_payload(stored, base, rev)
    if len(decoded) != decoded_size:
        die("decoded size mismatch")
    if (zlib.crc32(decoded) & 0xFFFFFFFF) != crc:
        die("fragment CRC mismatch")
    seq = (enc >> 4) ^ SEQ_MASK
    return {
        "seq": seq, "tag": tag, "guid": guid, "age": age, "pdb_size": pdb_size,
        "decoded": decoded, "flags": flags, "stored_size": stored_size,
    }


def inject_fragments(base_exe, trace_pdb, test_pdb, out_exe):
    trace_data = Path(trace_pdb).read_bytes()
    test_data = Path(test_pdb).read_bytes()
    trace_guid, trace_age = pdb_identity(trace_pdb)
    test_guid, test_age = pdb_identity(test_pdb)
    chunks = {
        "trace": split_six(trace_data),
        "decoy": split_decoys(test_data),
    }
    objects = {}
    for kind in ("trace", "decoy"):
        guid, age, full = (trace_guid, trace_age, len(trace_data)) if kind == "trace" else (test_guid, test_age, len(test_data))
        for seq, chunk in enumerate(chunks[kind]):
            objects[(kind, seq)] = make_object(kind, seq, chunk, guid, age, full)
    pe = PE(Path(base_exe).read_bytes())
    pe.add_sections([(name, objects[key]) for name, key in SECTION_ORDER])
    Path(out_exe).write_bytes(pe.data)


def reconstruct_from_exe(exe, out_pdb, expected_guid=None, expected_age=None, original=None):
    pe = PE(Path(exe).read_bytes())
    if expected_guid is None:
        expected_guid, expected_age, _ = pe.debug_codeview()
    good = []
    all_objs = []
    for name, blob in pe.custom_sections():
        obj = parse_object(blob)
        obj["section"] = name
        all_objs.append(obj)
        if obj["guid"] == expected_guid and obj["age"] == expected_age and obj["tag"] == TRACE_TAG:
            good.append(obj)
    if len(good) != 6:
        die(f"expected 6 matching fragments, got {len(good)}")
    seqs = sorted(o["seq"] for o in good)
    if seqs != list(range(6)):
        die(f"bad real fragment sequence set: {seqs}")
    data = b"".join(o["decoded"] for o in sorted(good, key=lambda o: o["seq"]))
    if len({o["pdb_size"] for o in good}) != 1 or len(data) != good[0]["pdb_size"]:
        die("reconstructed PDB size mismatch")
    Path(out_pdb).write_bytes(data)
    if original and Path(original).read_bytes() != data:
        die("reconstructed PDB differs from original")
    return all_objs


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
