"""Synthetic MSF/PDB core-stream fixture for parser tests, never a challenge artifact."""
import struct


def synthetic_pdb(guid):
    block_size, block_count = 4096, 80
    data = bytearray(block_size * block_count)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    sizes = [0, 28, 56, 64, 56, 71 * block_size]
    blocks = [[], [4], [5], [6], [7], list(range(8, 79))]
    directory = struct.pack("<I6I", 6, *sizes)
    for stream_blocks in blocks:
        directory += struct.pack("<" + "I" * len(stream_blocks), *stream_blocks)
    struct.pack_into("<6I", data, 32, block_size, 1, block_count, len(directory), 0, 3)
    struct.pack_into("<I", data, 3 * block_size, 79)
    data[79 * block_size:79 * block_size + len(directory)] = directory
    struct.pack_into("<III16s", data, 4 * block_size, 20000404, 0, 1, guid)
    for block in (5, 7):
        struct.pack_into("<5I", data, block * block_size, 20040203, 56, 0x1000, 0x1000, 0)
    struct.pack_into("<III", data, 6 * block_size, 0xffffffff, 19990903, 1)
    for offset in (12, 16, 20):
        struct.pack_into("<H", data, 6 * block_size + offset, 0xffff)
    for block in range(8, 79):
        data[block * block_size:(block + 1) * block_size] = bytes([block]) * block_size
    return bytes(data)
