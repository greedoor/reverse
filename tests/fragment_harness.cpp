#include "trace.hpp"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>

static std::vector<uint8_t> ReadFile(const char* path) {
    FILE* file = fopen(path, "rb");
    assert(file && fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size >= 0 && size <= 0x800000 && fseek(file, 0, SEEK_SET) == 0);
    std::vector<uint8_t> bytes((size_t)size);
    assert(fread(bytes.data(), 1, bytes.size(), file) == bytes.size());
    fclose(file);
    return bytes;
}

int main(int argc, char** argv) {
    assert(argc == 3);
    std::vector<uint8_t> object = ReadFile(argv[1]);
    TRACE_BLOCK block = {};
    bool parsed = ParseTraceBlock(object.data(), (uint32_t)object.size(), &block) != 0;
    if (strcmp(argv[2], "-") == 0) {
        if (!parsed) return 0;
        std::vector<uint8_t> output(block.decoded_size);
        if ((block.flags & 7u) == 3u)
            assert(!ExpandTraceBlock(&block, object.data() + sizeof(block), output.data(), (uint32_t)output.size()));
        assert(!RestoreDebugBlock(&block, object.data() + sizeof(block), output.data(), (uint32_t)output.size()));
        return 0;
    }
    std::vector<uint8_t> expected = ReadFile(argv[2]);
    assert(parsed && DecodeTraceOffset(block.encoded_offset) == 0x1234u);
    assert(DecodeTraceTotalSize(block.encoded_total_size) == 0x1234u + expected.size());
    std::vector<uint8_t> output(expected.size());
    assert(RestoreDebugBlock(&block, object.data() + sizeof(block), output.data(), (uint32_t)output.size()));
    assert(output == expected && VerifyTraceBlock(&block, output.data()));
    assert(!RestoreDebugBlock(&block, object.data() + sizeof(block), output.data(), (uint32_t)output.size() - 1u));
}
