#include "trace.hpp"

#include <stdio.h>
#include <string.h>

static const uint8_t kRestoreKey[4] = { 0x92, 0xbf, 0x13, 0x47 };
static const uint16_t kTraceMarker = 0xa7d3;

static uint8_t rol8(uint8_t v, unsigned r) {
    return (uint8_t)((v << r) | (v >> (8 - r)));
}

static uint8_t ror8(uint8_t v, unsigned r) {
    return (uint8_t)((v >> r) | (v << (8 - r)));
}

__declspec(noinline) void ClearWorkBuffer(void* ptr, uint32_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--) *p++ = 0;
}

__declspec(noinline) void InitializeTraceEngine(TRACE_CONTEXT* ctx) {
    if (!ctx) return;
    ResetTraceState(ctx);
    PrepareTraceContext(ctx);
}

__declspec(noinline) void ResetTraceState(TRACE_CONTEXT* ctx) {
    if (!ctx) return;
    ClearWorkBuffer(ctx, (uint32_t)sizeof(*ctx));
    ctx->flags = 0x1300;
}

__declspec(noinline) int LoadTraceHeader(const TRACE_BLOCK* block) {
    if (!block) return 0;
    if (block->marker != kTraceMarker) return 0;
    if (block->stored_size == 0 || block->decoded_size == 0) return 0;
    if (block->stored_size > 0x400000 || block->decoded_size > 0x400000) return 0;
    return 1;
}

__declspec(noinline) int ReadLotRecord(uint32_t lot_id, LOT_RECORD* record) {
    if (!record) return 0;
    ClearWorkBuffer(record, (uint32_t)sizeof(*record));
    record->lot_id = lot_id;
    record->relay_id = 0x19920711u ^ lot_id;
    memcpy(record->status, "SEALED", 7);
    return 1;
}

__declspec(noinline) int ParseTraceBlock(const uint8_t* raw, uint32_t raw_size, TRACE_BLOCK* out) {
    if (!raw || !out || raw_size < sizeof(TRACE_BLOCK)) return 0;
    memcpy(out, raw, sizeof(TRACE_BLOCK));
    return LoadTraceHeader(out);
}

__declspec(noinline) int NormalizeTraceBlock(TRACE_BLOCK* block) {
    if (!LoadTraceHeader(block)) return 0;
    block->flags &= 0x001f;
    return 1;
}

__declspec(noinline) uint32_t DecodeTraceSequence(uint32_t encoded_sequence) {
    return (encoded_sequence >> 4) ^ 0x41c6u;
}

__declspec(noinline) uint32_t CalculateRecordCRC(const uint8_t* data, uint32_t size) {
    uint32_t crc = 0xffffffffu;
    for (uint32_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (uint32_t bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

__declspec(noinline) int RestoreDebugBlock(const TRACE_BLOCK* block, const uint8_t* stored, uint8_t* out, uint32_t out_size) {
    if (!LoadTraceHeader(block) || !stored || !out || out_size < block->decoded_size) return 0;
    if ((block->flags & 7u) == 3u) return 0;
    if (block->stored_size != block->decoded_size) return 0;

    for (uint32_t i = 0; i < block->stored_size; ++i) {
        uint32_t si = (block->flags & 8u) ? block->stored_size - 1u - i : i;
        uint8_t b = stored[si];
        switch (block->flags & 7u) {
        case 1: b ^= kRestoreKey[i & 3u]; break;
        case 2: b = ror8(b, 3); break;
        case 4: b = (uint8_t)((b & 0xf0) | ((b + 11u) & 0x0f)); break;
        default: break;
        }
        out[i] = b;
    }
    return VerifyTraceBlock(block, out);
}

__declspec(noinline) int VerifyTraceBlock(const TRACE_BLOCK* block, const uint8_t* decoded) {
    if (!LoadTraceHeader(block) || !decoded) return 0;
    return CalculateRecordCRC(decoded, block->decoded_size) == block->checksum;
}

__declspec(noinline) void PrepareTraceContext(TRACE_CONTEXT* ctx) {
    if (!ctx) return;
    ctx->seed = 0x41c6a7d3u;
    for (uint32_t i = 0; i < 8; ++i) ctx->key[i] = (uint8_t)(0x31u + i * 17u);
}

__declspec(noinline) int DecodeLotRecord(const LOT_RECORD* in, LOT_RECORD* out) {
    if (!in || !out) return 0;
    memcpy(out, in, sizeof(*out));
    out->relay_id ^= 0x19920711u;
    return 1;
}

__declspec(noinline) void FormatDiagnosticLine(char* out, uint32_t out_size, const char* key, const char* value) {
    if (!out || out_size == 0) return;
    snprintf(out, out_size, "%-13s: %s", key ? key : "NO RECORD", value ? value : "INVALID");
}

__declspec(noinline) int LoadTraceContext(TRACE_CONTEXT* ctx) {
    if (!ctx) return 0;
    InitializeTraceEngine(ctx);
    return 1;
}

__declspec(noinline) int OpenRelayRecord(uint32_t relay_id, LOT_RECORD* out) {
    if (!out) return 0;
    ReadLotRecord(relay_id ^ 0x19920711u, out);
    out->relay_id = relay_id;
    return 1;
}
