#include "trace.hpp"
#include "validation.hpp"
#include "generated_constants.hpp"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t kRestoreKey[4] = { 0x92, 0xbf, 0x13, 0x47 };
static const uint16_t kTraceMarker = 0xa7d3;

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
    LoadTraceContext(ctx);
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
    if ((block->flags & ~0x0fu) || (block->flags & 7u) > 4u) return 0;
    uint32_t total = DecodeTraceTotalSize(block->encoded_total_size);
    uint32_t offset = DecodeTraceOffset(block->encoded_offset);
    if (!total || total > 0x4000000u || offset >= total || block->decoded_size > total - offset) return 0;
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

__declspec(noinline) int ParseLotIdentifier(const char* text, uint32_t* lot_id) {
    if (!text || !lot_id || !text[0] || strlen(text) > 8u) return 0;
    for (const char* p = text; *p; ++p)
        if (!strchr("0123456789abcdefABCDEF", *p)) return 0;
    *lot_id = (uint32_t)strtoul(text, 0, 16);
    return 1;
}

__declspec(noinline) int ParseTraceBlock(const uint8_t* raw, uint32_t raw_size, TRACE_BLOCK* out) {
    if (!raw || !out || raw_size < sizeof(TRACE_BLOCK)) return 0;
    memcpy(out, raw, sizeof(TRACE_BLOCK));
    if (out->stored_size > raw_size - sizeof(TRACE_BLOCK)) return 0;
    return LoadTraceHeader(out);
}

__declspec(noinline) int NormalizeTraceBlock(TRACE_BLOCK* block) {
    if (!LoadTraceHeader(block)) return 0;
    block->flags &= 0x000f;
    return 1;
}

__declspec(noinline) uint32_t DecodeTraceOffset(uint32_t encoded_offset) {
    return ((encoded_offset >> 5) | (encoded_offset << 27)) ^ 0x41c6a7d3u;
}

__declspec(noinline) uint32_t DecodeTraceTotalSize(uint32_t encoded_total_size) {
    return encoded_total_size ^ 0x19920711u;
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

static uint8_t ReadStoredByte(const TRACE_BLOCK* block, const uint8_t* stored, uint32_t index) {
    return stored[(block->flags & 8u) ? block->stored_size - 1u - index : index];
}

__declspec(noinline) int ExpandTraceBlock(const TRACE_BLOCK* block, const uint8_t* stored, uint8_t* out, uint32_t out_size) {
    if (!LoadTraceHeader(block) || !stored || !out || out_size < block->decoded_size) return 0;
    uint32_t src = 0, dst = 0;
    while (src < block->stored_size) {
        uint8_t control = ReadStoredByte(block, stored, src++);
        uint32_t count = (control & 0x80u) ? (control & 0x7fu) + 3u : control + 1u;
        if (count > block->decoded_size - dst) return 0;
        if (control & 0x80u) {
            if (src == block->stored_size) return 0;
            uint8_t value = ReadStoredByte(block, stored, src++);
            for (uint32_t i = 0; i < count; ++i) out[dst++] = value;
        } else {
            if (count > block->stored_size - src) return 0;
            for (uint32_t i = 0; i < count; ++i) out[dst++] = ReadStoredByte(block, stored, src++);
        }
    }
    return dst == block->decoded_size;
}

__declspec(noinline) int RestoreDebugBlock(const TRACE_BLOCK* block, const uint8_t* stored, uint8_t* out, uint32_t out_size) {
    if (!LoadTraceHeader(block) || !stored || !out || out_size < block->decoded_size) return 0;
    if ((block->flags & 7u) == 3u)
        return ExpandTraceBlock(block, stored, out, out_size) && VerifyTraceBlock(block, out);
    if (block->stored_size != block->decoded_size) return 0;

    for (uint32_t i = 0; i < block->stored_size; ++i) {
        uint8_t b = ReadStoredByte(block, stored, i);
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
    ctx->seed = kTraceSeed;
    ctx->lot_id = 0x0711u;
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
    LOT_RECORD raw, decoded;
    TRACE_PROFILE profile;
    if (!ReadLotRecord(ctx->lot_id, &raw) || !DecodeLotRecord(&raw, &decoded) ||
        !LoadTraceProfile(&decoded, &profile)) return 0;
    BindTraceProfile(ctx, &decoded, &profile);
    return LoadRecordTarget(ctx);
}

__declspec(noinline) int OpenRelayRecord(uint32_t relay_id, LOT_RECORD* out) {
    if (!out) return 0;
    ReadLotRecord(relay_id ^ 0x19920711u, out);
    out->relay_id = relay_id;
    return 1;
}

__declspec(noinline) int LoadTraceProfile(const LOT_RECORD* record, TRACE_PROFILE* profile) {
    if (!record || !profile) return 0;
    ClearWorkBuffer(profile, sizeof(*profile));
    profile->mode = record->lot_id & 3u;
    profile->seed_bias = profile->mode == 1u ? 0x0711u : 0x1992u;
    profile->target_size = profile->mode == 1u ? kExpectedInnerLength :
                           profile->mode == 2u ? 5u : 0u;
    profile->key_phase = profile->mode == 1u ? 0u : 2u;
    profile->rotation_period = profile->mode == 1u ? 5u : 3u;
    memcpy(profile->permutation, kPermutation, sizeof(profile->permutation));
    return 1;
}

__declspec(noinline) void BindTraceProfile(TRACE_CONTEXT* ctx, const LOT_RECORD* record, const TRACE_PROFILE* profile) {
    ctx->mode = profile->mode;
    ctx->key_state = ctx->seed ^ record->relay_id ^ profile->seed_bias;
    ctx->target_size = profile->target_size;
    ctx->key_phase = profile->key_phase;
    ctx->rotation_period = profile->rotation_period;
    memcpy(ctx->permutation, profile->permutation, sizeof(ctx->permutation));
}

__declspec(noinline) const TRACE_DISPATCH* ResolveTraceOperation(const TRACE_CONTEXT* ctx) {
    static const TRACE_DISPATCH operations[] = {
        { 2u, ValidateCandidate, TRACE_READY },
        { 0u, OpenLotRecord, TRACE_OPENED },
        { 1u, ValidateCandidate, TRACE_OPENED }
    };
    if (!ctx) return 0;
    for (uint32_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        if (operations[i].mode == ctx->mode) return operations + i;
    return 0;
}

__declspec(noinline) TRACE_STATUS ApplyTraceHandler(const TRACE_DISPATCH* operation, const TRACE_CONTEXT* ctx,
                                                  VALIDATION_STATE* state, const char* record) {
    if (!operation || !ctx || operation->mode != ctx->mode) return TRACE_NO_RECORD;
    TRACE_STATUS status = operation->handler(ctx, state, record);
    return status == TRACE_MATCH ? operation->accepted_status : status;
}

__declspec(noinline) TRACE_STATUS ProcessTraceRecord(TRACE_CONTEXT* ctx, const char* record) {
    if (!ctx) return TRACE_NO_RECORD;
    VALIDATION_STATE state = {};
    const TRACE_DISPATCH* operation = ResolveTraceOperation(ctx);
    TRACE_STATUS status = ApplyTraceHandler(operation, ctx, &state, record);
    ClearWorkBuffer(&state, sizeof(state));
    return RecordTraceResult(ctx, status);
}

__declspec(noinline) TRACE_STATUS RecordTraceResult(TRACE_CONTEXT* ctx, TRACE_STATUS status) {
    ctx->last_status = status;
    ctx->flags |= 1u;
    return ctx->last_status;
}

__declspec(noinline) void RenderTraceStatus(TRACE_STATUS status) {
    switch (status) {
    case TRACE_SILENT: break;
    case TRACE_OPENED: puts("TRACE RECORD VERIFIED"); break;
    case TRACE_READY: puts("LOT CACHE    : READY"); break;
    case TRACE_MISMATCH: puts("ERR: DEBUG SET MISMATCH"); break;
    default: puts("ERR: NO RECORD"); break;
    }
}
