#include "validation.hpp"

#include "generated_constants.hpp"

#include <string.h>

static uint8_t rol8v(uint8_t v, unsigned r) {
    return (uint8_t)((v << r) | (v >> (8 - r)));
}

static void BuildWrapper(uint8_t* prefix, uint8_t* suffix) {
    static const uint8_t p[] = {
        0x16,0x20,0x26,0x30,0x37,0x2c,0x2b,0x20,0x31,0x36,0x1a,0x23,0x36,0x31,0x3e
    };
    for (uint32_t i = 0; i < sizeof(p); ++i) prefix[i] = (uint8_t)(p[i] ^ 0x45u);
    *suffix = (uint8_t)(0x38u ^ 0x45u);
}

__declspec(noinline) int LoadRecordTarget(TRACE_CONTEXT* ctx) {
    if (!ctx || ctx->target_size > sizeof(ctx->target)) return 0;
    ClearWorkBuffer(ctx->target, sizeof(ctx->target));
    if (ctx->mode == 1u) {
        memcpy(ctx->target, kExpectedTransformed, ctx->target_size);
    } else if (ctx->mode == 2u) {
        VALIDATION_STATE state = {};
        DeriveTraceKey(ctx, &state);
        TransformCandidate(ctx, &state, (const uint8_t*)"LOCAL", 5);
        memcpy(ctx->target, state.transformed, ctx->target_size);
        ClearWorkBuffer(&state, sizeof(state));
    }
    return 1;
}

__declspec(noinline) void DeriveTraceKey(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state) {
    if (!ctx || !state) return;
    state->state = ctx->key_state;
    for (uint32_t i = 0; i < 8; ++i) {
        state->state = state->state * 1103515245u + 12345u;
        state->working_key[i] = (uint8_t)((state->state >> 16) & 0xffu);
    }
}

__declspec(noinline) void TransformCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const uint8_t* inner, uint32_t inner_len) {
    if (!ctx || !state || !inner || inner_len > sizeof(state->transformed) ||
        ctx->rotation_period == 0 || ctx->rotation_period > 7) return;
    state->payload_size = inner_len;
    for (uint32_t i = 0; i < inner_len; ++i)
        state->transformed[i] = (uint8_t)(inner[i] ^ state->working_key[(i + ctx->key_phase) & 7u]);

    for (uint32_t base = 0; base < inner_len; base += 16) {
        uint8_t tmp[16] = {0};
        uint8_t used[16] = {0};
        uint32_t pos = 0;
        uint32_t n = inner_len - base < 16 ? inner_len - base : 16;
        for (uint32_t i = 0; i < 16; ++i) {
            uint32_t src = ctx->permutation[i];
            if (src < n) {
                tmp[pos++] = state->transformed[base + src];
                used[src] = 1;
            }
        }
        for (uint32_t i = 0; i < n; ++i)
            if (!used[i]) tmp[pos++] = state->transformed[base + i];
        for (uint32_t i = 0; i < n; ++i)
            state->transformed[base + i] = rol8v(tmp[i], (i % ctx->rotation_period) + 1u);
    }
}

__declspec(noinline) int CompareRecordDigest(const TRACE_CONTEXT* ctx, const VALIDATION_STATE* state) {
    if (!ctx || !state || !ctx->target_size || ctx->target_size > sizeof(ctx->target) ||
        state->payload_size != ctx->target_size) return 0;
    uint8_t diff = 0;
    for (uint32_t i = 0; i < ctx->target_size; ++i)
        diff |= (uint8_t)(state->transformed[i] ^ ctx->target[i]);
    return diff == 0;
}

__declspec(noinline) TRACE_STATUS ValidateCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const char* record) {
    if (!ctx || !state || !record || !ctx->target_size || ctx->target_size > 64u)
        return TRACE_MISMATCH;
    const uint8_t* payload = (const uint8_t*)record;
    size_t total = strlen(record);
    if (ctx->mode == 1u) {
        uint8_t prefix[15], suffix;
        BuildWrapper(prefix, &suffix);
        if (total != sizeof(prefix) + ctx->target_size + 1u ||
            memcmp(record, prefix, sizeof(prefix)) != 0 ||
            (uint8_t)record[total - 1u] != suffix) return TRACE_MISMATCH;
        payload += sizeof(prefix);
    } else if (ctx->mode != 2u || total != ctx->target_size) {
        return TRACE_MISMATCH;
    }
    DeriveTraceKey(ctx, state);
    TransformCandidate(ctx, state, payload, ctx->target_size);
    return CompareRecordDigest(ctx, state) ? TRACE_MATCH : TRACE_MISMATCH;
}

__declspec(noinline) TRACE_STATUS OpenLotRecord(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const char* record) {
    if (!ctx || !state || !record || !record[0]) return TRACE_NO_RECORD;
    uint32_t id;
    if (!ParseLotIdentifier(record, &id) || id != ctx->lot_id) return TRACE_NO_RECORD;
    LOT_RECORD lot;
    return ReadLotRecord(id, &lot) ? TRACE_MATCH : TRACE_NO_RECORD;
}
