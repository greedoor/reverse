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

__declspec(noinline) void DeriveTraceKey(TRACE_CONTEXT* ctx, VALIDATION_STATE* state) {
    if (!ctx || !state) return;
    state->state = ctx->seed;
    for (uint32_t i = 0; i < 8; ++i) {
        state->state = state->state * 1103515245u + 12345u;
        state->working_key[i] = (uint8_t)((state->state >> 16) & 0xffu);
    }
}

__declspec(noinline) void TransformCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const uint8_t* inner, uint32_t inner_len) {
    if (!ctx || !state || !inner || inner_len > sizeof(state->transformed)) return;
    for (uint32_t i = 0; i < inner_len; ++i)
        state->transformed[i] = (uint8_t)(inner[i] ^ state->working_key[i & 7u]);

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
        for (uint32_t i = 0; i < n; ++i) state->transformed[base + i] = rol8v(tmp[i], (i % 5u) + 1u);
    }
}

__declspec(noinline) int CompareRecordDigest(const uint8_t* left, const uint8_t* right, uint32_t size) {
    uint8_t diff = 0;
    for (uint32_t i = 0; i < size; ++i) diff |= (uint8_t)(left[i] ^ right[i]);
    return diff == 0;
}

__declspec(noinline) int ValidateCandidate(const char* candidate) {
    uint8_t prefix[15], suffix;
    BuildWrapper(prefix, &suffix);
    if (!candidate) return 0;
    if (memcmp(candidate, prefix, sizeof(prefix)) != 0) return 0;

    uint32_t total = (uint32_t)strlen(candidate);
    if (total != sizeof(prefix) + kExpectedInnerLength + 1u) return 0;
    if ((uint8_t)candidate[total - 1u] != suffix) return 0;

    TRACE_CONTEXT ctx;
    VALIDATION_STATE state;
    ClearWorkBuffer(&ctx, sizeof(ctx));
    ClearWorkBuffer(&state, sizeof(state));
    ctx.seed = kTraceSeed;
    memcpy(ctx.permutation, kPermutation, sizeof(ctx.permutation));
    DeriveTraceKey(&ctx, &state);
    TransformCandidate(&ctx, &state, (const uint8_t*)candidate + sizeof(prefix), kExpectedInnerLength);
    return CompareRecordDigest(state.transformed, kExpectedTransformed, kExpectedInnerLength);
}
