#include "trace.hpp"
#include "validation.hpp"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char* record = getenv("TEST_RECORD");
    assert(record);
    TRACE_CONTEXT ctx;
    InitializeTraceEngine(&ctx);
    assert(ctx.mode == 1u && ctx.key_state == ctx.seed);
    assert(ProcessTraceRecord(&ctx, record) == TRACE_OPENED);
    assert(ctx.last_status == TRACE_OPENED && (ctx.flags & 1u));

    VALIDATION_STATE state = {};
    TRACE_CONTEXT empty = {};
    assert(ValidateCandidate(&empty, &state, record) == TRACE_MISMATCH);
    for (unsigned field = 0; field < 5; ++field) {
        TRACE_CONTEXT changed = ctx;
        if (field == 0) changed.key_state ^= 1u;
        if (field == 1) changed.key_phase = 1u;
        if (field == 2) changed.rotation_period = ctx.target_size > 1u ? 1u : 0u;
        if (field == 3) changed.target[0] ^= 1u;
        if (field == 4) changed.target_size = 65u;
        assert(ProcessTraceRecord(&changed, record) == TRACE_MISMATCH);
    }
    if (ctx.target_size > 1u) {
        TRACE_CONTEXT changed = ctx;
        uint8_t first = changed.permutation[0];
        memmove(changed.permutation, changed.permutation + 1, 15);
        changed.permutation[15] = first;
        assert(ProcessTraceRecord(&changed, record) == TRACE_MISMATCH);
    }
    char wrong[96];
    strcpy(wrong, record);
    wrong[15] ^= 1u;
    assert(ProcessTraceRecord(&ctx, wrong) == TRACE_MISMATCH);
    const char* short_records[] = {"", "S", "Securinets_fst{", "{}"};
    for (const char* short_record : short_records)
        assert(ProcessTraceRecord(&ctx, short_record) == TRACE_MISMATCH);

    ctx.lot_id = 0x0715u;
    assert(LoadTraceContext(&ctx));
    assert(ProcessTraceRecord(&ctx, record) == TRACE_MISMATCH);
    ctx.lot_id = 0x0712u;
    assert(LoadTraceContext(&ctx));
    assert(ProcessTraceRecord(&ctx, "LOCAL") == TRACE_READY);
    assert(ProcessTraceRecord(&ctx, record) == TRACE_MISMATCH);
    ctx.lot_id = 0x0710u;
    assert(LoadTraceContext(&ctx));
    assert(ProcessTraceRecord(&ctx, "0710") == TRACE_OPENED);
    assert(ProcessTraceRecord(&ctx, "-0") == TRACE_NO_RECORD);
    assert(ProcessTraceRecord(&ctx, "0711") == TRACE_NO_RECORD);
    ctx.lot_id = 0x0713u;
    assert(LoadTraceContext(&ctx));
    assert(ProcessTraceRecord(&ctx, record) == TRACE_NO_RECORD);
    ctx.lot_id = 0x0711u;
    assert(LoadTraceContext(&ctx));
    assert(ProcessTraceRecord(&ctx, record) == TRACE_OPENED);
}
