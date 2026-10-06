#pragma once

#include "trace.hpp"

int LoadRecordTarget(TRACE_CONTEXT* ctx);
void DeriveTraceKey(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state);
void TransformCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const uint8_t* inner, uint32_t inner_len);
int CompareRecordDigest(const TRACE_CONTEXT* ctx, const VALIDATION_STATE* state);
TRACE_STATUS ValidateCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const char* record);
TRACE_STATUS OpenLotRecord(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const char* record);
