#pragma once

#include "trace.hpp"

void DeriveTraceKey(TRACE_CONTEXT* ctx, VALIDATION_STATE* state);
void TransformCandidate(const TRACE_CONTEXT* ctx, VALIDATION_STATE* state, const uint8_t* inner, uint32_t inner_len);
int CompareRecordDigest(const uint8_t* left, const uint8_t* right, uint32_t size);
int ValidateCandidate(const char* candidate);
