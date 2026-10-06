#pragma once

#include <stdint.h>

struct TRACE_BLOCK {
    uint16_t marker;
    uint16_t flags;
    uint32_t encoded_sequence;
    uint32_t stored_size;
    uint32_t decoded_size;
    uint32_t checksum;
    uint32_t set_tag;
    uint8_t pdb_guid[16];
    uint32_t pdb_age;
    uint32_t pdb_size;
};

struct LOT_RECORD {
    uint32_t lot_id;
    uint32_t relay_id;
    uint8_t digest[32];
    char status[12];
};

struct TRACE_CONTEXT {
    uint32_t seed;
    uint8_t key[8];
    uint8_t expected_digest[32];
    uint8_t permutation[16];
    uint32_t flags;
};

struct VALIDATION_STATE {
    uint32_t state;
    uint8_t working_key[8];
    uint8_t transformed[64];
};

void InitializeTraceEngine(TRACE_CONTEXT* ctx);
void ResetTraceState(TRACE_CONTEXT* ctx);
int LoadTraceHeader(const TRACE_BLOCK* block);
int ReadLotRecord(uint32_t lot_id, LOT_RECORD* record);
int ParseTraceBlock(const uint8_t* raw, uint32_t raw_size, TRACE_BLOCK* out);
int NormalizeTraceBlock(TRACE_BLOCK* block);
uint32_t DecodeTraceSequence(uint32_t encoded_sequence);
uint32_t CalculateRecordCRC(const uint8_t* data, uint32_t size);
int RestoreDebugBlock(const TRACE_BLOCK* block, const uint8_t* stored, uint8_t* out, uint32_t out_size);
int VerifyTraceBlock(const TRACE_BLOCK* block, const uint8_t* decoded);
void PrepareTraceContext(TRACE_CONTEXT* ctx);
int DecodeLotRecord(const LOT_RECORD* in, LOT_RECORD* out);
void FormatDiagnosticLine(char* out, uint32_t out_size, const char* key, const char* value);
void ClearWorkBuffer(void* ptr, uint32_t size);
int LoadTraceContext(TRACE_CONTEXT* ctx);
int OpenRelayRecord(uint32_t relay_id, LOT_RECORD* out);
