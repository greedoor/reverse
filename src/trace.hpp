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

enum TRACE_STATUS {
    TRACE_SILENT = 0,
    TRACE_NO_RECORD = 0x10,
    TRACE_MISMATCH = 0x23,
    TRACE_MATCH = 0x37,
    TRACE_OPENED = 0x48,
    TRACE_READY = 0x59
};

struct TRACE_PROFILE {
    uint32_t mode;
    uint32_t seed_bias;
    uint32_t target_size;
    uint32_t key_phase;
    uint32_t rotation_period;
    uint8_t permutation[16];
};

struct TRACE_CONTEXT {
    uint32_t seed;
    uint32_t lot_id;
    uint32_t key_state;
    uint32_t mode;
    uint32_t target_size;
    uint32_t key_phase;
    uint32_t rotation_period;
    uint8_t permutation[16];
    uint8_t target[64];
    TRACE_STATUS last_status;
    uint32_t flags;
};

struct VALIDATION_STATE {
    uint32_t state;
    uint32_t payload_size;
    uint8_t working_key[8];
    uint8_t transformed[64];
};

typedef TRACE_STATUS (*TRACE_HANDLER)(const TRACE_CONTEXT*, VALIDATION_STATE*, const char*);

struct TRACE_DISPATCH {
    uint32_t mode;
    TRACE_HANDLER handler;
    TRACE_STATUS accepted_status;
};

void InitializeTraceEngine(TRACE_CONTEXT* ctx);
void ResetTraceState(TRACE_CONTEXT* ctx);
int LoadTraceHeader(const TRACE_BLOCK* block);
int ReadLotRecord(uint32_t lot_id, LOT_RECORD* record);
int ParseLotIdentifier(const char* text, uint32_t* lot_id);
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
int LoadTraceProfile(const LOT_RECORD* record, TRACE_PROFILE* profile);
void BindTraceProfile(TRACE_CONTEXT* ctx, const LOT_RECORD* record, const TRACE_PROFILE* profile);
const TRACE_DISPATCH* ResolveTraceOperation(const TRACE_CONTEXT* ctx);
TRACE_STATUS ApplyTraceHandler(const TRACE_DISPATCH* operation, const TRACE_CONTEXT* ctx,
                              VALIDATION_STATE* state, const char* record);
TRACE_STATUS ProcessTraceRecord(TRACE_CONTEXT* ctx, const char* record);
TRACE_STATUS RecordTraceResult(TRACE_CONTEXT* ctx, TRACE_STATUS status);
void RenderTraceStatus(TRACE_STATUS status);
