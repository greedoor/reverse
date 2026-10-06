#include "trace.hpp"
#include "validation.hpp"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void Banner(void) {
    puts("================================================");
    puts("RAVEN'S HORDE TRACE UTILITY v1.3");
    puts("(c) 1992 Black Feather Systems");
    puts("INTERNAL SERVICE COPY");
    puts("================================================");
    puts("");
    puts("TRACE DEVICE : READY");
    puts("DEBUG SET    : INCOMPLETE");
    puts("MODE         : LOCAL");
    puts("");
}

static void Help(void) {
    puts("HELP");
    puts("INFO");
    puts("TRACE <ID>");
    puts("CHECK <CODE>");
    puts("QUIT");
}

static void Info(void) {
    puts("TRACE ENGINE : ACTIVE");
    puts("DEBUG SET    : MISMATCH");
    puts("LOT CACHE    : READY");
    puts("SYMBOL SET   : NO RECORD");
}

static void Trace(const char* id) {
    LOT_RECORD rec;
    uint32_t lot = id ? (uint32_t)strtoul(id, 0, 16) : 0;
    if (!ReadLotRecord(lot, &rec)) {
        puts("ERR: TRACE RECORD INVALID");
        return;
    }
    printf("LOT %08lX : SEALED\n", (unsigned long)rec.lot_id);
    puts("RELAY      : MASKED");
    puts("DEBUG SET  : MISMATCH");
}

static void Check(const char* code) {
    if (ValidateCandidate(code)) {
        puts("TRACE RECORD VERIFIED");
        puts("DEBUG SET    : ACCEPTED");
    } else {
        puts("ERR: DEBUG SET MISMATCH");
    }
}

int main(int argc, char** argv) {
    char line[256];
    TRACE_CONTEXT ctx;
    InitializeTraceEngine(&ctx);

    if (argc == 3 && strcmp(argv[1], "--check") == 0) {
        Check(argv[2]);
        return ValidateCandidate(argv[2]) ? 0 : 1;
    }

    Banner();
    for (;;) {
        fputs("> ", stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\r\n")] = 0;
        if (_stricmp(line, "HELP") == 0) Help();
        else if (_stricmp(line, "INFO") == 0) Info();
        else if (_strnicmp(line, "TRACE ", 6) == 0) Trace(line + 6);
        else if (_strnicmp(line, "CHECK ", 6) == 0) Check(line + 6);
        else if (_stricmp(line, "QUIT") == 0) break;
        else if (line[0]) puts("ERR: NO RECORD");
    }
    ClearWorkBuffer(&ctx, sizeof(ctx));
    return 0;
}
