#include "trace.hpp"

#include <stdio.h>
#include <string.h>

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
    puts("OPEN <RECORD>");
    puts("QUIT");
}

static void Info(void) {
    puts("TRACE ENGINE : ACTIVE");
    puts("DEBUG SET    : MISMATCH");
    puts("LOT CACHE    : READY");
    puts("SYMBOL SET   : NO RECORD");
}

static TRACE_STATUS Trace(TRACE_CONTEXT* ctx, const char* id) {
    LOT_RECORD rec;
    uint32_t lot;
    if (!ParseLotIdentifier(id, &lot)) return TRACE_NO_RECORD;
    if (!ReadLotRecord(lot, &rec)) {
        return TRACE_NO_RECORD;
    }
    ctx->lot_id = lot;
    if (!LoadTraceContext(ctx)) return TRACE_NO_RECORD;
    printf("LOT %08lX : SEALED\n", (unsigned long)rec.lot_id);
    puts("RELAY      : MASKED");
    puts("DEBUG SET  : MISMATCH");
    return TRACE_SILENT;
}

__declspec(noinline) TRACE_STATUS DispatchTraceCommand(TRACE_CONTEXT* ctx, const char* line) {
    if (_stricmp(line, "HELP") == 0) Help();
    else if (_stricmp(line, "INFO") == 0) Info();
    else if (_strnicmp(line, "TRACE ", 6) == 0) return Trace(ctx, line + 6);
    else if (_strnicmp(line, "OPEN ", 5) == 0) return ProcessTraceRecord(ctx, line + 5);
    else if (line[0]) return TRACE_NO_RECORD;
    return TRACE_SILENT;
}

int main(void) {
    char line[256];
    TRACE_CONTEXT ctx;
    InitializeTraceEngine(&ctx);

    Banner();
    for (;;) {
        fputs("> ", stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        if (!strchr(line, '\n') && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            RenderTraceStatus(TRACE_NO_RECORD);
            continue;
        }
        line[strcspn(line, "\r\n")] = 0;
        if (_stricmp(line, "QUIT") == 0) break;
        RenderTraceStatus(DispatchTraceCommand(&ctx, line));
    }
    ClearWorkBuffer(&ctx, sizeof(ctx));
    return 0;
}
