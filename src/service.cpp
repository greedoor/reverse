#include <stdio.h>

struct SERVICE_RECORD {
    unsigned long serial;
    unsigned long stamp;
    char note[16];
};

__declspec(noinline) static void ReadServiceStamp(SERVICE_RECORD* rec) {
    rec->serial = 0x53455256ul;
    rec->stamp = 0x19920711ul;
    rec->note[0] = 'O';
    rec->note[1] = 'L';
    rec->note[2] = 'D';
    rec->note[3] = 0;
}

int main(void) {
    SERVICE_RECORD rec;
    ReadServiceStamp(&rec);
    puts("TRACE SERVICE PROBE");
    return 0;
}
