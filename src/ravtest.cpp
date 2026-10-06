#include <stdio.h>

struct RAVTEST_RECORD {
    unsigned long serial;
    unsigned long stamp;
    char note[16];
};

__declspec(noinline) static void RavtestProbe(RAVTEST_RECORD* rec) {
    rec->serial = 0x54455354ul;
    rec->stamp = 0x19920711ul;
    rec->note[0] = 'O';
    rec->note[1] = 'L';
    rec->note[2] = 'D';
    rec->note[3] = 0;
}

int main(void) {
    RAVTEST_RECORD rec;
    RavtestProbe(&rec);
    puts("RAVTEST SERVICE PROBE");
    return 0;
}
