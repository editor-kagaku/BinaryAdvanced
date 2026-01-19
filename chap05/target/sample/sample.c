#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main() {
    char buf[256];

    printf("Enter the data: ");
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        printf("Failed to read input.\n");
        return 1;
    }

    if (buf[0] == 'A') {
        if (buf[1] == 'B') {
            if (buf[2] == 'C') {
                if (buf[3] == 'D') {
                    printf("crash1\n");
                    abort();
                }
            }
        }
    }

    if (!strcmp(buf + 1, "MAGICHDR")) {
        printf("crash2\n");
        abort();
    }
    if (*(uint32_t*)buf == 0xDEADBEEF) {
        printf("crash3\n");
        abort();
    }

    return 0;
}
