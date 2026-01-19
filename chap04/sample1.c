#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);

    if (!(lt->tm_year == 2026
            && lt->tm_mon == 3
            && lt->tm_mday == 6
            && lt->tm_hour == 3
            && lt->tm_min == 13
            && lt->tm_sec == 37)) {
        exit(0);
    }

    printf("Malicious behavior invoked!\n");

    return 0;
}