#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint16_t crc16(char *input, int len) {
    uint16_t crc = 0;
    uint16_t polynomial = 0x8005;

    for (int i = 0; i < len; i++) {
        crc ^= (uint16_t)(input[i] & 0xFF) << 8;
        for (int j = 0; j < 8; j++) {
            if ((crc & 0x8000) != 0) {
                crc = (crc << 1) ^ polynomial;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

uint16_t get_checksum(char *input, int len) {
    uint16_t checksum;
    checksum  = ((uint16_t)(input[len - 2] & 0xFF) << 8);
    checksum |=  (uint16_t)(input[len - 1] & 0xFF);
    return checksum;
}

int main() {
    char input[256];
    size_t len;

    printf("Enter the data: ");
    len = fread(input, 1, sizeof(input), stdin);

    if (len < 3) {
        printf("Data too short to contain a valid checksum.\n");
        return 1;
    }

    uint16_t recomputed_chksum = crc16(input, len - 2);
    uint16_t chksum_in_file = get_checksum(input, len);

    if (chksum_in_file != recomputed_chksum) {
        printf("Checksum mismatch.\n");
        return 1;
    }

    if (input[0] == 'A') {
        if (input[1] == 'B') {
            printf("Trigger bug.\n");
            abort();
        }
    }

    return 0;
}
