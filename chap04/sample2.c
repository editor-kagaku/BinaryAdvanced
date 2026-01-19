#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define STACK_SIZE 32
#define MEM_SIZE 256

#define SYSCALL_PRINT        0x01
#define SYSCALL_TIME         0x10
#define SYSCALL_LOCALTIME    0x11
#define SYSCALL_PRINT_SECRET 0x12

uint8_t bytecode[] = {
    0x0C, 0x10,            // SYSCALL time(NULL) → mem[0x40]
    0x0C, 0x11,            // SYSCALL localtime → mem[0x50]
    0x0B, 0x50,            // LOADM mem[0x50]     ; tm_sec
    0x04, 37,              // CMP 37
    0x05, 11,              // JZ next
    0xFF,                  // HALT

    0x0B, 0x54,            // tm_min
    0x04, 13,
    0x05, 18,
    0xFF,

    0x0B, 0x58,            // tm_hour
    0x04, 3,
    0x05, 25,
    0xFF,

    0x0B, 0x5C,            // tm_mday
    0x04, 6,
    0x05, 32,
    0xFF,

    0x0B, 0x60,            // tm_mon
    0x04, 3,
    0x05, 39,
    0xFF,

    0x0B, 0x64,            // tm_year (1st byte)
    0x04, 234,             // 0xEA (2026 = 0x7EA)
    0x05, 46,
    0xFF,

    0x0B, 0x65,            // tm_year (2nd byte)
    0x04, 7,               // 0x7 (2026 = 0x7EA)
    0x05, 53,
    0xFF,

    0x0C, 0x12,            // SYSCALL print secret
    0xFF                   // HALT
};

void vm() {
    uint8_t pc = 0;
    uint8_t acc = 0;
    uint8_t flag = 0;
    uint8_t sp = 0;
    uint8_t stack[STACK_SIZE] = {0};
    uint8_t mem[MEM_SIZE] = {0};

    while (1) {
        uint8_t opcode = bytecode[pc++];
        switch (opcode) {
            case 0x01: acc = bytecode[pc++]; break;
            case 0x02: acc += bytecode[pc++]; break;
            case 0x03: printf("ACC = %d\n", acc); break;
            case 0x04: flag = (acc == bytecode[pc++]); break;
            case 0x05: { uint8_t addr = bytecode[pc++]; if (flag) pc = addr; break; }
            case 0x06: pc = bytecode[pc++]; break;
            case 0x07: if (sp < STACK_SIZE) stack[sp++] = acc; break;
            case 0x08: if (sp > 0) acc = stack[--sp]; break;
            case 0x09: acc ^= bytecode[pc++]; break;
            case 0x0A: mem[bytecode[pc++]] = acc; break;
            case 0x0B: acc = mem[bytecode[pc++]]; break;
            case 0x0C: {
                uint8_t id = bytecode[pc++];
                if (id == SYSCALL_PRINT) {
                    printf("[SYSCALL] acc = %d\n", acc);
                } else if (id == SYSCALL_TIME) {
                    time_t t = time(NULL);
                    memcpy(&mem[0x40], &t, sizeof(time_t));
                } else if (id == SYSCALL_LOCALTIME) {
                    time_t t;
                    memcpy(&t, &mem[0x40], sizeof(time_t));
                    struct tm *lt = localtime(&t);
                    if (lt) memcpy(&mem[0x50], lt, sizeof(struct tm));
                } else if (id == SYSCALL_PRINT_SECRET) {
                    printf("Malicious behavior invoked!\n");
                } else {
                    printf("[SYSCALL] unknown id: 0x%02X\n", id);
                }
                break;
            }
            case 0xFF: exit(0);
            default:
                printf("Invalid opcode: 0x%02X\n", opcode);
                return;
        }
    }
}

int main() {
    vm();
    return 0;
}

