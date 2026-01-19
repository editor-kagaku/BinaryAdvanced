#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define H 10
#define W 10

char maze[H][W] = {
    "##########",
    "#S #    G#",
    "# ### ####",
    "# #      #",
    "# ###### #",
    "# # # ## #",
    "#     #  #",
    "##### ## #",
    "#        #",
    "##########"
};

bool isValidInput(const char *input, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (input[i] != 'w' && input[i] != 's' && input[i] != 'a' && input[i] != 'd') {
            return false;
        }
    }
    return true;
}

void run(const char *input, size_t length) {
    int x = 1, y = 1;
    for (size_t i = 0; i < length; i++) {
        int nx = x, ny = y;
        switch (input[i]) {
            case 'w': ny--; break;
            case 's': ny++; break;
            case 'a': nx--; break;
            case 'd': nx++; break;
        }

        if (maze[ny][nx] == 'G') {
            printf("Congratulations! You've reached the goal!\n");
            abort();
        }

        if (maze[ny][nx] != '#') {
            x = nx, y = ny;
        }
    }
    printf("You haven't reached the goal yet. Pos is (%d, %d)\n", y, x);
    __afl_coverage_interesting(1, (y << 4) | x);  // アノテーション追加
}

int main() {
    char buf[256];
    size_t read_length;

    printf("Enter the data (w: up, s: down, a: left, d: right): ");
    read_length = fread(buf, 1, sizeof(buf), stdin);

    if (read_length == 0) {
        printf("Failed to read input.\n");
        return 1;
    }

    if (!isValidInput(buf, read_length)) {
        printf("Invalid input.\n");
        return 1;
    }

    run(buf, read_length);

    return 0;
}
