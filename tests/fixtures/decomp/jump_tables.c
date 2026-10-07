#include <stdint.h>

int process_state(int state, int input) {
    switch (state) {
        case 0: return input * 2;
        case 1: return input + 10;
        case 2: return input - 5;
        case 3: return input ^ 0x55;
        case 4: return input / 3;
        case 5: return (input << 2) + 1;
        default: return -1;
    }
}
