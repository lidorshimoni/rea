#include <stdint.h>

const uint32_t FIRMWARE_MAGIC = 0x52454131; // "REA1"
uint32_t g_counter = 0;

void increment_counter(uint32_t amount) {
    g_counter += amount;
}
