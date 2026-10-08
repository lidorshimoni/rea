#include <stdint.h>
#include <stddef.h>

/**
 * @brief Computes a standard 32-bit CRC checksum over a byte buffer.
 *
 * @param buf Pointer to the byte array.
 * @param len Number of bytes to process.
 * @return Computed 32-bit CRC checksum.
 */
uint32_t calculate_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= buf[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

/**
 * @brief Advances a 64-bit monotonic sequence counter with wrap-around guard.
 *
 * @param seq Pointer to the 64-bit sequence counter.
 * @param step Value to advance by.
 * @return 0 on success.
 */
int advance_sequence(uint64_t *seq, uint32_t step) {
    if (!seq) return -1;
    uint64_t cur = *seq;
    if (cur > (UINT64_MAX - step)) {
        *seq = 0;
    } else {
        *seq = cur + step;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    uint8_t data[4] = { 0x01, 0x02, 0x03, 0x04 };
    uint32_t crc = calculate_crc32(data, 4);
    uint64_t seq = (uint64_t)argc;
    advance_sequence(&seq, crc & 0xFF);
    return (int)(seq & 0x7F);
}
