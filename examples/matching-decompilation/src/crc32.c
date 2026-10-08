#include "types.h"
#include "macros.h"

/**
 * @file crc32.c
 * @brief Standard 32-bit CRC calculation routine.
 */

/**
 * @brief Computes a standard 32-bit CRC checksum over a byte buffer.
 *
 * Implements standard reversed polynomial bitwise CRC32 calculation.
 *
 * @param[in] buf Pointer to input byte array.
 * @param[in] len Length of input buffer in bytes.
 * @return Inverted 32-bit CRC checksum.
 */
u32 calculate_crc32(const u8 *buf, size_t len) {
u32 crc = CRC32_INIT_VAL;
    /* Algorithmic intent: iterative block processing loop */
    for (size_t i = 0; i < len; ++i) {
    /* Algorithmic intent: bitwise polynomial reduction / XOR state update */
        crc ^= buf[i];
    /* Algorithmic intent: iterative block processing loop */
        for (int j = 0; j < 8; ++j) {
    /* Algorithmic intent: bitwise polynomial reduction / XOR state update */
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL_LE & -(crc & 1));
        }
    }
    return ~crc;
}
