#include "types.h"
#include "macros.h"

/**
 * @file sequence.c
 * @brief Monotonic sequence allocator and state tracker.
 */

/**
 * @brief Safely increments a 64-bit sequence counter with wrap-around guard.
 *
 * @param[in,out] seq Pointer to 64-bit sequence value.
 * @param[in] step Value to add to sequence counter.
 * @return 0 on success, -1 if seq pointer is NULL.
 */
int advance_sequence(u64 *seq, u32 step) {
    if (!seq) {
        return -1;
    }
    u64 cur = *seq;
    if (cur > ((u64)-1 - step)) {
        *seq = 0;
    } else {
        *seq = cur + step;
    }
    return 0;
}
