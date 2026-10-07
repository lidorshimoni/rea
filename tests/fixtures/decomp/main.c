#include <stdint.h>
#include <stddef.h>

uint32_t crc32(const uint8_t *data, size_t length);
int process_state(int state, int input);
void increment_counter(uint32_t amount);
extern uint32_t g_counter;
extern const uint32_t FIRMWARE_MAGIC;

int main(void) {
    const uint8_t msg[] = "test";
    uint32_t c = crc32(msg, 4);
    int s = process_state(2, (int)c);
    increment_counter((uint32_t)s);
    return (int)(g_counter ^ FIRMWARE_MAGIC);
}
