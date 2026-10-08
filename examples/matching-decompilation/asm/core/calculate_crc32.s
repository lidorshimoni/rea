# REA Matching Decompilation Slice: calculate_crc32 (function)
# Offset: 0x11c0 | Size: 100 bytes
.section .text.func_calculate_crc32, "ax", %progbits
.balign 1
.global calculate_crc32
.type calculate_crc32, %function
calculate_crc32:
    .incbin "target.bin", 4544, 100
    .size calculate_crc32, . - calculate_crc32
