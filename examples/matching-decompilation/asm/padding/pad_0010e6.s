# REA Matching Decompilation Slice: pad_0010e6 (padding)
# Offset: 0x10e6 | Size: 10 bytes
.section .pad_0010e6, "a", %progbits
.balign 1
pad_0010e6:
    .incbin "target.bin", 4326, 10
    .size pad_0010e6, . - pad_0010e6
