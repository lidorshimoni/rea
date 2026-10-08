# REA Matching Decompilation Slice: pad_000000 (padding)
# Offset: 0x0 | Size: 4192 bytes
.section .pad_000000, "a", %progbits
.balign 1
pad_000000:
    .incbin "target.bin", 0, 4192
    .size pad_000000, . - pad_000000
