# REA Matching Decompilation Slice: pad_001224 (padding)
# Offset: 0x1224 | Size: 12 bytes
.section .pad_001224, "a", %progbits
.balign 1
pad_001224:
    .incbin "target.bin", 4644, 12
    .size pad_001224, . - pad_001224
