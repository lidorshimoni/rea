# REA Matching Decompilation Slice: pad_0010bc (padding)
# Offset: 0x10bc | Size: 4 bytes
.section .pad_0010bc, "a", %progbits
.balign 1
pad_0010bc:
    .incbin "target.bin", 4284, 4
    .size pad_0010bc, . - pad_0010bc
