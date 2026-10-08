# REA Matching Decompilation Slice: pad_0010f5 (padding)
# Offset: 0x10f5 | Size: 203 bytes
.section .pad_0010f5, "a", %progbits
.balign 1
pad_0010f5:
    .incbin "target.bin", 4341, 203
    .size pad_0010f5, . - pad_0010f5
