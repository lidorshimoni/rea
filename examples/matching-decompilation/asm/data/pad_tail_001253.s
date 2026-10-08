# REA Matching Decompilation Slice: pad_tail_001253 (data)
# Offset: 0x1253 | Size: 11261 bytes
.section .pad_tail_001253, "a", %progbits
.balign 1
pad_tail_001253:
    .incbin "target.bin", 4691, 11261
    .size pad_tail_001253, . - pad_tail_001253
