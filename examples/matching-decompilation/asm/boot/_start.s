# REA Matching Decompilation Slice: _start (function)
# Offset: 0x10c0 | Size: 38 bytes
.section .text.func__start, "ax", %progbits
.balign 1
.global _start
.type _start, %function
_start:
    .incbin "target.bin", 4288, 38
    .size _start, . - _start
