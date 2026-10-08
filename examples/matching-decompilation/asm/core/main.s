# REA Matching Decompilation Slice: main (function)
# Offset: 0x1060 | Size: 92 bytes
.section .text.func_main, "ax", %progbits
.balign 1
.global main
.type main, %function
main:
    .incbin "target.bin", 4192, 92
    .size main, . - main
