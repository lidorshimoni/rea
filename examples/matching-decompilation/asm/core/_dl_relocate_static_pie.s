# REA Matching Decompilation Slice: _dl_relocate_static_pie (function)
# Offset: 0x10f0 | Size: 5 bytes
.section .text.func__dl_relocate_static_pie, "ax", %progbits
.balign 1
.global _dl_relocate_static_pie
.type _dl_relocate_static_pie, %function
_dl_relocate_static_pie:
    .incbin "target.bin", 4336, 5
    .size _dl_relocate_static_pie, . - _dl_relocate_static_pie
