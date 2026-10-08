/* REA Memory-Pinned Linker Script (Day 0 Link Invariant) */
SECTIONS
{
    . = 0x00400350;
    .target_all : {
        KEEP(*(.pad_000000 .pad_000000.* .pad_000000 .pad_000000.*))
        KEEP(*(.text.func_main .text.func_main.* .text.main .text.main.*))
        KEEP(*(.pad_0010bc .pad_0010bc.* .pad_0010bc .pad_0010bc.*))
        KEEP(*(.text.func__start .text.func__start.* .text._start .text._start.*))
        KEEP(*(.pad_0010e6 .pad_0010e6.* .pad_0010e6 .pad_0010e6.*))
        KEEP(*(.text.func__dl_relocate_static_pie .text.func__dl_relocate_static_pie.* .text._dl_relocate_static_pie .text._dl_relocate_static_pie.*))
        KEEP(*(.pad_0010f5 .pad_0010f5.* .pad_0010f5 .pad_0010f5.*))
        KEEP(*(.text.func_calculate_crc32 .text.func_calculate_crc32.* .text.calculate_crc32 .text.calculate_crc32.*))
        KEEP(*(.pad_001224 .pad_001224.* .pad_001224 .pad_001224.*))
        KEEP(*(.text.func_advance_sequence .text.func_advance_sequence.* .text.advance_sequence .text.advance_sequence.*))
        KEEP(*(.pad_tail_001253 .pad_tail_001253.* .pad_tail_001253 .pad_tail_001253.*))
    }
}
