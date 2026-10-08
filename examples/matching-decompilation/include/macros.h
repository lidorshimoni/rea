#ifndef DECOMP_MACROS_H
#define DECOMP_MACROS_H

/* Deterministically recovered magic constants and macros */

/* --- CRC_CRYPTO --- */
#define CRC32_POLYNOMIAL 0xedb88320 /* Standard IEEE 802.3 CRC32 polynomial (bit-reversed) */

/* --- MEMORY_PAGE --- */
#define PAGE_SIZE_4K 0x00001000 /* Standard 4KB architecture page size */
#define PAGE_MASK_4K 0xfffff000 /* Standard 4KB page alignment mask */
#define PAGE_SIZE_64K 0x00010000 /* 64KB memory boundary size */
#define PAGE_SIZE_2M 0x00200000 /* 2MB huge page size */

#endif /* DECOMP_MACROS_H */
