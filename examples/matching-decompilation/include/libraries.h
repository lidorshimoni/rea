#ifndef DECOMP_LIBRARIES_H
#define DECOMP_LIBRARIES_H

/* Statically linked third-party library detections */

/* Detected library: zlib (compression, confidence: 70%) */
#define HAVE_LIB_ZLIB 1
#define REA_LIBRARY_ZLIB 1
/* Matched functions: crc32, crc32_z, adler32, adler32_z */

/* Detected library: musl_glibc (libc, confidence: 70%) */
#define HAVE_LIB_MUSL_GLIBC 1
#define REA_LIBRARY_MUSL_GLIBC 1
/* Matched functions: strlen */

/* Detected library: cJSON (json, confidence: 70%) */
#define HAVE_LIB_CJSON 1
#define REA_LIBRARY_CJSON 1
/* Matched functions: cJSON_Parse */

/* Identified library symbols */
/* Symbol: crc32 -> zlib (90%) */
/* Symbol: crc32 -> zlib (95%) */
/* Symbol: crc32_z -> zlib (90%) */
/* Symbol: adler32 -> zlib (90%) */
/* Symbol: adler32_z -> zlib (90%) */
/* Symbol: strlen -> musl_glibc (90%) */
/* Symbol: cJSON_Parse -> cJSON (90%) */

#endif /* DECOMP_LIBRARIES_H */
