/**
 * Curated in-tree database of third-party library signatures for offline matching decompilation.
 * Covers musl/glibc, zlib, OpenSSL, mbedtls, FreeRTOS, cJSON, and SQLite.
 */

export interface LibrarySignatureFunction {
  readonly name: string;
  readonly opcodePattern?: string;
  readonly distinctiveConstants?: readonly number[];
  readonly minimumSize?: number;
}

export interface LibrarySignatureEntry {
  readonly library: string;
  readonly category:
    | "libc"
    | "compression"
    | "crypto"
    | "rtos"
    | "json"
    | "database";
  readonly versionPattern?: string;
  readonly functions: readonly LibrarySignatureFunction[];
  readonly strings: readonly string[];
}

export const DEFAULT_LIBRARY_SIGNATURES: readonly LibrarySignatureEntry[] = [
  {
    library: "zlib",
    category: "compression",
    versionPattern: "1\\.2\\.[0-9]+",
    functions: [
      {
        name: "crc32",
        opcodePattern: "55 48 89 e5",
        distinctiveConstants: [0xedb88320, 0x04c11db7],
        minimumSize: 32,
      },
      {
        name: "crc32_z",
        opcodePattern: "55 48 89 e5",
        distinctiveConstants: [0xedb88320],
        minimumSize: 32,
      },
      {
        name: "adler32",
        opcodePattern: "55 48 89 e5",
        distinctiveConstants: [65521],
        minimumSize: 24,
      },
      {
        name: "adler32_z",
        opcodePattern: "55 48 89 e5",
        distinctiveConstants: [65521],
        minimumSize: 24,
      },
      {
        name: "deflate",
        minimumSize: 64,
      },
      {
        name: "inflate",
        minimumSize: 64,
      },
      {
        name: "zlibVersion",
        minimumSize: 8,
      },
    ],
    strings: [
      "deflate 1.",
      "inflate 1.",
      "need dictionary",
      "stream end",
      "file error",
      "stream error",
      "data error",
      "insufficient memory",
      "buffer error",
      "incompatible version",
    ],
  },
  {
    library: "musl_glibc",
    category: "libc",
    versionPattern: "(GNU C|musl libc)",
    functions: [
      { name: "printf", minimumSize: 16 },
      { name: "sprintf", minimumSize: 16 },
      { name: "snprintf", minimumSize: 20 },
      { name: "puts", minimumSize: 8 },
      { name: "strlen", opcodePattern: "55 48 89 e5", minimumSize: 8 },
      { name: "strcmp", minimumSize: 12 },
      { name: "strncmp", minimumSize: 16 },
      { name: "memcpy", minimumSize: 12 },
      { name: "memset", minimumSize: 10 },
      { name: "memmove", minimumSize: 16 },
      { name: "malloc", minimumSize: 24 },
      { name: "free", minimumSize: 16 },
      { name: "abort", minimumSize: 8 },
      { name: "exit", minimumSize: 8 },
      { name: "atoi", minimumSize: 12 },
    ],
    strings: [
      "Assertion failed: ",
      "GNU C",
      "musl libc",
      "out of memory",
      "invalid argument",
    ],
  },
  {
    library: "openssl",
    category: "crypto",
    versionPattern: "OpenSSL [0-9]+\\.[0-9]+",
    functions: [
      {
        name: "SHA256_Init",
        distinctiveConstants: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
        minimumSize: 32,
      },
      {
        name: "SHA256_Update",
        minimumSize: 48,
      },
      {
        name: "SHA256_Final",
        minimumSize: 48,
      },
      {
        name: "AES_set_encrypt_key",
        minimumSize: 64,
      },
      {
        name: "AES_encrypt",
        minimumSize: 64,
      },
    ],
    strings: ["OpenSSL", "SHA256", "AES-", "crypto/sha", "crypto/aes"],
  },
  {
    library: "mbedtls",
    category: "crypto",
    versionPattern: "mbed TLS [0-9]+\\.[0-9]+",
    functions: [
      {
        name: "mbedtls_sha256_starts",
        distinctiveConstants: [0x6a09e667, 0xbb67ae85],
        minimumSize: 32,
      },
      {
        name: "mbedtls_sha256_update",
        minimumSize: 48,
      },
      {
        name: "mbedtls_sha256_finish",
        minimumSize: 48,
      },
      {
        name: "mbedtls_aes_setkey_enc",
        minimumSize: 48,
      },
    ],
    strings: ["mbed TLS", "mbedtls_", "POLARSSL_"],
  },
  {
    library: "cJSON",
    category: "json",
    versionPattern: "cJSON",
    functions: [
      { name: "cJSON_Parse", opcodePattern: "55 48 89 e5", minimumSize: 32 },
      { name: "cJSON_Print", minimumSize: 32 },
      { name: "cJSON_Delete", minimumSize: 16 },
      { name: "cJSON_CreateObject", minimumSize: 16 },
      { name: "cJSON_AddItemToArray", minimumSize: 16 },
    ],
    strings: ["cJSON", "true", "false", "null", '"format":'],
  },
  {
    library: "sqlite",
    category: "database",
    versionPattern: "3\\.[0-9]+\\.[0-9]+",
    functions: [
      { name: "sqlite3_open", minimumSize: 32 },
      { name: "sqlite3_close", minimumSize: 24 },
      { name: "sqlite3_exec", minimumSize: 48 },
      { name: "sqlite3_prepare_v2", minimumSize: 40 },
      { name: "sqlite3_step", minimumSize: 48 },
      { name: "sqlite3_finalize", minimumSize: 20 },
    ],
    strings: [
      "SQLite format 3",
      "not authorized",
      "table %s may not be dropped",
      "syntax error",
      "cannot commit",
    ],
  },
  {
    library: "freertos",
    category: "rtos",
    versionPattern: "FreeRTOS V[0-9]+",
    functions: [
      { name: "vTaskStartScheduler", minimumSize: 32 },
      { name: "xTaskCreate", minimumSize: 48 },
      { name: "vTaskDelay", opcodePattern: "?? b5 ?? af", minimumSize: 16 },
      { name: "xQueueGenericCreate", minimumSize: 32 },
      { name: "vTaskSuspend", minimumSize: 20 },
    ],
    strings: ["FreeRTOS", "Task", "Queue", "vTaskSwitchContext"],
  },
];
