import { describe, expect, it } from "vitest";
import {
  decompBinaryFingerprintSchema,
  decompProjectConfigSchema,
  decompDiffResultSchema,
  decompSliceSchema,
  decompSliceManifestSchema,
  decompBuildResultSchema,
  decompPermuteResultSchema,
  decompSyncObligationsResultSchema,
  decompInputSchemas,
  decompResultSchemas,
  decompRequestSchema,
} from "./decompilationAnalysis.js";

describe("decompilationAnalysis schemas", () => {
  it("validates decompBinaryFingerprintSchema", () => {
    const valid = {
      format: "ARM_CORTEX_M_RAW" as const,
      architecture: "arm-thumb" as const,
      bits: 32 as const,
      endianness: "little" as const,
      image_base: "0x08000000",
      entry_point: "0x08000101",
      flash_base: "0x08000000",
      sram_base: "0x20000000",
      initial_sp: "0x20010000",
      recommended_toolchain: "arm-none-eabi-gcc",
      sections: [
        {
          name: ".vector_table",
          virtual_address: "0x08000000",
          virtual_size: 1024,
          raw_size: 1024,
          flags: "rx",
        },
      ],
      feasible_1to1_match: true,
    };
    expect(decompBinaryFingerprintSchema.safeParse(valid).success).toBe(true);

    const invalid = { ...valid, bits: 16 };
    expect(decompBinaryFingerprintSchema.safeParse(invalid).success).toBe(
      false,
    );
  });

  it("validates decompProjectConfigSchema", () => {
    const config = {
      schema_version: 1 as const,
      name: "firmware",
      target: {
        path: "firmware.bin",
        sha256:
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        format: "ARM_CORTEX_M_RAW",
        architecture: "arm-thumb",
        endianness: "little" as const,
        image_base: "0x08000000",
      },
      toolchain: {
        compiler: "arm-none-eabi-gcc",
        version: "10.3.1",
        flags: ["-mcpu=cortex-m4", "-mthumb", "-O2"],
        include_paths: ["include"],
      },
      splicing: {
        day0_mode: "progressive_assembly" as const,
        asm_directory: "asm",
        src_directory: "src",
        expected_directory: "expected",
        build_directory: "build",
      },
    };
    expect(decompProjectConfigSchema.safeParse(config).success).toBe(true);
  });

  it("validates decompSliceManifestSchema", () => {
    const manifest = {
      target_sha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      total_slices: 2,
      linker_script_path: "linker.ld",
      slices: [
        {
          id: "slice_0001",
          name: "Reset_Handler",
          type: "function" as const,
          offset: 0,
          size: 64,
          address: "0x08000100",
          asm_file: "asm/core/Reset_Handler.s",
          status: "spliced" as const,
        },
        {
          id: "slice_0002",
          name: "pool_0001",
          type: "literal_pool" as const,
          offset: 64,
          size: 16,
          address: "0x08000140",
          asm_file: "asm/data/pool_0001.s",
          status: "spliced" as const,
        },
      ],
    };
    expect(decompSliceManifestSchema.safeParse(manifest).success).toBe(true);
  });

  it("validates decompDiffResultSchema", () => {
    const diff = {
      unit: "src/core/crc32.c",
      symbol: "crc32",
      status: "matched" as const,
      match_percent: 100,
      similarity: 1.0,
      total_bytes: 96,
      matched_bytes: 96,
      sample_mismatches: [],
    };
    expect(decompDiffResultSchema.safeParse(diff).success).toBe(true);

    const mismatched = {
      ...diff,
      status: "different" as const,
      match_percent: 85.5,
      similarity: 0.855,
      matched_bytes: 82,
      sample_mismatches: [
        {
          offset: "0x0014",
          expected_byte: "48",
          compiled_byte: "49",
        },
      ],
    };
    expect(decompDiffResultSchema.safeParse(mismatched).success).toBe(true);
  });

  it("validates decompSyncObligationsResultSchema", () => {
    const sync = {
      verified_symbols: ["crc32", "Reset_Handler"],
      total_obligations: 2,
      ledger_closed: true,
      closure_digest: "a".repeat(64),
    };
    expect(decompSyncObligationsResultSchema.safeParse(sync).success).toBe(
      true,
    );
  });

  it("validates decompRequestSchema discriminated union", () => {
    const req1 = {
      operation: "inspect_decomp_binary" as const,
      input: { path: "binary.elf" },
    };
    expect(decompRequestSchema.safeParse(req1).success).toBe(true);

    const req2 = {
      operation: "check_decomp_unit" as const,
      input: {
        project_directory: "./decomp",
        symbol: "crc32",
      },
    };
    expect(decompRequestSchema.safeParse(req2).success).toBe(true);
  });
});
