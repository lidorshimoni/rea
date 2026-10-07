import { mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { execFileOutput } from "../process/ExecFileOutput.js";
import {
  MatchingDecompilationService,
  DECOMPILATION_PROVIDER,
} from "./MatchingDecompilationService.js";
import { BinaryFingerprintScanner } from "./BinaryFingerprintScanner.js";
import { DecompilerAstTranspiler } from "./DecompilerAstTranspiler.js";
import { ProjectScaffolder } from "./ProjectScaffolder.js";
import { LinearPartitionSplicer } from "./LinearPartitionSplicer.js";
import { BuiltInObjectDiffer } from "./BuiltInObjectDiffer.js";
import {
  DwarfSymbolExtractor,
  normalizeDwarfOffset,
} from "./DwarfSymbolExtractor.js";
import {
  LibrarySignatureDetector,
  matchBytePattern,
} from "./LibrarySignatureDetector.js";
import {
  MacroConstantRecoverer,
  replaceConstantsInCSource,
} from "./MacroConstantRecoverer.js";
import { SourceCommentAnnotator } from "./SourceCommentAnnotator.js";
import { createAirgapEnv } from "../process/AirgapEnvironment.js";
import {
  decompBinaryFingerprintSchema,
  decompProjectConfigSchema,
  decompSliceManifestSchema,
  decompDiffResultSchema,
  decompBuildResultSchema,
  decompPermuteResultSchema,
  decompSyncObligationsResultSchema,
  decompEnrichSymbolsResultSchema,
  decompDetectLibrariesResultSchema,
  decompRecoverMacrosResultSchema,
  decompAnnotateSourceResultSchema,
  decompEnrichProjectResultSchema,
} from "../domain/decompilationAnalysis.js";

describe("BinaryFingerprintScanner", () => {
  it("scans synthetic ARM Cortex-M NVIC firmware image", () => {
    const scanner = new BinaryFingerprintScanner();
    // 16 32-bit vector entries (64 bytes)
    const buf = Buffer.alloc(128, 0);
    buf.writeUInt32LE(0x20002000, 0); // Initial SP in SRAM
    buf.writeUInt32LE(0x08000041, 4); // Reset_Handler (Thumb address in Flash)
    buf.writeUInt32LE(0x08000051, 8); // NMI_Handler
    buf.writeUInt32LE(0x08000061, 12); // HardFault_Handler

    const result = scanner.scanBuffer(buf);
    expect(result.format).toBe("ARM_CORTEX_M_RAW");
    expect(result.architecture).toBe("arm-thumb");
    expect(result.bits).toBe(32);
    expect(result.endianness).toBe("little");
    expect(result.image_base).toBe("0x08000000");
    expect(result.entry_point).toBe("0x08000040");
    expect(result.feasible_1to1_match).toBe(true);
    expect(decompBinaryFingerprintSchema.safeParse(result).success).toBe(true);
  });

  it("scans synthetic PE buffer with MSVC Rich Header", () => {
    const scanner = new BinaryFingerprintScanner();
    const peOffset = 128;
    const buf = Buffer.alloc(512, 0);
    // MZ header
    buf[0] = 0x4d;
    buf[1] = 0x5a;
    buf.writeUInt32LE(peOffset, 60);

    // Rich Header before PE
    // DanS ... Rich <key>
    const richKey = 0x12345678;
    const richOff = 64;
    buf.writeUInt32LE(0x536e6144 ^ richKey, richOff); // 'DanS' ^ key
    buf.writeUInt32LE(richKey, richOff + 4);
    buf.writeUInt32LE(richKey, richOff + 8);
    buf.writeUInt32LE(richKey, richOff + 12);
    // Product 0x012c (VS2019 C Compiler) xor key
    buf.writeUInt32LE(0x012c0001 ^ richKey, richOff + 16);
    buf.writeUInt32LE(1 ^ richKey, richOff + 20);
    buf.write("Rich", richOff + 24);
    buf.writeUInt32LE(richKey, richOff + 28);

    // PE signature
    buf[peOffset] = 0x50;
    buf[peOffset + 1] = 0x45;
    // Machine = 0x8664 (x86_64)
    buf.writeUInt16LE(0x8664, peOffset + 4);
    // Number of sections = 1
    buf.writeUInt16LE(1, peOffset + 6);
    // Optional header magic = 0x20b (PE32+)
    buf.writeUInt16LE(0x020b, peOffset + 24);
    buf.writeBigUInt64LE(0x0000000140000000n, peOffset + 48); // ImageBase

    const result = scanner.scanBuffer(buf);
    expect(result.format).toBe("PE32+");
    expect(result.architecture).toBe("x86_64");
    expect(result.bits).toBe(64);
    expect(result.endianness).toBe("little");
    expect(result.recommended_toolchain).toContain("VS2019");
    expect(decompBinaryFingerprintSchema.safeParse(result).success).toBe(true);
  });
});

describe("DecompilerAstTranspiler", () => {
  it("de-synthesizes synthetic types and idioms into C99", () => {
    const transpiler = new DecompilerAstTranspiler();
    const inputPseudocode = `
/* WARNING: Function: crc32 may have stack adjustments */
undefined4 process_packet(undefined4 param1, undefined1 *param2) {
    undefined4 local_10 = DAT_08001000;
    if (param2 == (code *)0x0) {
        return 0;
    }
    return local_10 + param1;
}
`;
    const output = transpiler.transpile(inputPseudocode);
    expect(output).not.toContain("WARNING");
    expect(output).not.toContain("undefined4");
    expect(output).not.toContain("undefined1");
    expect(output).toContain("uint32_t process_packet");
    expect(output).toContain("uint8_t *param2");
    expect(output).toContain("NULL");
    expect(output).toContain("(*(volatile uint32_t *)0x08001000)");
    expect(output).toContain('#include "types.h"');
    expect(output).toContain('#include "hardware.h"');
    expect(output).toContain('#include "globals.h"');
  });
});

describe("ProjectScaffolder", () => {
  it("scaffolds modular structure and authentic configs", async () => {
    const testDir = await createTestTempDirectory("rea-scaffold-test-");
    const scaffolder = new ProjectScaffolder();

    // Create a dummy target.bin
    const dummyBinPath = join(testDir, "seed.bin");
    const dummyBytes = Buffer.from([
      0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    ]);
    await writeFile(dummyBinPath, dummyBytes);

    const projectDir = join(testDir, "proj");
    const config = await scaffolder.scaffold({
      binaryPath: dummyBinPath,
      projectDirectory: projectDir,
    });

    expect(config.schema_version).toBe(1);
    expect(config.target.path).toBe("target.bin");
    expect(config.toolchain.compiler).toBe("gcc");
    expect(decompProjectConfigSchema.safeParse(config).success).toBe(true);

    const decompYaml = await readFile(join(projectDir, "decomp.yaml"), "utf8");
    expect(decompYaml).toContain("schema_version: 1");

    const typesHeader = await readFile(
      join(projectDir, "include", "types.h"),
      "utf8",
    );
    expect(typesHeader).toContain("uint32_t");
    expect(typesHeader).toContain("u32");

    const hardwareHeader = await readFile(
      join(projectDir, "include", "hardware.h"),
      "utf8",
    );
    expect(hardwareHeader).toContain("REG32");

    const objdiffJson = await readFile(
      join(projectDir, "objdiff.json"),
      "utf8",
    );
    expect(objdiffJson).toContain('"custom_make"');
  });
});

describe("LinearPartitionSplicer & Day 0 Link Invariant", () => {
  it("partitions binary into assembly stubs and proves 100% bit-exact Day 0 relink", async () => {
    const testDir = await createTestTempDirectory("rea-splicer-test-");
    const targetBin = join(testDir, "target.bin");

    // Generate deterministic 256-byte payload
    const payload = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) {
      payload[i] = (i * 37 + 13) & 0xff;
    }
    await writeFile(targetBin, payload);
    const expectedSha256 = createHash("sha256").update(payload).digest("hex");

    const splicer = new LinearPartitionSplicer();
    const manifest = await splicer.split({
      projectDirectory: testDir,
      targetPath: targetBin,
    });

    expect(manifest.target_sha256).toBe(expectedSha256);
    expect(manifest.total_slices).toBeGreaterThan(0);
    expect(decompSliceManifestSchema.safeParse(manifest).success).toBe(true);

    // Verify that every slice exists on disk
    for (const slice of manifest.slices) {
      const stubContent = await readFile(join(testDir, slice.asm_file), "utf8");
      expect(stubContent).toContain('.incbin "target.bin"');
      expect(stubContent).toContain(".balign 1");
    }

    // Assemble all slices and relink using host tools
    const objFiles: string[] = [];
    const buildDir = join(testDir, "build");
    await mkdir(buildDir, { recursive: true });

    for (let i = 0; i < manifest.slices.length; i++) {
      const slice = manifest.slices[i]!;
      const asmPath = join(testDir, slice.asm_file);
      const objPath = join(buildDir, `slice_${i}.o`);
      await execFileOutput("as", ["-I", testDir, asmPath, "-o", objPath], {
        cwd: testDir,
      });
      objFiles.push(objPath);
    }

    const relinkedElf = join(buildDir, "relinked.elf");
    const relinkedBin = join(buildDir, "relinked.bin");
    const linkerScript = join(testDir, manifest.linker_script_path);

    await execFileOutput(
      "ld",
      ["-T", linkerScript, "-nostdlib", ...objFiles, "-o", relinkedElf],
      { cwd: testDir },
    );

    await execFileOutput(
      "objcopy",
      ["-O", "binary", relinkedElf, relinkedBin],
      { cwd: testDir },
    );

    const relinkedBytes = await readFile(relinkedBin);
    const actualSha256 = createHash("sha256")
      .update(relinkedBytes)
      .digest("hex");

    expect(actualSha256).toBe(expectedSha256);
    expect(relinkedBytes.equals(payload)).toBe(true);
  });
});

describe("BuiltInObjectDiffer", () => {
  it("reports 100% matched for identical object files", async () => {
    const testDir = await createTestTempDirectory("rea-differ-test-");
    const differ = new BuiltInObjectDiffer();

    const srcC = join(testDir, "fn.c");
    await writeFile(
      srcC,
      `
#include <stdint.h>
uint32_t compute(uint32_t a, uint32_t b) {
    return (a * 3) ^ (b + 7);
}
`,
    );

    const obj1 = join(testDir, "fn1.o");
    const obj2 = join(testDir, "fn2.o");

    await execFileOutput("gcc", ["-O2", "-c", srcC, "-o", obj1]);
    await execFileOutput("gcc", ["-O2", "-c", srcC, "-o", obj2]);

    const diff = await differ.diff({
      unit: "src/fn.c",
      symbol: "compute",
      expectedPath: obj1,
      compiledPath: obj2,
    });

    expect(diff.status).toBe("matched");
    expect(diff.similarity).toBe(1);
    expect(diff.match_percent).toBe(100);
    expect(diff.sample_mismatches).toHaveLength(0);
    expect(decompDiffResultSchema.safeParse(diff).success).toBe(true);
  });

  it("detects differences and reports sample mismatches", async () => {
    const testDir = await createTestTempDirectory("rea-differ-diff-");
    const differ = new BuiltInObjectDiffer();

    const srcC1 = join(testDir, "fn1.c");
    const srcC2 = join(testDir, "fn2.c");

    await writeFile(
      srcC1,
      `
#include <stdint.h>
uint32_t compute(uint32_t a, uint32_t b) {
    return (a * 3) + b;
}
`,
    );
    await writeFile(
      srcC2,
      `
#include <stdint.h>
uint32_t compute(uint32_t a, uint32_t b) {
    return (a * 99) - b;
}
`,
    );

    const obj1 = join(testDir, "fn1.o");
    const obj2 = join(testDir, "fn2.o");

    await execFileOutput("gcc", ["-O2", "-c", srcC1, "-o", obj1]);
    await execFileOutput("gcc", ["-O2", "-c", srcC2, "-o", obj2]);

    const diff = await differ.diff({
      unit: "src/fn.c",
      symbol: "compute",
      expectedPath: obj1,
      compiledPath: obj2,
    });

    expect(diff.status).toBe("different");
    expect(diff.similarity).toBeLessThan(1);
    expect(diff.sample_mismatches.length).toBeGreaterThan(0);
    expect(decompDiffResultSchema.safeParse(diff).success).toBe(true);
  });
});

describe("MatchingDecompilationService full workflow", () => {
  it("executes complete lifecycle and achieves obligation closure", async () => {
    const testDir = await createTestTempDirectory("rea-decomp-e2e-");
    const service = new MatchingDecompilationService();

    // 1. Compile target binary from fixtures
    const fixtureDir = join(process.cwd(), "tests", "fixtures", "decomp");
    const targetBin = join(testDir, "target.bin");

    await execFileOutput("gcc", [
      "-O2",
      "-fno-pie",
      "-no-pie",
      "-ffunction-sections",
      join(fixtureDir, "main.c"),
      join(fixtureDir, "crc32.c"),
      join(fixtureDir, "globals.c"),
      join(fixtureDir, "jump_tables.c"),
      "-o",
      targetBin,
    ]);

    // 2. inspect_decomp_binary
    const inspectRes = await service.execute("inspect_decomp_binary", {
      path: targetBin,
    });
    expect(inspectRes.ok).toBe(true);
    if (!inspectRes.ok) throw new Error("inspect failed");
    expect(inspectRes.value.provider.id).toBe(DECOMPILATION_PROVIDER.id);
    expect(inspectRes.value.predicate_type).toBe(
      "rea.decompilation.fingerprint",
    );
    const fingerprint = decompBinaryFingerprintSchema.parse(
      inspectRes.value.normalized_result,
    );
    expect(fingerprint.architecture).toBe("x86_64");

    // 3. init_decomp_project
    const projectDir = join(testDir, "project");
    const initRes = await service.execute("init_decomp_project", {
      binary_path: targetBin,
      project_directory: projectDir,
    });
    expect(initRes.ok).toBe(true);
    if (!initRes.ok) throw new Error("init failed");
    expect(initRes.value.predicate_type).toBe("rea.decompilation.project");

    // 4. split_decomp_slices
    const splitRes = await service.execute("split_decomp_slices", {
      project_directory: projectDir,
    });
    expect(splitRes.ok).toBe(true);
    if (!splitRes.ok) throw new Error("split failed");
    expect(splitRes.value.predicate_type).toBe("rea.decompilation.slices");
    const sliceManifest = decompSliceManifestSchema.parse(
      splitRes.value.normalized_result,
    );
    expect(sliceManifest.total_slices).toBeGreaterThan(0);

    // Verify Day 0 Relink
    const relinkRes = await service.execute("build_decomp_unit", {
      project_directory: projectDir,
      relink: true,
    });
    expect(relinkRes.ok).toBe(true);
    if (!relinkRes.ok) throw new Error("relink failed");
    const relinkData = decompBuildResultSchema.parse(
      relinkRes.value.normalized_result,
    );
    expect(relinkData.relink_success).toBe(true);
    expect(relinkData.full_binary_match).toBe(true);

    // Copy authentic source files into project src/core
    await writeFile(
      join(projectDir, "src", "core", "crc32.c"),
      await readFile(join(fixtureDir, "crc32.c"), "utf8"),
    );

    // 5. check_decomp_unit on crc32
    const checkRes = await service.execute("check_decomp_unit", {
      project_directory: projectDir,
      symbol: "crc32",
    });
    expect(checkRes.ok).toBe(true);
    if (!checkRes.ok) throw new Error("check failed");
    const checkData = decompDiffResultSchema.parse(
      checkRes.value.normalized_result,
    );
    expect(checkData.status).toBe("matched");
    expect(checkData.similarity).toBe(1);

    // 6. permute_decomp_symbol on crc32
    const permuteRes = await service.execute("permute_decomp_symbol", {
      project_directory: projectDir,
      symbol: "crc32",
      max_iters: 2,
    });
    expect(permuteRes.ok).toBe(true);
    if (!permuteRes.ok) throw new Error("permute failed");
    const permuteData = decompPermuteResultSchema.parse(
      permuteRes.value.normalized_result,
    );
    expect(permuteData.best_similarity).toBe(1);

    // 7. sync_decomp_obligations
    const syncRes = await service.execute("sync_decomp_obligations", {
      project_directory: projectDir,
    });
    expect(syncRes.ok).toBe(true);
    if (!syncRes.ok) throw new Error("sync failed");
    const syncData = decompSyncObligationsResultSchema.parse(
      syncRes.value.normalized_result,
    );
    expect(syncData.verified_symbols).toContain("crc32");
    expect(syncData.ledger_closed).toBe(true);
    expect(syncData.closure_digest).toBeDefined();
    expect(decompSyncObligationsResultSchema.safeParse(syncData).success).toBe(
      true,
    );

    const savedLedgerRaw = await readFile(
      join(projectDir, "ledger.json"),
      "utf8",
    );
    const savedLedger = JSON.parse(savedLedgerRaw);
    expect(savedLedger.status).toBe("ready");
    expect(savedLedger.summary.required_open).toBe(0);
    expect(savedLedger.summary.verified).toBeGreaterThanOrEqual(1);
  });
});

describe("MatchingDecompilationService error handling", () => {
  it("handles cancellation signal properly", async () => {
    const service = new MatchingDecompilationService();
    const controller = new AbortController();
    controller.abort();

    const result = await service.execute(
      "inspect_decomp_binary",
      { path: "fake.bin" },
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisCancelledError");
    }
  });

  it("rejects invalid input schema", async () => {
    const service = new MatchingDecompilationService();
    const result = await service.execute("inspect_decomp_binary", {
      invalid_prop: 123,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisInputError");
    }
  });
});

describe("AirgapEnvironment", () => {
  it("enforces offline environment variables and sanitizes remote symbol server URLs", () => {
    const env = createAirgapEnv({
      DEBUGINFOD_URLS: "https://debuginfod.elfutils.org/",
      DEBUGINFOD_TIMEOUT: "90",
      OTHER_KEY: "preserved",
    });
    expect(env.DEBUGINFOD_URLS).toBe("");
    expect(env.DEBUGINFOD_TIMEOUT).toBe("0");
    expect(env.DEBUGINFOD_MAX_RETRIES).toBe("0");
    expect(env.LC_ALL).toBe("C");
    expect(env.TZ).toBe("UTC");
    expect(env.SOURCE_DATE_EPOCH).toBe("0");
    expect(env.OTHER_KEY).toBe("preserved");
  });
});

describe("DwarfSymbolExtractor", () => {
  it("extracts exact function signatures, parameters, and structs from DWARF debug info", async () => {
    const testDir = await createTestTempDirectory("dwarf-extractor-test-");
    const src = join(testDir, "test.c");
    await writeFile(
      src,
      `
      struct PacketHeader {
          int version;
          int length;
      };
      int process_packet(struct PacketHeader hdr, int flags) {
          int status = hdr.version + flags;
          return status;
      }
      `,
      "utf8",
    );
    const obj = join(testDir, "test.o");
    await execFileOutput("gcc", ["-g", "-c", src, "-o", obj], {
      env: createAirgapEnv(),
    });

    const extractor = new DwarfSymbolExtractor();
    const result = await extractor.extract({
      binaryPath: obj,
      projectDirectory: testDir,
    });

    expect(decompEnrichSymbolsResultSchema.safeParse(result).success).toBe(
      true,
    );
    expect(result.total_functions_recovered).toBeGreaterThanOrEqual(1);
    const fn = result.functions.find((f) => f.name === "process_packet");
    expect(fn).toBeDefined();
    expect(fn?.parameters.length).toBe(2);
    expect(fn?.parameters.map((p) => p.name)).toEqual(["hdr", "flags"]);
    expect(result.types.some((t) => t.name === "PacketHeader")).toBe(true);

    const symbolsH = await readFile(
      join(testDir, "include", "symbols.h"),
      "utf8",
    );
    expect(symbolsH).toContain("process_packet");
    const typesH = await readFile(join(testDir, "include", "types.h"), "utf8");
    expect(typesH).toContain("PacketHeader");
  });
});

describe("LibrarySignatureDetector", () => {
  it("detects 3rd-party library signatures from binary strings and emits libraries.h", async () => {
    const testDir = await createTestTempDirectory("lib-sig-test-");
    const dummyBin = join(testDir, "target.bin");
    const payload = Buffer.concat([
      Buffer.from("dummy code segment prefix"),
      Buffer.from(
        "deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler\0",
      ),
      Buffer.from("inflate 1.2.11 Copyright 1995-2017 Mark Adler\0"),
      Buffer.from("SQLite format 3\0"),
    ]);
    await writeFile(dummyBin, payload);

    const detector = new LibrarySignatureDetector();
    const result = await detector.detect({
      projectDirectory: testDir,
      binaryPath: dummyBin,
    });

    expect(decompDetectLibrariesResultSchema.safeParse(result).success).toBe(
      true,
    );
    expect(result.total_libraries_detected).toBeGreaterThanOrEqual(1);
    const zlib = result.detected_libraries.find((l) => l.library === "zlib");
    expect(zlib).toBeDefined();
    expect(zlib?.confidence).toBeGreaterThan(0.5);

    const libHeader = await readFile(
      join(testDir, "include", "libraries.h"),
      "utf8",
    );
    expect(libHeader).toContain("REA_LIBRARY_ZLIB");
  });
});

describe("MacroConstantRecoverer", () => {
  it("recovers deterministic magic constants and replaces them in source files", async () => {
    const testDir = await createTestTempDirectory("macro-recover-test-");
    await mkdir(join(testDir, "src", "core"), { recursive: true });
    const srcFile = join(testDir, "src", "core", "test_crc.c");
    await writeFile(
      srcFile,
      `unsigned int calc(unsigned int val) {\n    return val ^ 0xEDB88320;\n}\n`,
      "utf8",
    );

    const recoverer = new MacroConstantRecoverer();
    const result = await recoverer.recover({
      projectDirectory: testDir,
      targetSourcePath: "src/core/test_crc.c",
    });

    expect(decompRecoverMacrosResultSchema.safeParse(result).success).toBe(
      true,
    );
    expect(result.total_macros).toBeGreaterThanOrEqual(1);
    const macro = result.macros_recovered.find(
      (m) => m.name === "CRC32_POLYNOMIAL",
    );
    expect(macro).toBeDefined();
    expect(macro?.value).toBe("0xedb88320");

    const macrosHeader = await readFile(
      join(testDir, "include", "macros.h"),
      "utf8",
    );
    expect(macrosHeader).toContain("#define CRC32_POLYNOMIAL 0xedb88320");

    const updatedSrc = await readFile(srcFile, "utf8");
    expect(updatedSrc).toContain("CRC32_POLYNOMIAL");
    expect(updatedSrc).toContain('#include "macros.h"');
  });
});

describe("SourceCommentAnnotator", () => {
  it("synthesizes Doxygen contracts and intent comments while preserving code statements", async () => {
    const testDir = await createTestTempDirectory("comment-annotator-test-");
    await mkdir(join(testDir, "src", "core"), { recursive: true });
    const srcFile = join(testDir, "src", "core", "math.c");
    const code = `int sum_array(int *arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += arr[i];
    }
    return total;
}`;
    await writeFile(srcFile, code, "utf8");

    const annotator = new SourceCommentAnnotator();
    const result = await annotator.annotate({
      projectDirectory: testDir,
      sourceFile: "src/core/math.c",
      symbol: "sum_array",
      style: "both",
    });

    expect(decompAnnotateSourceResultSchema.safeParse(result).success).toBe(
      true,
    );
    expect(result.total_comments_added).toBeGreaterThan(0);
    expect(result.functions_annotated.length).toBe(1);

    const annotatedSource = await readFile(srcFile, "utf8");
    expect(annotatedSource).toContain("/**");
    expect(annotatedSource).toContain("@param[in] arr");
    expect(annotatedSource).toContain("@param[in] len");
    expect(annotatedSource).toContain("@return");
    expect(annotatedSource).toContain("total += arr[i];");
  });
});

describe("MatchingDecompilationService SDES operations", () => {
  it("executes the 5 discrete enrichment tools and validates authentic outputs", async () => {
    const service = new MatchingDecompilationService();
    const testDir = await createTestTempDirectory("sdes-service-test-");
    const projectDir = join(testDir, "project");

    // Initialize project
    const dummyBin = join(testDir, "target.bin");
    const payload = Buffer.concat([
      Buffer.from("initial binary header..."),
      Buffer.from(
        "deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler\0",
      ),
    ]);
    await writeFile(dummyBin, payload);

    const initRes = await service.execute("init_decomp_project", {
      binary_path: dummyBin,
      project_directory: projectDir,
    });
    expect(initRes.ok).toBe(true);

    // Create a debug object for DWARF extraction test
    const debugSrc = join(testDir, "debug.c");
    await writeFile(
      debugSrc,
      `
      struct Point { int x; int y; };
      int add_coords(struct Point pt) { return pt.x + pt.y; }
      `,
      "utf8",
    );
    const debugObj = join(testDir, "debug.o");
    await execFileOutput("gcc", ["-g", "-c", debugSrc, "-o", debugObj], {
      env: createAirgapEnv(),
    });

    // 1. enrich_decomp_symbols
    const enrichSymbolsRes = await service.execute("enrich_decomp_symbols", {
      project_directory: projectDir,
      binary_path: debugObj,
    });
    expect(enrichSymbolsRes.ok).toBe(true);
    if (!enrichSymbolsRes.ok) throw new Error("enrich_decomp_symbols failed");
    expect(enrichSymbolsRes.value.predicate_type).toBe(
      "rea.decompilation.symbols",
    );
    const symbolsData = decompEnrichSymbolsResultSchema.parse(
      enrichSymbolsRes.value.normalized_result,
    );
    expect(symbolsData.total_functions_recovered).toBeGreaterThanOrEqual(1);

    // 2. detect_decomp_libraries
    const detectLibsRes = await service.execute("detect_decomp_libraries", {
      project_directory: projectDir,
      binary_path: dummyBin,
    });
    expect(detectLibsRes.ok).toBe(true);
    if (!detectLibsRes.ok) throw new Error("detect_decomp_libraries failed");
    expect(detectLibsRes.value.predicate_type).toBe(
      "rea.decompilation.libraries",
    );
    const libsData = decompDetectLibrariesResultSchema.parse(
      detectLibsRes.value.normalized_result,
    );
    expect(libsData.total_libraries_detected).toBeGreaterThanOrEqual(1);

    // 3. recover_decomp_macros
    await mkdir(join(projectDir, "src", "core"), { recursive: true });
    await writeFile(
      join(projectDir, "src", "core", "test.c"),
      `int test_func(int x) { return x ^ 0xEDB88320; }`,
      "utf8",
    );
    const recoverMacrosRes = await service.execute("recover_decomp_macros", {
      project_directory: projectDir,
    });
    expect(recoverMacrosRes.ok).toBe(true);
    if (!recoverMacrosRes.ok) throw new Error("recover_decomp_macros failed");
    expect(recoverMacrosRes.value.predicate_type).toBe(
      "rea.decompilation.macros",
    );
    const macrosData = decompRecoverMacrosResultSchema.parse(
      recoverMacrosRes.value.normalized_result,
    );
    expect(macrosData.total_macros).toBeGreaterThanOrEqual(1);

    // 4. annotate_decomp_source
    const annotateRes = await service.execute("annotate_decomp_source", {
      project_directory: projectDir,
      symbol: "test_func",
      style: "both",
    });
    expect(annotateRes.ok).toBe(true);
    if (!annotateRes.ok) throw new Error("annotate_decomp_source failed");
    expect(annotateRes.value.predicate_type).toBe(
      "rea.decompilation.annotations",
    );
    const annotateData = decompAnnotateSourceResultSchema.parse(
      annotateRes.value.normalized_result,
    );
    expect(annotateData.functions_annotated.length).toBe(1);

    // 5. enrich_decomp_project
    const enrichProjRes = await service.execute("enrich_decomp_project", {
      project_directory: projectDir,
      dwarf_symbols: false, // already tested on debug.o
      library_detection: true,
      macro_recovery: true,
      comment_synthesis: true,
    });
    expect(enrichProjRes.ok).toBe(true);
    if (!enrichProjRes.ok) throw new Error("enrich_decomp_project failed");
    expect(enrichProjRes.value.predicate_type).toBe(
      "rea.decompilation.enrichment",
    );
    const enrichData = decompEnrichProjectResultSchema.parse(
      enrichProjRes.value.normalized_result,
    );
    expect(enrichData.summary).toContain("Enriched project");
  });
});

describe("matchBytePattern wildcard verification", () => {
  it("matches exact opcode byte sequences", () => {
    const buf = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10]);
    expect(matchBytePattern(buf, "55 48 89 e5")).toBe(true);
    expect(matchBytePattern(buf, "48 83 ec 10")).toBe(true);
    expect(matchBytePattern(buf, "55 48 89 e6")).toBe(false);
  });

  it("matches with ?? and ? wildcards", () => {
    const buf = Buffer.from([
      0x55, 0x48, 0x89, 0xe5, 0xb8, 0x20, 0x83, 0xb8, 0xed,
    ]);
    expect(matchBytePattern(buf, "55 48 ?? e5")).toBe(true);
    expect(matchBytePattern(buf, "55 48 ? e5")).toBe(true);
    expect(matchBytePattern(buf, "?? ?? ?? ?? b8 ?? ?? ?? ed")).toBe(true);
    expect(matchBytePattern(buf, "55 ?? ?? ?? ?? 00")).toBe(false);
  });

  it("handles boundary cases cleanly", () => {
    const buf = Buffer.from([0x55]);
    expect(matchBytePattern(buf, "55 48 89")).toBe(false);
    expect(matchBytePattern(buf, "")).toBe(false);
    expect(matchBytePattern(Buffer.alloc(0), "55")).toBe(false);
  });
});

describe("replaceConstantsInCSource token and suffix robustness", () => {
  it("replaces hex constants with compiler suffixes and leading zeros", () => {
    const macros = [
      {
        name: "CRC32_POLYNOMIAL",
        value: "0xedb88320",
        category: "cryptographic_polynomial",
        occurrences: 1,
      },
    ];
    const source = `uint32_t val1 = 0xedb88320U;\nuint32_t val2 = 0xEDB88320UL;\nuint32_t val3 = 0x00edb88320;`;
    const res = replaceConstantsInCSource(source, macros);
    expect(res.modified).toBe(true);
    expect(res.content).toContain("uint32_t val1 = CRC32_POLYNOMIAL;");
    expect(res.content).toContain("uint32_t val2 = CRC32_POLYNOMIAL;");
    expect(res.content).toContain("uint32_t val3 = CRC32_POLYNOMIAL;");
    expect(res.content).toContain('#include "macros.h"');
  });

  it("strictly preserves constants inside string literals, char literals, and comments", () => {
    const macros = [
      {
        name: "CRC32_POLYNOMIAL",
        value: "0xedb88320",
        category: "cryptographic_polynomial",
        occurrences: 1,
      },
    ];
    const source = `// Polynomial is 0xedb88320
/* Multiline
   0xedb88320 inside comment
*/
const char *msg = "Checksum polynomial: 0xedb88320\\n";
char ch = 'a';
uint32_t poly = 0xedb88320;
`;
    const res = replaceConstantsInCSource(source, macros);
    expect(res.modified).toBe(true);
    expect(res.content).toContain("// Polynomial is 0xedb88320");
    expect(res.content).toContain("0xedb88320 inside comment");
    expect(res.content).toContain('"Checksum polynomial: 0xedb88320\\n"');
    expect(res.content).toContain("char ch = 'a';");
    expect(res.content).toContain("uint32_t poly = CRC32_POLYNOMIAL;");
  });
});

describe("SourceCommentAnnotator edge cases", () => {
  it("ignores fake functions in comments and strings and handles braces in strings/comments", async () => {
    const testDir = await createTestTempDirectory("comment-edge-test-");
    await mkdir(join(testDir, "src", "core"), { recursive: true });
    const srcFile = join(testDir, "src", "core", "tricky.c");
    const code = `// int fake_comment_fn() { return 0; }
/*
void fake_block_fn() {
    int ignored = 1;
}
*/
const char *fake_code = "int fake_str_fn() { return 2; }";

int real_fn(int code) {
    if (code > 0) {
        printf("} closing brace in string\\n"); // } and comment brace
    }
    return code ^ 0x1234;
}
`;
    await writeFile(srcFile, code, "utf8");

    const annotator = new SourceCommentAnnotator();
    const result = await annotator.annotate({
      projectDirectory: testDir,
      sourceFile: "src/core/tricky.c",
      style: "both",
    });

    expect(result.functions_annotated.length).toBe(1);
    expect(result.functions_annotated[0]?.symbol).toBe("real_fn");

    const annotatedSource = await readFile(srcFile, "utf8");
    expect(annotatedSource).toContain("fake_comment_fn");
    expect(annotatedSource).toContain("fake_block_fn");
    expect(annotatedSource).toContain("fake_str_fn");
    expect(annotatedSource).toContain("/**");
    expect(annotatedSource).toContain("@param[in] code");
    expect(annotatedSource).toContain(
      'printf("} closing brace in string\\n");',
    );
  });

  it("annotates function with existing Doxygen with intent comments without duplicating doc block", async () => {
    const testDir = await createTestTempDirectory("comment-doxygen-exist-");
    await mkdir(join(testDir, "src", "core"), { recursive: true });
    const srcFile = join(testDir, "src", "core", "doc.c");
    const code = `/**
 * @brief Existing documentation for compute.
 */
int compute(int *arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += arr[i];
    }
    return total;
}
`;
    await writeFile(srcFile, code, "utf8");

    const annotator = new SourceCommentAnnotator();
    const result = await annotator.annotate({
      projectDirectory: testDir,
      sourceFile: "src/core/doc.c",
      style: "intent",
    });

    expect(result.functions_annotated.length).toBe(1);
    expect(result.total_comments_added).toBeGreaterThan(0);

    const annotatedSource = await readFile(srcFile, "utf8");
    const docMatches = annotatedSource.match(
      /@brief Existing documentation for compute/g,
    );
    expect(docMatches?.length).toBe(1);
    expect(annotatedSource).toContain(
      "/* Algorithmic intent: iterative block processing loop */",
    );
  });
});

describe("DwarfSymbolExtractor offset normalization & member locations", () => {
  it("normalizes DIE offsets across formats", () => {
    expect(normalizeDwarfOffset("<0x14a>")).toBe("14a");
    expect(normalizeDwarfOffset("<0x0014a>")).toBe("14a");
    expect(normalizeDwarfOffset("0x00014a")).toBe("14a");
    expect(normalizeDwarfOffset("14a")).toBe("14a");
    expect(normalizeDwarfOffset("0x0")).toBe("0");
    expect(normalizeDwarfOffset("0")).toBe("0");
  });

  it("extracts struct member locations accurately", async () => {
    const testDir = await createTestTempDirectory("dwarf-struct-test-");
    const src = join(testDir, "struct_test.c");
    await writeFile(
      src,
      `
      struct HardwareRegisters {
          volatile unsigned int ctrl;
          volatile unsigned int status;
          volatile unsigned int data[4];
      };
      int read_reg(struct HardwareRegisters regs) {
          return regs.status;
      }
      `,
      "utf8",
    );
    const obj = join(testDir, "struct_test.o");
    await execFileOutput("gcc", ["-g", "-c", src, "-o", obj], {
      env: createAirgapEnv(),
    });

    const extractor = new DwarfSymbolExtractor();
    const result = await extractor.extract({
      binaryPath: obj,
      projectDirectory: testDir,
    });

    const hwRegs = result.types.find((t) => t.name === "HardwareRegisters");
    expect(hwRegs).toBeDefined();
    expect(hwRegs?.members).toBeDefined();
    expect(hwRegs?.members?.length).toBe(3);

    const ctrl = hwRegs?.members?.find((m) => m.name === "ctrl");
    const status = hwRegs?.members?.find((m) => m.name === "status");
    const data = hwRegs?.members?.find((m) => m.name === "data");

    expect(ctrl?.offset).toBe(0);
    expect(status?.offset).toBe(4);
    expect(data?.offset).toBe(8);
  });
});
