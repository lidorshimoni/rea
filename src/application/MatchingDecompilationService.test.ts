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
  decompBinaryFingerprintSchema,
  decompProjectConfigSchema,
  decompSliceManifestSchema,
  decompDiffResultSchema,
  decompSyncObligationsResultSchema,
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
    expect(decompYaml).toContain('"schema_version": 1');

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
    const fingerprint = inspectRes.value.normalized_result as any;
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
    const sliceManifest = splitRes.value.normalized_result as any;
    expect(sliceManifest.total_slices).toBeGreaterThan(0);

    // Verify Day 0 Relink
    const relinkRes = await service.execute("build_decomp_unit", {
      project_directory: projectDir,
      relink: true,
    });
    expect(relinkRes.ok).toBe(true);
    if (!relinkRes.ok) throw new Error("relink failed");
    const relinkData = relinkRes.value.normalized_result as any;
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
    const checkData = checkRes.value.normalized_result as any;
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
    const permuteData = permuteRes.value.normalized_result as any;
    expect(permuteData.best_similarity).toBe(1);

    // 7. sync_decomp_obligations
    const syncRes = await service.execute("sync_decomp_obligations", {
      project_directory: projectDir,
    });
    expect(syncRes.ok).toBe(true);
    if (!syncRes.ok) throw new Error("sync failed");
    const syncData = syncRes.value.normalized_result as any;
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
