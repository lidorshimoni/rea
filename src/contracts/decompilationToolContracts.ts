import {
  decompInputSchemas,
  decompResultSchemas,
} from "../domain/decompilationAnalysis.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Canonical matching decompilation tool contracts. */
export const DECOMPILATION_TOOL_CONTRACTS = [
  {
    name: "inspect_decomp_binary",
    ...toolContractMetadata("inspect_decomp_binary"),
    kind: "application",
    description:
      "Scans a target binary or raw firmware image for matching decompilation feasibility. Detects executable format (PE/ELF/ARM Cortex-M raw), CPU architecture, bitness, endianness, base address, entry point, MSVC Rich Header build stamps, and ARM NVIC vector tables.",
    inputSchema: decompInputSchemas.inspect_decomp_binary,
    outputSchema: evidenceResultOf(decompResultSchemas.inspect_decomp_binary),
    examples: [
      {
        title: "Inspect target binary for decompilation",
        input: { path: "tests/fixtures/decomp/build/firmware.bin" },
      },
    ],
  },
  {
    name: "init_decomp_project",
    ...toolContractMetadata("init_decomp_project"),
    kind: "application",
    description:
      "Scaffolds a modular matching decompilation project repository for a target binary. Generates decomp.yaml, splat.yaml, objdiff.json, linker.ld, Makefile, and standard headers (types.h, hardware.h, globals.h) with clean directory hierarchy.",
    inputSchema: decompInputSchemas.init_decomp_project,
    outputSchema: evidenceResultOf(decompResultSchemas.init_decomp_project),
    examples: [
      {
        title: "Initialize matching decompilation workspace",
        input: {
          binary_path: "firmware.bin",
          project_directory: "./decomp_workspace",
          preset: "stm32f4",
        },
      },
    ],
  },
  {
    name: "split_decomp_slices",
    ...toolContractMetadata("split_decomp_slices"),
    kind: "application",
    description:
      "Performs contiguous linear partitioning on the target binary. Slices code and data into relocatable .s assembly stubs, literal pools, jump tables, and alignment padding to guarantee the Day 0 Link Invariant (100% bit-exact SHA256 relinking).",
    inputSchema: decompInputSchemas.split_decomp_slices,
    outputSchema: evidenceResultOf(decompResultSchemas.split_decomp_slices),
    examples: [
      {
        title: "Partition target binary into relocatable slices",
        input: { project_directory: "./decomp_workspace" },
      },
    ],
  },
  {
    name: "build_decomp_unit",
    ...toolContractMetadata("build_decomp_unit"),
    kind: "application",
    description:
      "Compiles a candidate C source file or spliced assembly stub with deterministic toolchain settings (SOURCE_DATE_EPOCH=0, LC_ALL=C, TZ=UTC). When relink=true, performs full-binary relinking and validates bit-exact SHA256 parity against the target binary.",
    inputSchema: decompInputSchemas.build_decomp_unit,
    outputSchema: evidenceResultOf(decompResultSchemas.build_decomp_unit),
    examples: [
      {
        title: "Compile candidate unit and relink",
        input: {
          project_directory: "./decomp_workspace",
          symbol: "calc_crc32",
          relink: true,
        },
      },
    ],
  },
  {
    name: "check_decomp_unit",
    ...toolContractMetadata("check_decomp_unit"),
    kind: "application",
    description:
      "Compares a recompiled candidate object against the baseline target slice using relocation-masked object diffing. Produces match percentage (0-100%), similarity score, and detailed instruction deltas.",
    inputSchema: decompInputSchemas.check_decomp_unit,
    outputSchema: evidenceResultOf(decompResultSchemas.check_decomp_unit),
    examples: [
      {
        title: "Diff candidate object against baseline",
        input: {
          project_directory: "./decomp_workspace",
          symbol: "calc_crc32",
        },
      },
    ],
  },
  {
    name: "permute_decomp_symbol",
    ...toolContractMetadata("permute_decomp_symbol"),
    kind: "application",
    description:
      "Optimizes candidate C source code toward a 100.0% match by applying iterative local AST mutations (stack variable reordering, loop transformations, temporary variable inlining) and compiler optimization flag sweeps, escalating to LLM reflexive prompts on plateaus.",
    inputSchema: decompInputSchemas.permute_decomp_symbol,
    outputSchema: evidenceResultOf(decompResultSchemas.permute_decomp_symbol),
    examples: [
      {
        title: "Permute candidate C function for exact match",
        input: {
          project_directory: "./decomp_workspace",
          symbol: "calc_crc32",
          max_iters: 10,
          strategy: "hierarchical",
        },
      },
    ],
  },
  {
    name: "sync_decomp_obligations",
    ...toolContractMetadata("sync_decomp_obligations"),
    kind: "application",
    description:
      "Synchronizes verified 100% matching decompilation symbols into REA's ReconstructionObligationLedger, emitting authentic rea.reconstruction-proof Evidence under the native-abi authority to achieve mathematical reconstruction closure.",
    inputSchema: decompInputSchemas.sync_decomp_obligations,
    outputSchema: evidenceResultOf(decompResultSchemas.sync_decomp_obligations),
    examples: [
      {
        title: "Synchronize verified symbols with obligation ledger",
        input: { project_directory: "./decomp_workspace" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];

/** Resolve a decompilation contract by name while retaining exact types. */
export const decompToolContract = <
  Name extends (typeof DECOMPILATION_TOOL_CONTRACTS)[number]["name"],
>(
  name: Name,
): Extract<
  (typeof DECOMPILATION_TOOL_CONTRACTS)[number],
  { readonly name: Name }
> => {
  const contract = DECOMPILATION_TOOL_CONTRACTS.find(
    (
      c,
    ): c is Extract<
      (typeof DECOMPILATION_TOOL_CONTRACTS)[number],
      { readonly name: Name }
    > => c.name === name,
  );
  if (contract === undefined)
    throw new Error(`Missing decompilation tool contract: ${name}`);
  return contract;
};
