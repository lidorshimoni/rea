import { z } from "incur";
import { MatchingDecompilationService } from "../application/MatchingDecompilationService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { DecompOperation } from "../domain/decompilationAnalysis.js";
import type { Logger } from "../logger.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** One-shot matching decompilation CLI commands backed by the same workflows as MCP. */
export const registerDecompilationCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = new MatchingDecompilationService();
  const execute = (name: string, operation: DecompOperation, input: unknown) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, async () => {
        const result = await service.execute(operation, input, { signal });
        return result.ok ? result.value : projectAnalysisError(result.error);
      }),
    );

  cli.command(CLI_COMMANDS.inspectDecompBinary, {
    description:
      "Scans a target binary or raw firmware image for matching decompilation feasibility",
    args: z.object({
      path: z.string().describe("Path to target binary or raw firmware"),
    }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.inspectDecompBinary, "inspect_decomp_binary", args),
  });

  cli.command(CLI_COMMANDS.initDecompProject, {
    description:
      "Scaffolds a modular matching decompilation project repository for a target binary",
    args: z.object({
      binaryPath: z.string().describe("Path to original target binary"),
      projectDirectory: z
        .string()
        .describe("Directory to scaffold matching decomp project"),
    }),
    options: z.object({
      preset: z
        .string()
        .optional()
        .describe("Optional preset (e.g. stm32f4, posix_x86_64, msvc_pe)"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.initDecompProject, "init_decomp_project", {
        binary_path: args.binaryPath,
        project_directory: args.projectDirectory,
        ...(options.preset !== undefined ? { preset: options.preset } : {}),
      }),
  });

  cli.command(CLI_COMMANDS.splitDecompSlices, {
    description:
      "Performs contiguous linear partitioning on the target binary into relocatable assembly stubs",
    args: z.object({
      projectDirectory: z
        .string()
        .describe("Matching decomp project root directory"),
    }),
    options: z.object({
      targetPath: z
        .string()
        .optional()
        .describe("Override target binary path if moved"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.splitDecompSlices, "split_decomp_slices", {
        project_directory: args.projectDirectory,
        ...(options.targetPath !== undefined
          ? { target_path: options.targetPath }
          : {}),
      }),
  });

  cli.command(CLI_COMMANDS.buildDecompUnit, {
    description:
      "Compiles a candidate C source file or spliced assembly stub with deterministic toolchain settings",
    args: z.object({
      projectDirectory: z
        .string()
        .describe("Matching decomp project root directory"),
    }),
    options: z.object({
      symbol: z
        .string()
        .optional()
        .describe("Specific symbol/function to compile"),
      unit: z.string().optional().describe("Translation unit path to compile"),
      relink: z
        .boolean()
        .optional()
        .describe(
          "If true, perform full-binary relinking and check SHA256 match",
        ),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.buildDecompUnit, "build_decomp_unit", {
        project_directory: args.projectDirectory,
        ...(options.symbol !== undefined ? { symbol: options.symbol } : {}),
        ...(options.unit !== undefined ? { unit: options.unit } : {}),
        ...(options.relink !== undefined ? { relink: options.relink } : {}),
      }),
  });

  cli.command(CLI_COMMANDS.checkDecompUnit, {
    description:
      "Compares a recompiled candidate object against the baseline target slice using relocation-masked object diffing",
    args: z.object({
      projectDirectory: z
        .string()
        .describe("Matching decomp project root directory"),
      symbol: z.string().describe("Symbol/function name to diff"),
    }),
    options: z.object({
      unit: z
        .string()
        .optional()
        .describe("Optional translation unit path containing the symbol"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.checkDecompUnit, "check_decomp_unit", {
        project_directory: args.projectDirectory,
        symbol: args.symbol,
        ...(options.unit !== undefined ? { unit: options.unit } : {}),
      }),
  });

  cli.command(CLI_COMMANDS.permuteDecompSymbol, {
    description:
      "Optimizes candidate C source code toward a 100.0% match by applying iterative AST mutations and flag sweeps",
    args: z.object({
      projectDirectory: z
        .string()
        .describe("Matching decomp project root directory"),
      symbol: z.string().describe("Symbol/function name to optimize"),
    }),
    options: z.object({
      unit: z.string().optional().describe("Optional translation unit path"),
      maxIters: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Maximum mutation iterations to attempt"),
      strategy: z
        .enum(["hierarchical", "local_only"])
        .optional()
        .describe("Optimization search strategy"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.permuteDecompSymbol, "permute_decomp_symbol", {
        project_directory: args.projectDirectory,
        symbol: args.symbol,
        ...(options.unit !== undefined ? { unit: options.unit } : {}),
        ...(options.maxIters !== undefined
          ? { max_iters: options.maxIters }
          : {}),
        ...(options.strategy !== undefined
          ? { strategy: options.strategy }
          : {}),
      }),
  });

  cli.command(CLI_COMMANDS.syncDecompObligations, {
    description:
      "Synchronizes verified 100% matching decompilation symbols into REA's ReconstructionObligationLedger",
    args: z.object({
      projectDirectory: z
        .string()
        .describe("Matching decomp project root directory"),
    }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.syncDecompObligations, "sync_decomp_obligations", {
        project_directory: args.projectDirectory,
      }),
  });
};
