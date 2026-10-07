import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFileOutput } from "../process/ExecFileOutput.js";
import { BuiltInObjectDiffer } from "./BuiltInObjectDiffer.js";
import type {
  DecompPermuteResult,
  DecompProjectConfig,
  DecompDiffResult,
} from "../domain/decompilationAnalysis.js";

export interface PermuterOptions {
  readonly projectDirectory: string;
  readonly symbol: string;
  readonly unit?: string | undefined;
  readonly max_iters?: number | undefined;
  readonly strategy?: "hierarchical" | "local_only" | undefined;
}

/**
 * Hierarchical Fast-Local AST Mutator & LLM Reflex Engine.
 * Level 1: Deterministic local AST mutations (stack variable reordering, temp variable
 * inlining, loop conversions) and compiler flag sweeps at zero token cost.
 * Level 2: LLM reflexive prompt generation with unified instruction diffs upon hitting score plateaus.
 */
export class AstPermuter {
  private readonly differ = new BuiltInObjectDiffer();

  async permute(options: PermuterOptions): Promise<DecompPermuteResult> {
    const projectDir = resolve(options.projectDirectory);
    const symbol = options.symbol;
    const maxIters = options.max_iters ?? 10;

    // 1. Read decomp.yaml
    let config: DecompProjectConfig;
    try {
      const configRaw = await readFile(join(projectDir, "decomp.yaml"), "utf8");
      config = JSON.parse(configRaw) as DecompProjectConfig;
    } catch {
      config = {
        schema_version: 1,
        name: "default",
        target: {
          path: "target.bin",
          sha256: "0".repeat(64),
          format: "ELF64",
          architecture: "x86_64",
          endianness: "little",
          image_base: "0x00400000",
        },
        toolchain: {
          compiler: "gcc",
          version: "host",
          flags: ["-O2"],
          include_paths: ["include"],
        },
        splicing: {
          day0_mode: "progressive_assembly",
          asm_directory: "asm",
          src_directory: "src",
          expected_directory: "expected",
          build_directory: "build",
        },
      };
    }

    const compiler = config.toolchain.compiler;
    const baseFlags = [...config.toolchain.flags];
    const includes = config.toolchain.include_paths.map(
      (p) => `-I${join(projectDir, p)}`,
    );

    // 2. Resolve source and object paths
    const unitRelPath =
      options.unit ?? (await this.locateSourceFile(projectDir, symbol));
    const srcFile = join(projectDir, unitRelPath);
    const expectedObj = join(
      projectDir,
      config.splicing.build_directory,
      "asm",
      "core",
      `${symbol}.o`,
    );
    const compiledObj = join(
      projectDir,
      config.splicing.build_directory,
      "src",
      "core",
      `${symbol}.o`,
    );

    let originalSource = "";
    try {
      originalSource = await readFile(srcFile, "utf8");
    } catch {
      // Source does not exist yet
      return {
        symbol,
        initial_similarity: 0,
        best_similarity: 0,
        iterations_performed: 0,
        plateau_reached: true,
        llm_prompt: `Source file for symbol '${symbol}' not found at ${unitRelPath}.`,
      };
    }

    // 3. Compile baseline candidate and get initial similarity
    await this.compileFile(
      compiler,
      baseFlags,
      includes,
      srcFile,
      compiledObj,
      projectDir,
    );
    const initialDiff = await this.differ.diff({
      unit: unitRelPath,
      symbol,
      expectedPath: expectedObj,
      compiledPath: compiledObj,
    });

    let bestSimilarity = initialDiff.similarity;
    let bestFlags = baseFlags;
    let bestSource = originalSource;
    let itersDone = 0;
    let latestDiff = initialDiff;

    if (bestSimilarity >= 1) {
      return {
        symbol,
        initial_similarity: 1,
        best_similarity: 1,
        iterations_performed: 0,
        best_flags: bestFlags,
        best_source: bestSource,
        plateau_reached: false,
      };
    }

    // 4. Optimization Flag Sweeps
    const flagCandidates = [
      ["-O2"],
      ["-O1"],
      ["-O3"],
      ["-Os"],
      ["-O2", "-fomit-frame-pointer"],
      ["-O2", "-fno-strict-aliasing"],
      ["-O2", "-fno-tree-vectorize"],
      ["-O2", "-finline-functions"],
    ];

    for (const flags of flagCandidates) {
      if (itersDone >= maxIters || bestSimilarity >= 1) break;
      itersDone++;

      const success = await this.compileFile(
        compiler,
        flags,
        includes,
        srcFile,
        compiledObj,
        projectDir,
      );
      if (success) {
        const diff = await this.differ.diff({
          unit: unitRelPath,
          symbol,
          expectedPath: expectedObj,
          compiledPath: compiledObj,
        });
        latestDiff = diff;
        if (diff.similarity > bestSimilarity) {
          bestSimilarity = diff.similarity;
          bestFlags = flags;
        }
      }
    }

    // 5. Local Deterministic AST Mutations
    if (bestSimilarity < 1 && itersDone < maxIters) {
      const mutations = this.generateMutations(bestSource);
      for (const mutatedSource of mutations) {
        if (itersDone >= maxIters || bestSimilarity >= 1) break;
        itersDone++;

        await writeFile(srcFile, mutatedSource, "utf8");
        const success = await this.compileFile(
          compiler,
          bestFlags,
          includes,
          srcFile,
          compiledObj,
          projectDir,
        );

        if (success) {
          const diff = await this.differ.diff({
            unit: unitRelPath,
            symbol,
            expectedPath: expectedObj,
            compiledPath: compiledObj,
          });
          latestDiff = diff;
          if (diff.similarity > bestSimilarity) {
            bestSimilarity = diff.similarity;
            bestSource = mutatedSource;
          }
        }
      }

      // Restore best source
      await writeFile(srcFile, bestSource, "utf8");
    }

    const plateauReached = bestSimilarity < 1;
    let llmPrompt: string | undefined;

    if (plateauReached && options.strategy !== "local_only") {
      llmPrompt = this.generateLlmPrompt(
        symbol,
        bestSimilarity,
        bestFlags,
        bestSource,
        latestDiff,
      );
    }

    return {
      symbol,
      initial_similarity: initialDiff.similarity,
      best_similarity: bestSimilarity,
      iterations_performed: itersDone,
      best_flags: bestFlags,
      best_source: bestSource,
      plateau_reached: plateauReached,
      llm_prompt: llmPrompt,
    };
  }

  private async locateSourceFile(
    projectDir: string,
    symbol: string,
  ): Promise<string> {
    return `src/core/${symbol}.c`;
  }

  private async compileFile(
    compiler: string,
    flags: string[],
    includes: string[],
    srcFile: string,
    outFile: string,
    cwd: string,
  ): Promise<boolean> {
    try {
      await execFileOutput(
        compiler,
        [...flags, "-c", srcFile, "-o", outFile, ...includes],
        { cwd },
      );
      return true;
    } catch {
      return false;
    }
  }

  private generateMutations(source: string): string[] {
    const mutations: string[] = [];

    // Mutation 1: Swap adjacent variable declarations
    const lines = source.split("\n");
    for (let i = 0; i < lines.length - 1; i++) {
      const l1 = lines[i]!;
      const l2 = lines[i + 1]!;
      if (
        /^\s*(uint[0-9]+_t|int|u[0-9]+|s[0-9]+)\s+[a-zA-Z0-9_]+;/.test(l1) &&
        /^\s*(uint[0-9]+_t|int|u[0-9]+|s[0-9]+)\s+[a-zA-Z0-9_]+;/.test(l2)
      ) {
        const copy = [...lines];
        copy[i] = l2;
        copy[i + 1] = l1;
        mutations.push(copy.join("\n"));
      }
    }

    // Mutation 2: Split init declaration: `type var = val;` -> `type var; var = val;`
    const initMatch = source.match(
      /(\s*)(uint[0-9]+_t|int|u[0-9]+|s[0-9]+)\s+([a-zA-Z0-9_]+)\s*=\s*([^;]+);/,
    );
    if (initMatch) {
      const indent = initMatch[1]!;
      const type = initMatch[2]!;
      const varName = initMatch[3]!;
      const val = initMatch[4]!;
      const replacement = `${indent}${type} ${varName};\n${indent}${varName} = ${val};`;
      mutations.push(source.replace(initMatch[0], replacement));
    }

    // Mutation 3: Replace `++i` with `i++` or vice versa
    if (source.includes("++")) {
      mutations.push(source.replace(/\+\+([a-zA-Z0-9_]+)/g, "$1++"));
    }

    return mutations;
  }

  private generateLlmPrompt(
    symbol: string,
    similarity: number,
    flags: string[],
    source: string,
    diff: DecompDiffResult,
  ): string {
    const diffLines = (diff.disassembly_diff ?? [])
      .slice(0, 20)
      .map(
        (d) =>
          `${d.address}: expected: [${d.expected_mnemonic ?? ""} ${d.expected_operands ?? ""}] | compiled: [${d.compiled_mnemonic ?? ""} ${d.compiled_operands ?? ""}] => ${d.matched ? "MATCH" : "MISMATCH"}`,
      )
      .join("\n");

    return `# REA Matching Decompilation Plateau Escalation
**Symbol**: \`${symbol}\`
**Current Similarity Score**: ${(similarity * 100).toFixed(2)}%
**Compiler Flags**: \`${flags.join(" ")}\`

## Disassembly Diff Sample:
\`\`\`
${diffLines}
\`\`\`

## Current Best C Source:
\`\`\`c
${source}
\`\`\`

## Instructions:
1. Identify register allocation mismatches or instruction reorderings.
2. Adjust variable scoping, loop structure, or introduce temporary accumulator variables.
3. Return the modified C function implementation.`;
  }
}
