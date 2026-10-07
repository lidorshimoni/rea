import { stat } from "node:fs/promises";
import { execFileOutput } from "../process/ExecFileOutput.js";
import type { DecompDiffResult } from "../domain/decompilationAnalysis.js";

export interface ObjectDiffOptions {
  readonly unit: string;
  readonly symbol: string;
  readonly expectedPath: string;
  readonly compiledPath: string;
}

interface ParsedInstruction {
  readonly offset: number;
  readonly hexBytes: string[];
  readonly mnemonic: string;
  readonly operands: string;
  readonly relocations: string[];
}

/**
 * Built-in relocation-masked object differ utilizing `objdump -d -r`.
 * Provides 100% zero-dependency out-of-the-box object diffing without requiring
 * external Rust objdiff binaries.
 */
export class BuiltInObjectDiffer {
  async diff(options: ObjectDiffOptions): Promise<DecompDiffResult> {
    const { unit, symbol, expectedPath, compiledPath } = options;

    // 1. Verify existence of both files
    const expectedExists = await this.fileExists(expectedPath);
    if (!expectedExists) {
      return {
        unit,
        symbol,
        status: "missing_expected",
        match_percent: 0,
        similarity: 0,
        total_bytes: 0,
        matched_bytes: 0,
        sample_mismatches: [],
      };
    }

    const compiledExists = await this.fileExists(compiledPath);
    if (!compiledExists) {
      return {
        unit,
        symbol,
        status: "missing_compiled",
        match_percent: 0,
        similarity: 0,
        total_bytes: 0,
        matched_bytes: 0,
        sample_mismatches: [],
      };
    }

    // 2. Disassemble both object files using objdump
    const [expectedDump, compiledDump] = await Promise.all([
      this.disassemble(expectedPath),
      this.disassemble(compiledPath),
    ]);

    // 3. Extract instructions for the target symbol
    const expectedInsts = this.extractSymbolInstructions(expectedDump, symbol);
    const compiledInsts = this.extractSymbolInstructions(compiledDump, symbol);

    // 4. Perform relocation-masked comparison
    return this.compareInstructions(unit, symbol, expectedInsts, compiledInsts);
  }

  private async fileExists(path: string): Promise<boolean> {
    try {
      const s = await stat(path);
      return s.isFile();
    } catch {
      return false;
    }
  }

  private async disassemble(path: string): Promise<string> {
    try {
      const { stdout } = await execFileOutput("objdump", ["-d", "-r", path]);
      return stdout;
    } catch (err: unknown) {
      return "";
    }
  }

  private extractSymbolInstructions(
    dump: string,
    targetSymbol: string,
  ): ParsedInstruction[] {
    const lines = dump.split("\n");
    const instructions: ParsedInstruction[] = [];
    let inTarget = false;
    let fallbackAll = false;

    // Check if target symbol is present in dump
    const hasSymbol =
      targetSymbol !== "" &&
      lines.some(
        (line) =>
          line.includes(`<${targetSymbol}>:`) ||
          line.includes(`.text.${targetSymbol}`),
      );

    if (!hasSymbol) {
      // If symbol not explicitly named, collect all disassembly from the first text section
      fallbackAll = true;
    }

    let currentInst: ParsedInstruction | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;

      // Check for section boundary
      if (line.startsWith("Disassembly of section ")) {
        if (inTarget) {
          break; // Reached end of current symbol's section
        }
        continue;
      }

      // Check for symbol entry
      const symMatch = /^[0-9a-fA-F]+\s+<([^>]+)>:/.exec(line);
      if (symMatch) {
        const sym = symMatch[1]!;
        if (sym === targetSymbol || sym.startsWith(`${targetSymbol}@`)) {
          inTarget = true;
          continue;
        }

        if (inTarget) {
          // Internal labels within target symbol or local compiler labels (e.g. .L, $, +offset)
          if (
            sym.startsWith(`${targetSymbol}+`) ||
            sym.startsWith(".L") ||
            sym.startsWith("$")
          ) {
            continue;
          }
          // Hit the next distinct function symbol
          break;
        }
      }

      // Fallback check if symbol entry line is formatted without hex offset prefix
      if (!inTarget && line.includes(`<${targetSymbol}>:`)) {
        inTarget = true;
        continue;
      }

      if (!inTarget && !fallbackAll) {
        continue;
      }

      // Check for relocation line (tab indented with relocation type)
      if (
        line.includes("R_") ||
        line.includes("IMAGE_REL_") ||
        line.includes("OFFSET") ||
        line.includes("RELOC")
      ) {
        if (currentInst) {
          currentInst.relocations.push(line.trim());
        }
        continue;
      }

      // Parse instruction line:
      // Examples:
      // "   0:   48 83 ec 18             sub    $0x18,%rsp"
      // "   0:   b580                    push   {r7, lr}"
      // "   0:   e92d4800                push   {fp, lr}"
      // "0000000000000000 <calc_crc32> 48 83 ec 18 sub $0x18,%rsp"
      const match =
        /^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F\s]{2,})\s+([a-zA-Z0-9_.-]+)\s*(.*)$/.exec(
          line,
        );
      if (match) {
        const offset = Number.parseInt(match[1]!, 16);
        const hexStr = match[2]!.trim();
        const hexBytes = hexStr.match(/[0-9a-fA-F]{2}/g) ?? [];
        const mnemonic = match[3]!;
        const operands = (match[4] ?? "").split("#")[0]!.trim();

        currentInst = {
          offset,
          hexBytes: [...hexBytes],
          mnemonic,
          operands,
          relocations: [],
        };
        instructions.push(currentInst);
      } else if (currentInst) {
        // Check for instruction continuation line (hex bytes only without mnemonic)
        const contMatch = /^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F\s]{2,})\s*$/.exec(
          line,
        );
        if (contMatch) {
          const extraBytes =
            contMatch[2]!.trim().match(/[0-9a-fA-F]{2}/g) ?? [];
          if (extraBytes.length > 0) {
            (currentInst.hexBytes as string[]).push(...extraBytes);
          }
        }
      }
    }

    return instructions;
  }

  private compareInstructions(
    unit: string,
    symbol: string,
    expected: ParsedInstruction[],
    compiled: ParsedInstruction[],
  ): DecompDiffResult {
    const totalInsts = Math.max(expected.length, compiled.length);
    if (totalInsts === 0) {
      return {
        unit,
        symbol,
        status: "different",
        match_percent: 0,
        similarity: 0,
        total_bytes: 0,
        matched_bytes: 0,
        sample_mismatches: [],
      };
    }

    let totalBytes = 0;
    let matchedBytes = 0;
    const sampleMismatches: Array<{
      offset: string;
      expected_byte: string;
      compiled_byte: string;
    }> = [];
    const disassemblyDiff: NonNullable<DecompDiffResult["disassembly_diff"]> =
      [];

    for (let i = 0; i < totalInsts; i++) {
      const exp = expected[i];
      const cmp = compiled[i];

      const expBytes = exp?.hexBytes ?? [];
      const cmpBytes = cmp?.hexBytes ?? [];
      const instByteCount = Math.max(expBytes.length, cmpBytes.length);
      totalBytes += instByteCount;

      const hasReloc =
        (exp?.relocations.length ?? 0) > 0 ||
        (cmp?.relocations.length ?? 0) > 0;

      // Mnemonics match?
      const mnemonicMatch = exp && cmp && exp.mnemonic === cmp.mnemonic;
      let instBytesMatched = 0;

      for (let b = 0; b < instByteCount; b++) {
        const eb = expBytes[b];
        const cb = cmpBytes[b];

        if (hasReloc && b >= 1) {
          // Relocated displacement byte -> masked as match
          instBytesMatched++;
        } else if (eb === cb && eb !== undefined) {
          instBytesMatched++;
        } else {
          if (sampleMismatches.length < 10) {
            const byteOffset = (exp?.offset ?? cmp?.offset ?? 0) + b;
            sampleMismatches.push({
              offset: `0x${byteOffset.toString(16).padStart(4, "0")}`,
              expected_byte: eb ?? "??",
              compiled_byte: cb ?? "??",
            });
          }
        }
      }

      matchedBytes += instBytesMatched;
      const isInstMatch = Boolean(
        mnemonicMatch &&
        (instBytesMatched === instByteCount ||
          (hasReloc && exp?.mnemonic === cmp?.mnemonic)),
      );

      const addrOffset = exp?.offset ?? cmp?.offset ?? i * 4;
      disassemblyDiff.push({
        address: `0x${addrOffset.toString(16).padStart(4, "0")}`,
        expected_mnemonic: exp?.mnemonic,
        expected_operands: exp?.operands,
        compiled_mnemonic: cmp?.mnemonic,
        compiled_operands: cmp?.operands,
        matched: isInstMatch,
      });
    }

    const similarity =
      totalBytes > 0 ? Math.min(1, matchedBytes / totalBytes) : 0;
    const matchPercent = Math.round(similarity * 10000) / 100;
    const isMatched =
      similarity === 1 ||
      (disassemblyDiff.length > 0 &&
        disassemblyDiff.every((d) => d.matched) &&
        sampleMismatches.length === 0);

    return {
      unit,
      symbol,
      status: isMatched ? "matched" : "different",
      match_percent: isMatched ? 100 : matchPercent,
      similarity: isMatched ? 1 : similarity,
      total_bytes: totalBytes,
      matched_bytes: isMatched ? totalBytes : matchedBytes,
      sample_mismatches: isMatched ? [] : sampleMismatches,
      disassembly_diff: disassemblyDiff,
    };
  }
}
