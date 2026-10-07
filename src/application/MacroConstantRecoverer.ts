import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  DEFAULT_MAGIC_CONSTANTS,
  type MagicConstantEntry,
} from "../data/constants/defaultConstants.js";
import type { DecompRecoverMacrosResult } from "../domain/decompilationAnalysis.js";

export interface RecoveredMacro {
  readonly name: string;
  readonly value: string;
  readonly category: string;
  readonly occurrences: number;
  readonly description?: string | undefined;
}

export type MacroRecoveryResult = DecompRecoverMacrosResult;

/**
 * Replaces recovered magic constants in C source code while preserving string literals and comments.
 */
export function replaceConstantsInCSource(
  content: string,
  macros: readonly RecoveredMacro[],
): { content: string; modified: boolean } {
  const tokenRegex =
    /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*)/g;
  const parts = content.split(tokenRegex);
  let anyModified = false;

  for (let i = 0; i < parts.length; i++) {
    // Even indices are code; odd indices are string literals, char literals, or comments
    if (i % 2 === 1) {
      continue;
    }

    let codeChunk = parts[i]!;
    for (const macro of macros) {
      const hexDigits = macro.value.replace(/^0x/i, "");
      const hexClean = hexDigits.replace(/^0+/, "") || "0";
      const hexRegex = new RegExp(`\\b0x0*${hexClean}[uUlL]*\\b`, "gi");
      if (hexRegex.test(codeChunk)) {
        codeChunk = codeChunk.replace(hexRegex, macro.name);
        anyModified = true;
      }
    }
    parts[i] = codeChunk;
  }

  let newContent = parts.join("");
  if (anyModified) {
    if (
      !newContent.includes('"macros.h"') &&
      !newContent.includes("<macros.h>")
    ) {
      newContent = `#include "macros.h"\n${newContent}`;
    }
  }

  return { content: newContent, modified: anyModified };
}

export class MacroConstantRecoverer {
  async recover(options: {
    readonly projectDirectory: string;
    readonly constantsPath?: string | undefined;
    readonly targetSourcePath?: string | undefined;
  }): Promise<DecompRecoverMacrosResult> {
    const projectDir = resolve(options.projectDirectory);

    // 1. Load constants database
    const constants = await this.loadConstants(options.constantsPath);

    // 2. Collect files to scan
    const filesToScan: string[] = [];
    if (options.targetSourcePath) {
      filesToScan.push(resolve(projectDir, options.targetSourcePath));
    } else {
      await this.collectSourceFiles(join(projectDir, "src"), filesToScan);
      await this.collectSourceFiles(join(projectDir, "asm"), filesToScan);
    }

    // 3. Scan for magic constants
    const occurrenceMap = new Map<string, number>();

    for (const filePath of filesToScan) {
      try {
        const content = await readFile(filePath, "utf8");
        for (const entry of constants) {
          const count = this.countOccurrences(content, entry);
          if (count > 0) {
            occurrenceMap.set(
              entry.name,
              (occurrenceMap.get(entry.name) ?? 0) + count,
            );
          }
        }
      } catch {
        // file could not be read, skip
      }
    }

    // Also check target binary if few or none found in source/asm
    const targetBinPath = join(projectDir, "target.bin");
    try {
      const binBytes = await readFile(targetBinPath);
      for (const entry of constants) {
        if (!occurrenceMap.has(entry.name) && entry.value > 255) {
          if (this.bufferContainsUint32(binBytes, entry.value)) {
            occurrenceMap.set(entry.name, 1);
          }
        }
      }
    } catch {
      // ignore
    }

    const recoveredMacros: RecoveredMacro[] = [];
    for (const entry of constants) {
      const occurrences = occurrenceMap.get(entry.name);
      if (occurrences !== undefined && occurrences > 0) {
        recoveredMacros.push({
          name: entry.name,
          value: entry.hex,
          category: entry.category,
          occurrences,
          description: entry.description,
        });
      }
    }

    // 4. Emit include/macros.h
    const headerRelPath = "include/macros.h";
    const headerFullPath = join(projectDir, headerRelPath);
    await mkdir(join(projectDir, "include"), { recursive: true });
    await this.generateMacrosHeader(headerFullPath, recoveredMacros);

    // 5. Replace recovered constants in scanned C source files and add #include "macros.h"
    for (const filePath of filesToScan) {
      if (!filePath.endsWith(".c")) continue;
      try {
        const content = await readFile(filePath, "utf8");
        const { content: replacedContent, modified } =
          replaceConstantsInCSource(content, recoveredMacros);

        if (modified) {
          await writeFile(filePath, replacedContent, "utf8");
        }
      } catch {
        // file cannot be updated, ignore
      }
    }

    return {
      total_macros: recoveredMacros.length,
      header_path: headerRelPath,
      macros_recovered: recoveredMacros,
    };
  }

  private async loadConstants(
    customPath?: string,
  ): Promise<readonly MagicConstantEntry[]> {
    if (customPath) {
      try {
        const raw = await readFile(resolve(customPath), "utf8");
        return JSON.parse(raw) as MagicConstantEntry[];
      } catch {
        // fallback
      }
    }
    return DEFAULT_MAGIC_CONSTANTS;
  }

  private async collectSourceFiles(
    dir: string,
    outList: string[],
  ): Promise<void> {
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          await this.collectSourceFiles(fullPath, outList);
        } else if (
          entry.isFile() &&
          (entry.name.endsWith(".c") ||
            entry.name.endsWith(".h") ||
            entry.name.endsWith(".s"))
        ) {
          outList.push(fullPath);
        }
      }
    } catch {
      // Directory doesn't exist yet
    }
  }

  private countOccurrences(content: string, entry: MagicConstantEntry): number {
    // Strip string literals and comments so occurrences are only counted in actual code
    const codeOnly = content.replace(
      /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*)/g,
      " ",
    );
    let count = 0;
    const lowerContent = codeOnly.toLowerCase();

    // Check hex without leading 0x e.g. edb88320
    const hexClean = entry.hex.replace(/^0x0*/i, "").toLowerCase() || "0";
    const hexWithPrefix = entry.hex.toLowerCase();

    if (hexClean.length >= 4) {
      const regex = new RegExp(`\\b(?:0x)?0*${hexClean}[uUlL]*\\b`, "gi");
      const matches = codeOnly.match(regex);
      if (matches) count += matches.length;
    } else {
      // For short numbers (like errnos 1, 2, 22), match explicit hex or macro name
      if (lowerContent.includes(hexWithPrefix)) count++;
      if (codeOnly.includes(entry.name)) count++;
    }

    // Check decimal representation for non-trivial constants (> 255)
    if (entry.value > 255) {
      const decStr = entry.value.toString(10);
      const decRegex = new RegExp(`\\b${decStr}[uUlL]*\\b`, "g");
      const decMatches = codeOnly.match(decRegex);
      if (decMatches) count += decMatches.length;

      // Check signed representation (e.g. -305419896 for 0xedb88320)
      const signedVal = (entry.value | 0).toString(10);
      if (signedVal.startsWith("-")) {
        const signedRegex = new RegExp(`\\b${signedVal}[uUlL]*\\b`, "g");
        const signedMatches = codeOnly.match(signedRegex);
        if (signedMatches) count += signedMatches.length;
      }
    }

    return count;
  }

  private bufferContainsUint32(buffer: Buffer, value: number): boolean {
    const le = Buffer.alloc(4);
    le.writeUInt32LE(value >>> 0, 0);
    if (buffer.includes(le)) return true;

    const be = Buffer.alloc(4);
    be.writeUInt32BE(value >>> 0, 0);
    return buffer.includes(be);
  }

  private async generateMacrosHeader(
    headerPath: string,
    macros: readonly RecoveredMacro[],
  ): Promise<void> {
    const lines: string[] = [
      "#ifndef DECOMP_MACROS_H",
      "#define DECOMP_MACROS_H",
      "",
      "/* Deterministically recovered magic constants and macros */",
      "",
    ];

    const categories = new Set(macros.map((m) => m.category));
    for (const cat of categories) {
      lines.push(`/* --- ${cat.toUpperCase()} --- */`);
      for (const m of macros.filter((m) => m.category === cat)) {
        const descComment = m.description ? ` /* ${m.description} */` : "";
        lines.push(`#define ${m.name} ${m.value}${descComment}`);
      }
      lines.push("");
    }

    lines.push("#endif /* DECOMP_MACROS_H */", "");
    await writeFile(headerPath, lines.join("\n"), "utf8");
  }
}
