import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  DEFAULT_LIBRARY_SIGNATURES,
  type LibrarySignatureEntry,
} from "../data/signatures/defaultSignatures.js";
import type { DecompDetectLibrariesResult } from "../domain/decompilationAnalysis.js";

export interface DetectedLibrary {
  readonly library: string;
  readonly category: string;
  readonly version?: string | undefined;
  readonly confidence: number;
  readonly functions_matched: string[];
  readonly matched_strings: string[];
}

export interface IdentifiedSymbol {
  readonly address: string;
  readonly symbol: string;
  readonly library: string;
  readonly confidence: number;
}

export type LibraryDetectionResult = DecompDetectLibrariesResult;

/**
 * Matches a binary buffer against an opcode mask pattern with '??' or '?' wildcards.
 * Pattern format: space-delimited hex bytes, e.g. "55 48 89 e5 ?? ??"
 */
export function matchBytePattern(buffer: Buffer, pattern: string): boolean {
  const tokens = pattern.trim().split(/\s+/);
  if (tokens.length === 0 || tokens[0] === "") return false;
  const patternBytes: Array<number | null> = tokens.map((t) => {
    if (t === "??" || t === "?") return null;
    const val = parseInt(t, 16);
    return isNaN(val) ? null : val;
  });
  const pLen = patternBytes.length;
  if (pLen === 0 || buffer.length < pLen) return false;

  const maxStart = buffer.length - pLen;
  for (let i = 0; i <= maxStart; i++) {
    let matched = true;
    for (let j = 0; j < pLen; j++) {
      const pByte = patternBytes[j];
      if (pByte !== null && buffer[i + j] !== pByte) {
        matched = false;
        break;
      }
    }
    if (matched) return true;
  }
  return false;
}

export class LibrarySignatureDetector {
  async detect(options: {
    readonly projectDirectory: string;
    readonly binaryPath?: string | undefined;
    readonly signaturesPath?: string | undefined;
    readonly useLlmFallback?: boolean | undefined;
  }): Promise<DecompDetectLibrariesResult> {
    const projectDir = resolve(options.projectDirectory);
    const targetBinaryPath = options.binaryPath
      ? resolve(options.binaryPath)
      : join(projectDir, "target.bin");

    // 1. Load signatures database (custom override or default in-tree)
    const signatures = await this.loadSignatures(options.signaturesPath);

    // 2. Read target binary bytes
    let binaryBytes: Buffer;
    try {
      binaryBytes = await readFile(targetBinaryPath);
    } catch {
      binaryBytes = Buffer.alloc(0);
    }

    // 3. Extract strings from binary
    const extractedStrings = this.extractStrings(binaryBytes);

    // 4. Read slices or assembly stubs if present
    const sliceContents = await this.loadProjectSlices(projectDir);

    const detectedLibraries: DetectedLibrary[] = [];
    const identifiedSymbols: IdentifiedSymbol[] = [];

    // 5. Match signatures
    for (const entry of signatures) {
      const matchedStrings: string[] = [];
      for (const sigStr of entry.strings) {
        if (extractedStrings.some((s) => s.includes(sigStr))) {
          matchedStrings.push(sigStr);
        }
      }

      const matchedFunctions: string[] = [];

      for (const func of entry.functions) {
        let funcMatched = false;

        // Check opcode pattern mask in target binary
        if (func.opcodePattern && binaryBytes.length > 0) {
          if (matchBytePattern(binaryBytes, func.opcodePattern)) {
            funcMatched = true;
            if (!identifiedSymbols.some((s) => s.symbol === func.name)) {
              identifiedSymbols.push({
                address: "pattern_match",
                symbol: func.name,
                library: entry.library,
                confidence: 0.9,
              });
            }
          }
        }

        // Check distinctive constants in binary
        if (func.distinctiveConstants && func.distinctiveConstants.length > 0) {
          for (const constant of func.distinctiveConstants) {
            if (this.bufferContainsUint32(binaryBytes, constant)) {
              funcMatched = true;
              break;
            }
          }
        }

        // Check in sliced assembly / C files
        for (const [sliceName, content] of sliceContents.entries()) {
          if (sliceName.includes(func.name) || content.includes(func.name)) {
            funcMatched = true;
            identifiedSymbols.push({
              address: "auto",
              symbol: func.name,
              library: entry.library,
              confidence: 0.95,
            });
            break;
          }

          if (
            func.distinctiveConstants &&
            func.distinctiveConstants.length > 0
          ) {
            for (const c of func.distinctiveConstants) {
              const hexVal = c.toString(16);
              if (content.toLowerCase().includes(hexVal)) {
                funcMatched = true;
                identifiedSymbols.push({
                  address: sliceName,
                  symbol: func.name,
                  library: entry.library,
                  confidence: 0.85,
                });
                break;
              }
            }
          }
        }

        if (funcMatched && !matchedFunctions.includes(func.name)) {
          matchedFunctions.push(func.name);
        }
      }

      // Calculate confidence
      let confidence = 0;
      if (matchedStrings.length > 0 && matchedFunctions.length > 0) {
        confidence = Math.min(
          1.0,
          0.6 +
            0.25 * (matchedStrings.length / entry.strings.length) +
            0.15 * (matchedFunctions.length / entry.functions.length),
        );
      } else if (matchedStrings.length >= 2) {
        confidence = Math.min(
          0.9,
          0.5 + 0.3 * (matchedStrings.length / entry.strings.length),
        );
      } else if (matchedStrings.length === 1) {
        confidence = 0.45;
      } else if (matchedFunctions.length > 0) {
        confidence = 0.7;
      }

      if (confidence > 0.4) {
        detectedLibraries.push({
          library: entry.library,
          category: entry.category,
          confidence: Number(confidence.toFixed(2)),
          functions_matched: matchedFunctions,
          matched_strings: matchedStrings,
        });
      }
    }

    // 6. Optional LLM fallback for unrecognized logic (offline-safe)
    if (options.useLlmFallback) {
      // Offline fallback: when no external LLM is configured, heuristic pattern analysis is performed safely
      this.applyOfflineHeuristicFallback(sliceContents, identifiedSymbols);
    }

    // 7. Generate library header into project
    await this.generateLibraryHeader(
      projectDir,
      detectedLibraries,
      identifiedSymbols,
    );

    return {
      total_libraries_detected: detectedLibraries.length,
      total_symbols_identified: identifiedSymbols.length,
      detected_libraries: detectedLibraries,
      identified_symbols: identifiedSymbols,
    };
  }

  private async loadSignatures(
    customPath?: string,
  ): Promise<readonly LibrarySignatureEntry[]> {
    if (customPath) {
      try {
        const raw = await readFile(resolve(customPath), "utf8");
        return JSON.parse(raw) as LibrarySignatureEntry[];
      } catch {
        // Fall back to default
      }
    }
    return DEFAULT_LIBRARY_SIGNATURES;
  }

  private extractStrings(buffer: Buffer, minLen = 4): string[] {
    const strings: string[] = [];
    let current: number[] = [];

    for (let i = 0; i < buffer.length; i++) {
      const b = buffer[i]!;
      if (b >= 32 && b <= 126) {
        current.push(b);
      } else {
        if (current.length >= minLen) {
          strings.push(Buffer.from(current).toString("utf8"));
        }
        current = [];
      }
    }
    if (current.length >= minLen) {
      strings.push(Buffer.from(current).toString("utf8"));
    }
    return strings;
  }

  private bufferContainsUint32(buffer: Buffer, value: number): boolean {
    const le = Buffer.alloc(4);
    le.writeUInt32LE(value >>> 0, 0);
    if (buffer.includes(le)) return true;

    const be = Buffer.alloc(4);
    be.writeUInt32BE(value >>> 0, 0);
    return buffer.includes(be);
  }

  private async loadProjectSlices(
    projectDir: string,
  ): Promise<Map<string, string>> {
    const map = new Map<string, string>();
    try {
      const raw = await readFile(join(projectDir, "slices.json"), "utf8");
      const manifest = JSON.parse(raw) as {
        slices: Array<{ name: string; asm_file: string }>;
      };
      for (const slice of manifest.slices) {
        try {
          const asmContent = await readFile(
            join(projectDir, slice.asm_file),
            "utf8",
          );
          map.set(slice.name, asmContent);
        } catch {
          // ignore missing
        }
      }
    } catch {
      // No slices.json
    }
    return map;
  }

  private applyOfflineHeuristicFallback(
    slices: Map<string, string>,
    symbols: IdentifiedSymbol[],
  ): void {
    for (const [name, content] of slices.entries()) {
      if (symbols.some((s) => s.symbol === name)) continue;
      // Heuristic detection: CRC loop patterns
      if (
        content.includes("shr") &&
        content.includes("xor") &&
        content.includes("32")
      ) {
        symbols.push({
          address: name,
          symbol: `${name}_crc32_candidate`,
          library: "zlib (heuristic)",
          confidence: 0.65,
        });
      }
    }
  }

  private async generateLibraryHeader(
    projectDir: string,
    libraries: readonly DetectedLibrary[],
    symbols: readonly IdentifiedSymbol[],
  ): Promise<void> {
    const includeDir = join(projectDir, "include");
    await mkdir(includeDir, { recursive: true });

    const lines: string[] = [
      "#ifndef DECOMP_LIBRARIES_H",
      "#define DECOMP_LIBRARIES_H",
      "",
      "/* Statically linked third-party library detections */",
      "",
    ];

    for (const lib of libraries) {
      lines.push(
        `/* Detected library: ${lib.library} (${lib.category}, confidence: ${lib.confidence * 100}%) */`,
      );
      lines.push(`#define HAVE_LIB_${lib.library.toUpperCase()} 1`);
      lines.push(`#define REA_LIBRARY_${lib.library.toUpperCase()} 1`);
      if (lib.functions_matched.length > 0) {
        lines.push(
          `/* Matched functions: ${lib.functions_matched.join(", ")} */`,
        );
      }
      lines.push("");
    }

    if (symbols.length > 0) {
      lines.push("/* Identified library symbols */");
      for (const sym of symbols) {
        lines.push(
          `/* Symbol: ${sym.symbol} -> ${sym.library} (${sym.confidence * 100}%) */`,
        );
      }
      lines.push("");
    }

    lines.push("#endif /* DECOMP_LIBRARIES_H */", "");
    await writeFile(join(includeDir, "libraries.h"), lines.join("\n"), "utf8");
  }
}
