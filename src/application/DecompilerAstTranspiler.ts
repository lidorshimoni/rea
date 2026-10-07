/**
 * Decompiler AST / Pseudocode Transpiler (C99 De-Synthesizer).
 * Cleans synthetic decompiler artifacts (undefined4, DAT_*, register spills, warning headers)
 * into clean, compilable C99 code.
 */
export class DecompilerAstTranspiler {
  /**
   * Transpile raw decompiler pseudocode into valid C99.
   */
  transpile(
    rawPseudocode: string,
    options: { functionName?: string } = {},
  ): string {
    let code = rawPseudocode;

    // 1. Strip WARNING comment blocks commonly produced by Ghidra/HexRays
    code = code.replace(/\/\*\s*WARNING:[\s\S]*?\*\//g, "");

    // 2. Replace pointer casts and decompiler idioms
    code = code.replace(/\((?:code|void)\s*\*\)\s*0x?0\b/g, "NULL");

    // 3. Replace Ghidra/IDA synthetic integer and primitive types
    code = code
      .replace(/\bundefined8\b/g, "uint64_t")
      .replace(/\bulonglong\b/g, "uint64_t")
      .replace(/\bqword\b/g, "uint64_t")
      .replace(/\bundefined4\b/g, "uint32_t")
      .replace(/\bdword\b/g, "uint32_t")
      .replace(/\bundefined2\b/g, "uint16_t")
      .replace(/\bushort\b/g, "uint16_t")
      .replace(/\bword\b/g, "uint16_t")
      .replace(/\bundefined1\b/g, "uint8_t")
      .replace(/\buchar\b/g, "uint8_t")
      .replace(/\bbyte\b/g, "uint8_t")
      .replace(/\bundefined\b/g, "uint8_t")
      .replace(/\bcode\b/g, "void");

    // 4. Transpile memory references DAT_0800... -> REG32(0x0800...)
    code = code.replace(
      /\b_?DAT_([0-9a-fA-F]+)\b/g,
      "(*(volatile uint32_t *)0x$1)",
    );

    // 5. Clean up register spill parameter annotations (e.g. in_register_00000014)
    code = code.replace(/\bin_register_[0-9a-fA-F]+\b/g, "reg_param");

    // 6. Ensure standard modular header includes
    const headers = [
      '#include "types.h"',
      '#include "hardware.h"',
      '#include "globals.h"',
      "",
    ].join("\n");

    const trimmed = code.trim();
    if (!trimmed.includes("types.h")) {
      return `${headers}\n${trimmed}\n`;
    }

    return `${trimmed}\n`;
  }
}
