import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve, relative } from "node:path";
import { execFileOutput } from "../process/ExecFileOutput.js";
import { createAirgapEnv } from "../process/AirgapEnvironment.js";
import type { DecompEnrichSymbolsResult } from "../domain/decompilationAnalysis.js";

export interface ExtractedParameter {
  readonly name: string;
  readonly type: string;
}

export interface ExtractedVariable {
  readonly name: string;
  readonly type: string;
}

export interface ExtractedFunction {
  readonly name: string;
  readonly return_type: string;
  readonly parameters: ExtractedParameter[];
  readonly local_variables: ExtractedVariable[];
  readonly address?: string | undefined;
  readonly size?: number | undefined;
}

export interface ExtractedMember {
  readonly name: string;
  readonly type: string;
  readonly offset?: number | undefined;
}

export interface ExtractedType {
  readonly name: string;
  readonly kind: "struct" | "union" | "enum" | "typedef";
  readonly size?: number | undefined;
  readonly members?: ExtractedMember[] | undefined;
}

export type DwarfEnrichmentResult = DecompEnrichSymbolsResult;
export const normalizeDwarfOffset = (raw: string): string =>
  raw
    .trim()
    .toLowerCase()
    .replace(/^<0x?([0-9a-fA-F]+)>$/, "$1")
    .replace(/^0x/, "")
    .replace(/^0+/, "") || "0";

interface RawDie {
  readonly offset: string;
  readonly level: number;
  readonly tag: string;
  readonly attributes: Map<string, string>;
  readonly children: RawDie[];
}

/**
 * Extracts exact function signatures, parameters, local variables,
 * and struct/type definitions from DWARF debug info using local host tools.
 * 100% airgapped: sanitizes environment so debuginfod/symbol-servers are never queried.
 */
export class DwarfSymbolExtractor {
  async extract(options: {
    readonly binaryPath: string;
    readonly projectDirectory: string;
    readonly outputHeaderDir?: string | undefined;
  }): Promise<DecompEnrichSymbolsResult> {
    const binaryPath = resolve(options.binaryPath);
    const projectDir = resolve(options.projectDirectory);

    const dwarfOutput = await this.readDwarfDebugInfo(binaryPath);
    if (!dwarfOutput || dwarfOutput.trim().length === 0) {
      return {
        total_functions_recovered: 0,
        total_types_recovered: 0,
        functions: [],
        types: [],
        header_files_generated: [],
      };
    }

    const dies = this.parseDwarfOutput(dwarfOutput);
    const dieMap = new Map<string, RawDie>();
    for (const die of dies) {
      dieMap.set(normalizeDwarfOffset(die.offset), die);
    }

    const resolveType = (typeOffset: string | undefined, depth = 0): string => {
      if (!typeOffset || depth > 10) return "void";
      const cleanOffset = normalizeDwarfOffset(typeOffset);
      const targetDie = dieMap.get(cleanOffset);
      if (!targetDie) return "void";

      const nameAttr = targetDie.attributes.get("DW_AT_name");
      const targetRef = targetDie.attributes.get("DW_AT_type");

      switch (targetDie.tag) {
        case "DW_TAG_base_type":
          return nameAttr ?? "int";
        case "DW_TAG_typedef":
          return nameAttr ?? resolveType(targetRef, depth + 1);
        case "DW_TAG_pointer_type": {
          if (!targetRef) return "void *";
          const subType = resolveType(targetRef, depth + 1);
          return subType.endsWith("*") ? `${subType}*` : `${subType} *`;
        }
        case "DW_TAG_const_type": {
          if (!targetRef) return "const void";
          const subType = resolveType(targetRef, depth + 1);
          return `const ${subType}`;
        }
        case "DW_TAG_volatile_type": {
          if (!targetRef) return "volatile void";
          const subType = resolveType(targetRef, depth + 1);
          return `volatile ${subType}`;
        }
        case "DW_TAG_structure_type":
          return `struct ${nameAttr ?? "unnamed"}`;
        case "DW_TAG_union_type":
          return `union ${nameAttr ?? "unnamed"}`;
        case "DW_TAG_enumeration_type":
          return `enum ${nameAttr ?? "unnamed"}`;
        case "DW_TAG_array_type": {
          const subType = resolveType(targetRef, depth + 1);
          return `${subType}[]`;
        }
        default:
          return nameAttr ?? "void";
      }
    };

    const functions: ExtractedFunction[] = [];
    const types: ExtractedType[] = [];

    for (const die of dies) {
      // 1. Structure types
      if (
        die.tag === "DW_TAG_structure_type" ||
        die.tag === "DW_TAG_union_type"
      ) {
        const structName = die.attributes.get("DW_AT_name");
        if (structName) {
          const members: ExtractedMember[] = [];
          for (const child of die.children) {
            if (child.tag === "DW_TAG_member") {
              const memberName = child.attributes.get("DW_AT_name");
              const memberTypeRef = child.attributes.get("DW_AT_type");
              const memberLoc = child.attributes.get(
                "DW_AT_data_member_location",
              );
              if (memberName) {
                let memberOffset: number | undefined;
                if (memberLoc) {
                  const opMatch =
                    /DW_OP_plus_uconst\s+(\d+|0x[0-9a-fA-F]+)/.exec(memberLoc);
                  if (opMatch && opMatch[1]) {
                    memberOffset =
                      opMatch[1].startsWith("0x") || opMatch[1].startsWith("0X")
                        ? parseInt(opMatch[1], 16)
                        : parseInt(opMatch[1], 10);
                  } else if (/^0x[0-9a-fA-F]+$/i.test(memberLoc.trim())) {
                    memberOffset = parseInt(memberLoc.trim(), 16);
                  } else {
                    const numMatch = /(\d+)/.exec(memberLoc.trim());
                    memberOffset =
                      numMatch && numMatch[1]
                        ? parseInt(numMatch[1], 10)
                        : undefined;
                  }
                }
                members.push({
                  name: memberName,
                  type: resolveType(memberTypeRef),
                  offset: memberOffset,
                });
              }
            }
          }

          const byteSizeStr = die.attributes.get("DW_AT_byte_size");
          types.push({
            name: structName,
            kind: die.tag === "DW_TAG_union_type" ? "union" : "struct",
            size: byteSizeStr
              ? parseInt(byteSizeStr, 10) || undefined
              : undefined,
            members: members.length > 0 ? members : undefined,
          });
        }
      }

      // 2. Typedefs
      if (die.tag === "DW_TAG_typedef") {
        const typeName = die.attributes.get("DW_AT_name");
        if (typeName && !typeName.startsWith("__")) {
          types.push({
            name: typeName,
            kind: "typedef",
          });
        }
      }

      // 3. Subprograms (Functions)
      if (die.tag === "DW_TAG_subprogram") {
        const funcName = die.attributes.get("DW_AT_name");
        if (funcName) {
          const returnTypeRef = die.attributes.get("DW_AT_type");
          const returnType = returnTypeRef
            ? resolveType(returnTypeRef)
            : "void";
          const lowPc = die.attributes.get("DW_AT_low_pc");
          const highPc = die.attributes.get("DW_AT_high_pc");

          const parameters: ExtractedParameter[] = [];
          const localVars: ExtractedVariable[] = [];

          for (const child of die.children) {
            if (child.tag === "DW_TAG_formal_parameter") {
              const paramName = child.attributes.get("DW_AT_name");
              const paramTypeRef = child.attributes.get("DW_AT_type");
              if (paramName) {
                parameters.push({
                  name: paramName,
                  type: resolveType(paramTypeRef),
                });
              }
            } else if (child.tag === "DW_TAG_variable") {
              const varName = child.attributes.get("DW_AT_name");
              const varTypeRef = child.attributes.get("DW_AT_type");
              if (varName) {
                localVars.push({
                  name: varName,
                  type: resolveType(varTypeRef),
                });
              }
            }
          }

          let size: number | undefined;
          if (lowPc !== undefined && highPc !== undefined) {
            const low = parseInt(lowPc, 16);
            if (!isNaN(low)) {
              if (highPc.startsWith("0x") || /[a-fA-F]/.test(highPc)) {
                const high = parseInt(highPc, 16);
                size = high > low ? high - low : high;
              } else {
                size = parseInt(highPc, 10) || undefined;
              }
            }
          }

          functions.push({
            name: funcName,
            return_type: returnType,
            parameters,
            local_variables: localVars,
            address: lowPc
              ? lowPc.startsWith("0x")
                ? lowPc
                : `0x${lowPc}`
              : undefined,
            size,
          });
        }
      }
    }

    // 4. Generate C headers into project
    const generatedHeaders: string[] = [];
    const outputDir = options.outputHeaderDir
      ? resolve(projectDir, options.outputHeaderDir)
      : join(projectDir, "include");
    const relOutputDir = relative(projectDir, outputDir) || "include";
    await mkdir(outputDir, { recursive: true });

    if (types.length > 0) {
      const typesHeaderPath = join(outputDir, "types.h");
      const typesContent = this.generateTypesHeader(types);
      await writeFile(typesHeaderPath, typesContent, "utf8");
      generatedHeaders.push(join(relOutputDir, "types.h"));
    }

    if (functions.length > 0) {
      const symbolsHeaderPath = join(outputDir, "symbols.h");
      const symbolsContent = this.generateSymbolsHeader(functions);
      await writeFile(symbolsHeaderPath, symbolsContent, "utf8");
      generatedHeaders.push(join(relOutputDir, "symbols.h"));
    }

    return {
      total_functions_recovered: functions.length,
      total_types_recovered: types.length,
      functions,
      types,
      header_files_generated: generatedHeaders,
    };
  }

  private async readDwarfDebugInfo(binaryPath: string): Promise<string> {
    const env = createAirgapEnv();

    // 1. Try readelf -wi / readelf --debug-dump=info
    try {
      const { stdout } = await execFileOutput(
        "readelf",
        ["--debug-dump=info", binaryPath],
        { env, maxBuffer: 32 * 1024 * 1024 },
      );
      if (stdout.includes("DW_TAG_")) {
        return stdout;
      }
    } catch {
      // Fallback to llvm-dwarfdump
    }

    // 2. Try llvm-dwarfdump
    try {
      const { stdout } = await execFileOutput(
        "llvm-dwarfdump",
        ["--debug-info", binaryPath],
        { env, maxBuffer: 32 * 1024 * 1024 },
      );
      if (stdout.includes("DW_TAG_")) {
        return stdout;
      }
    } catch {
      // No DWARF tools available or binary has no DWARF
    }

    return "";
  }

  private parseDwarfOutput(output: string): RawDie[] {
    const lines = output.split(/\r?\n/);
    const rootDies: RawDie[] = [];
    const dieStack: RawDie[] = [];

    // Regex for DIE header:
    // e.g. " <1><c1>: Abbrev Number: 9 (DW_TAG_subprogram)"
    // or "0x0000000c: DW_TAG_compile_unit"
    const readelfTagRegex =
      /^\s*<(\d+)><([0-9a-fA-F]+)>:\s+Abbrev\s+Number:\s+\d+\s+\((DW_TAG_[a-zA-Z0-9_]+)\)/;
    const llvmTagRegex = /^0x([0-9a-fA-F]+):\s*(\s*)(DW_TAG_[a-zA-Z0-9_]+)/;
    const readelfAttrRegex =
      /^\s*(?:<[0-9a-fA-F]+>)?\s*(DW_AT_[a-zA-Z0-9_]+)\s*:\s*(.*)$/;
    const llvmAttrRegex =
      /^\s*(DW_AT_[a-zA-Z0-9_]+)\s*(?:\[[^\]]*\])?\s*(?::\s*|\s+)\((.*)\)\s*$/;

    let currentDie: {
      offset: string;
      level: number;
      tag: string;
      attributes: Map<string, string>;
      children: RawDie[];
    } | null = null;

    const commitCurrentDie = () => {
      if (!currentDie) return;
      const die: RawDie = {
        offset: currentDie.offset,
        level: currentDie.level,
        tag: currentDie.tag,
        attributes: currentDie.attributes,
        children: currentDie.children,
      };

      // Manage stack according to nesting level
      while (
        dieStack.length > 0 &&
        dieStack[dieStack.length - 1]!.level >= die.level
      ) {
        dieStack.pop();
      }

      if (dieStack.length === 0) {
        rootDies.push(die);
      } else {
        dieStack[dieStack.length - 1]!.children.push(die);
      }
      dieStack.push(die);
    };

    for (const line of lines) {
      const readelfTagMatch = readelfTagRegex.exec(line);
      const llvmTagMatch = !readelfTagMatch ? llvmTagRegex.exec(line) : null;

      if (
        readelfTagMatch &&
        readelfTagMatch[1] &&
        readelfTagMatch[2] &&
        readelfTagMatch[3]
      ) {
        commitCurrentDie();
        const level = parseInt(readelfTagMatch[1], 10);
        const offset = readelfTagMatch[2];
        const tag = readelfTagMatch[3];
        currentDie = {
          offset,
          level,
          tag,
          attributes: new Map(),
          children: [],
        };
        continue;
      } else if (
        llvmTagMatch &&
        llvmTagMatch[1] &&
        llvmTagMatch[2] !== undefined &&
        llvmTagMatch[3]
      ) {
        commitCurrentDie();
        const offset = llvmTagMatch[1];
        const level = Math.floor(llvmTagMatch[2].length / 2);
        const tag = llvmTagMatch[3];
        currentDie = {
          offset,
          level,
          tag,
          attributes: new Map(),
          children: [],
        };
        continue;
      }

      if (currentDie) {
        const llvmAttrMatch = llvmAttrRegex.exec(line);
        const readelfAttrMatch = !llvmAttrMatch
          ? readelfAttrRegex.exec(line)
          : null;

        if (
          llvmAttrMatch &&
          llvmAttrMatch[1] &&
          llvmAttrMatch[2] !== undefined
        ) {
          const attr = llvmAttrMatch[1];
          let val = llvmAttrMatch[2].trim();
          if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
            val = val.slice(1, -1);
          } else if (attr === "DW_AT_type") {
            const refMatch = /^(0x[0-9a-fA-F]+)/.exec(val);
            if (refMatch && refMatch[1]) {
              val = refMatch[1];
            }
          }
          currentDie.attributes.set(attr, val);
        } else if (
          readelfAttrMatch &&
          readelfAttrMatch[1] &&
          readelfAttrMatch[2] !== undefined
        ) {
          const attr = readelfAttrMatch[1];
          let val = readelfAttrMatch[2].trim();

          // Clean indirect string wrapper: "(indirect string, offset: 0x...): my_name" -> "my_name"
          const indirectMatch =
            /\(indirect line string[^)]*\):\s*(.*)$/.exec(val) ??
            /\(indirect string[^)]*\):\s*(.*)$/.exec(val);
          if (indirectMatch && indirectMatch[1]) {
            val = indirectMatch[1].trim();
          }

          // Clean reference wrapper: "<0x148>" -> "148"
          const refMatch = /^<0x?([0-9a-fA-F]+)>$/.exec(val);
          if (refMatch && refMatch[1]) {
            val = refMatch[1].toLowerCase();
          }

          currentDie.attributes.set(attr, val);
        }
      }
    }

    commitCurrentDie();

    // Flatten all DIEs for lookup
    const allDies: RawDie[] = [];
    const collect = (node: RawDie) => {
      allDies.push(node);
      for (const child of node.children) {
        collect(child);
      }
    };
    for (const r of rootDies) {
      collect(r);
    }

    return allDies;
  }

  private generateTypesHeader(types: readonly ExtractedType[]): string {
    const lines: string[] = [
      "#ifndef DECOMP_TYPES_H",
      "#define DECOMP_TYPES_H",
      "",
      "#include <stdint.h>",
      "#include <stddef.h>",
      "#include <stdbool.h>",
      "",
    ];

    for (const t of types) {
      if (t.kind === "struct" && t.members && t.members.length > 0) {
        lines.push(`struct ${t.name} {`);
        for (const m of t.members) {
          const offsetComment =
            m.offset !== undefined ? ` /* offset: ${m.offset} */` : "";
          lines.push(`    ${m.type} ${m.name};${offsetComment}`);
        }
        lines.push("};", "");
      }
    }

    lines.push("#endif /* DECOMP_TYPES_H */", "");
    return lines.join("\n");
  }

  private generateSymbolsHeader(
    functions: readonly ExtractedFunction[],
  ): string {
    const lines: string[] = [
      "#ifndef DECOMP_SYMBOLS_H",
      "#define DECOMP_SYMBOLS_H",
      "",
      '#include "types.h"',
      "",
    ];

    for (const fn of functions) {
      const params =
        fn.parameters.length > 0
          ? fn.parameters.map((p) => `${p.type} ${p.name}`).join(", ")
          : "void";
      lines.push(`${fn.return_type} ${fn.name}(${params});`);
    }

    lines.push("", "#endif /* DECOMP_SYMBOLS_H */", "");
    return lines.join("\n");
  }
}
