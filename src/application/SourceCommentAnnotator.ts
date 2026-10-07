import { readFile, writeFile, readdir } from "node:fs/promises";
import { join, resolve, relative } from "node:path";
import type { DecompAnnotateSourceResult } from "../domain/decompilationAnalysis.js";

export interface AnnotatedFunction {
  readonly symbol: string;
  readonly file: string;
  readonly docstring: string;
  readonly intent_comments_count: number;
}

export type SourceAnnotationResult = DecompAnnotateSourceResult;

export class SourceCommentAnnotator {
  async annotate(options: {
    readonly projectDirectory: string;
    readonly symbol?: string | undefined;
    readonly sourceFile?: string | undefined;
    readonly style?: "doxygen" | "intent" | "both" | undefined;
  }): Promise<DecompAnnotateSourceResult> {
    const projectDir = resolve(options.projectDirectory);
    const style = options.style ?? "both";

    // 1. Locate candidate source files
    const candidateFiles: string[] = [];
    if (options.sourceFile) {
      candidateFiles.push(resolve(projectDir, options.sourceFile));
    } else {
      await this.collectCFiles(join(projectDir, "src"), candidateFiles);
    }

    const annotatedFiles: string[] = [];
    const annotatedFunctions: AnnotatedFunction[] = [];
    let totalCommentsAdded = 0;

    for (const filePath of candidateFiles) {
      let content = "";
      try {
        content = await readFile(filePath, "utf8");
      } catch {
        continue;
      }

      const relPath = relative(projectDir, filePath);
      const parsedFunctions = this.parseCFunctions(content);

      if (parsedFunctions.length === 0) continue;

      let fileModified = false;
      let newContent = content;

      // Process functions in reverse order so character slice replacements do not shift earlier indices
      for (let idx = parsedFunctions.length - 1; idx >= 0; idx--) {
        const fn = parsedFunctions[idx]!;
        if (options.symbol && fn.name !== options.symbol) {
          continue;
        }

        // Generate Doxygen docstring
        const docstring = this.generateDoxygen(fn);
        let intentCommentsCount = 0;

        // Annotate function body if intent comments requested
        let annotatedBody = fn.body;
        if (style === "intent" || style === "both") {
          const intentResult = this.injectIntentComments(fn.body);
          annotatedBody = intentResult.body;
          intentCommentsCount = intentResult.count;
        }

        let totalForFunction = 0;
        let replacement = "";

        if (style === "doxygen" || style === "both") {
          replacement = `${docstring}\n${fn.returnType} ${fn.name}(${fn.paramsRaw}) {\n${annotatedBody}\n}`;
          totalForFunction += 1 + intentCommentsCount;
        } else {
          replacement = `${fn.returnType} ${fn.name}(${fn.paramsRaw}) {\n${annotatedBody}\n}`;
          totalForFunction += intentCommentsCount;
        }

        if (!fn.hasExistingDoxygen) {
          if (totalForFunction > 0) {
            newContent =
              newContent.slice(0, fn.startIndex) +
              replacement +
              newContent.slice(fn.endIndex);
            fileModified = true;
            totalCommentsAdded += totalForFunction;

            annotatedFunctions.unshift({
              symbol: fn.name,
              file: relPath,
              docstring,
              intent_comments_count: intentCommentsCount,
            });
          }
        } else if (
          intentCommentsCount > 0 &&
          (style === "intent" || style === "both")
        ) {
          const docPrefix = fn.existingDoc ? `${fn.existingDoc}\n` : "";
          const intentReplacement = `${docPrefix}${fn.returnType} ${fn.name}(${fn.paramsRaw}) {\n${annotatedBody}\n}`;
          newContent =
            newContent.slice(0, fn.startIndex) +
            intentReplacement +
            newContent.slice(fn.endIndex);
          fileModified = true;
          totalCommentsAdded += intentCommentsCount;

          annotatedFunctions.unshift({
            symbol: fn.name,
            file: relPath,
            docstring: fn.existingDoc ?? docstring,
            intent_comments_count: intentCommentsCount,
          });
        }
      }

      if (fileModified) {
        await writeFile(filePath, newContent, "utf8");
        annotatedFiles.push(relPath);
      }
    }

    return {
      total_comments_added: totalCommentsAdded,
      annotated_files: annotatedFiles,
      functions_annotated: annotatedFunctions,
    };
  }

  private async collectCFiles(dir: string, outList: string[]): Promise<void> {
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          await this.collectCFiles(fullPath, outList);
        } else if (entry.isFile() && entry.name.endsWith(".c")) {
          outList.push(fullPath);
        }
      }
    } catch {
      // ignore missing
    }
  }

  private parseCFunctions(content: string): Array<{
    name: string;
    returnType: string;
    paramsRaw: string;
    body: string;
    fullMatch: string;
    startIndex: number;
    endIndex: number;
    hasExistingDoxygen: boolean;
    existingDoc?: string | undefined;
  }> {
    const results: Array<{
      name: string;
      returnType: string;
      paramsRaw: string;
      body: string;
      fullMatch: string;
      startIndex: number;
      endIndex: number;
      hasExistingDoxygen: boolean;
      existingDoc?: string | undefined;
    }> = [];

    // Pre-calculate ranges of comments and strings so we never match fake functions inside them
    const stringAndCommentRanges: Array<{ start: number; end: number }> = [];
    const tokenRegex =
      /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*)/g;
    let tokenMatch: RegExpExecArray | null;
    while ((tokenMatch = tokenRegex.exec(content)) !== null) {
      stringAndCommentRanges.push({
        start: tokenMatch.index,
        end: tokenMatch.index + tokenMatch[0].length,
      });
    }

    const isInsideStringOrComment = (pos: number): boolean => {
      for (const range of stringAndCommentRanges) {
        if (pos >= range.start && pos < range.end) {
          return true;
        }
      }
      return false;
    };

    // Match signature: [existingDoc] <type> <name>(<params>) {
    const sigRegex =
      /(?:(\/\*\*[\s\S]*?\*\/)\s*)?([a-zA-Z_][a-zA-Z0-9_\s*]+?)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{/g;

    let match: RegExpExecArray | null;
    while ((match = sigRegex.exec(content)) !== null) {
      const existingDoc = match[1];
      const returnType = match[2]?.trim();
      const name = match[3];
      const paramsRaw = match[4]?.trim();

      if (returnType && name && paramsRaw !== undefined) {
        // Exclude control flow keywords like if, while, for, switch
        if (["if", "while", "for", "switch", "catch"].includes(name)) {
          continue;
        }

        // Verify the function signature itself is not located inside a comment or string literal
        const sigStart = match.index + match[0].lastIndexOf(returnType);
        if (isInsideStringOrComment(sigStart)) {
          continue;
        }

        // Find matching closing brace from after the opening '{',
        // properly skipping string literals, character literals, and comments.
        let depth = 1;
        let i = sigRegex.lastIndex;
        const bodyStart = i;
        while (i < content.length && depth > 0) {
          const ch = content[i];

          // Check line comment
          if (ch === "/" && content[i + 1] === "/") {
            i += 2;
            while (i < content.length && content[i] !== "\n") {
              i++;
            }
            continue;
          }

          // Check block comment
          if (ch === "/" && content[i + 1] === "*") {
            i += 2;
            while (
              i < content.length - 1 &&
              !(content[i] === "*" && content[i + 1] === "/")
            ) {
              i++;
            }
            i += 2; // skip */
            continue;
          }

          // Check string literal
          if (ch === '"') {
            i++;
            while (i < content.length && content[i] !== '"') {
              if (content[i] === "\\" && i + 1 < content.length) {
                i++; // skip escaped char
              }
              i++;
            }
            i++; // skip closing "
            continue;
          }

          // Check char literal
          if (ch === "'") {
            i++;
            while (i < content.length && content[i] !== "'") {
              if (content[i] === "\\" && i + 1 < content.length) {
                i++; // skip escaped char
              }
              i++;
            }
            i++; // skip closing '
            continue;
          }

          if (ch === "{") {
            depth++;
          } else if (ch === "}") {
            depth--;
          }
          i++;
        }

        if (depth === 0) {
          const body = content.slice(bodyStart, i - 1).trim();
          const startIndex = match.index;
          const endIndex = i;
          const fullMatch = content.slice(startIndex, endIndex);
          results.push({
            name,
            returnType,
            paramsRaw,
            body,
            fullMatch,
            startIndex,
            endIndex,
            hasExistingDoxygen: existingDoc !== undefined,
            existingDoc: existingDoc ?? undefined,
          });
          sigRegex.lastIndex = i;
        }
      }
    }

    return results;
  }

  private generateDoxygen(fn: {
    name: string;
    returnType: string;
    paramsRaw: string;
  }): string {
    const lines: string[] = [
      "/**",
      ` * @brief Reconstructed matching implementation of \`${fn.name}\`.`,
    ];

    // Infer description from function name
    if (fn.name.toLowerCase().includes("crc")) {
      lines.push(
        " * @details Computes cyclic redundancy check (CRC) checksum using generator polynomial.",
      );
    } else if (fn.name.toLowerCase().includes("init")) {
      lines.push(
        " * @details Initializes hardware subsystem or context state.",
      );
    } else if (fn.name.toLowerCase().includes("calc")) {
      lines.push(
        " * @details Evaluates deterministic mathematical or state calculation.",
      );
    }

    lines.push(" *");

    // Parse parameters
    if (fn.paramsRaw && fn.paramsRaw !== "void") {
      const params = fn.paramsRaw.split(",").map((p) => p.trim());
      for (const p of params) {
        const parts = p.split(/\s+/);
        const pName = parts[parts.length - 1]?.replace(/^[*]+/, "") ?? "param";
        const pType = parts.slice(0, -1).join(" ") || "unknown";
        lines.push(` * @param[in] ${pName} Parameter of type \`${pType}\`.`);
      }
    }

    if (fn.returnType !== "void") {
      lines.push(
        ` * @return Reconstructed computation result of type \`${fn.returnType}\`.`,
      );
    }

    lines.push(" */");
    return lines.join("\n");
  }

  private injectIntentComments(body: string): { body: string; count: number } {
    const lines = body.split("\n");
    const newLines: string[] = [];
    let count = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const trimmed = line.trim();

      // Check if line contains loop or condition or bitwise
      if (
        (trimmed.startsWith("for ") || trimmed.startsWith("for(")) &&
        !lines[i - 1]?.trim().startsWith("/*")
      ) {
        newLines.push(
          "    /* Algorithmic intent: iterative block processing loop */",
        );
        count++;
      } else if (
        (trimmed.startsWith("while ") || trimmed.startsWith("while(")) &&
        !lines[i - 1]?.trim().startsWith("/*")
      ) {
        newLines.push(
          "    /* Algorithmic intent: loop until stream or condition terminates */",
        );
        count++;
      } else if (
        (trimmed.includes("^=") || trimmed.includes(" ^ ")) &&
        !trimmed.startsWith("/*") &&
        !lines[i - 1]?.trim().startsWith("/*")
      ) {
        newLines.push(
          "    /* Algorithmic intent: bitwise polynomial reduction / XOR state update */",
        );
        count++;
      } else if (
        (trimmed.includes(">>=") ||
          trimmed.includes(" << ") ||
          trimmed.includes(" >> ")) &&
        !trimmed.startsWith("/*") &&
        !lines[i - 1]?.trim().startsWith("/*")
      ) {
        newLines.push(
          "    /* Algorithmic intent: bitshift operand transformation */",
        );
        count++;
      }

      newLines.push(line);
    }

    return {
      body: newLines.join("\n"),
      count,
    };
  }
}
