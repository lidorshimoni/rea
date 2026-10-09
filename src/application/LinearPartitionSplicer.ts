import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve, basename, dirname } from "node:path";
import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";
import type {
  DecompSlice,
  DecompSliceManifest,
  DecompProjectConfig,
} from "../domain/decompilationAnalysis.js";

export interface SplicerOptions {
  readonly projectDirectory: string;
  readonly targetPath?: string | undefined;
}

/**
 * Contiguous Linear Partitioning Splicer.
 * Guarantees the Day 0 Link Invariant: partitions target binary into 100% gapless,
 * non-overlapping assembly stubs (.s) that relink to a bit-exact SHA256 match.
 */
export class LinearPartitionSplicer {
  async split(options: SplicerOptions): Promise<DecompSliceManifest> {
    const projectDir = resolve(options.projectDirectory);
    const targetFile = resolve(
      options.targetPath ?? join(projectDir, "target.bin"),
    );
    const buffer = await readFile(targetFile);
    const targetSha256 = createHash("sha256").update(buffer).digest("hex");

    // Read decomp.yaml if present
    let config: DecompProjectConfig | undefined;
    try {
      const configRaw = await readFile(join(projectDir, "decomp.yaml"), "utf8");
      config = parseYaml(configRaw) as DecompProjectConfig;
    } catch {
      // Config optional
    }

    const isArm =
      config?.target.architecture === "arm-thumb" ||
      config?.target.architecture === "arm";
    const imageBaseBig = BigInt(config?.target.image_base ?? "0x00400000");

    // Mine assert strings for module mapping
    const assertPaths = this.mineAssertPaths(buffer);

    // Identify candidate slices
    const rawSlices = this.identifySlices(
      buffer,
      isArm,
      imageBaseBig,
      assertPaths,
    );

    // Ensure contiguous linear partition from 0 to buffer.length (0 gaps!)
    const contiguousSlices = this.makeContiguous(
      rawSlices,
      buffer.length,
      imageBaseBig,
    );

    // Ensure directories exist
    await mkdir(join(projectDir, "asm", "boot"), { recursive: true });
    await mkdir(join(projectDir, "asm", "core"), { recursive: true });
    await mkdir(join(projectDir, "asm", "drivers"), { recursive: true });
    await mkdir(join(projectDir, "asm", "padding"), { recursive: true });
    await mkdir(join(projectDir, "asm", "data"), { recursive: true });

    // Generate .s assembly stub for each slice
    for (const slice of contiguousSlices) {
      const fullAsmPath = join(projectDir, slice.asm_file);
      await mkdir(dirname(fullAsmPath), { recursive: true });
      const asmCode = this.generateAsmStub(slice, isArm);
      await writeFile(fullAsmPath, asmCode, "utf8");
    }

    // Generate memory-pinned linker.ld
    const linkerScriptContent = this.generateLinkerScript(
      contiguousSlices,
      imageBaseBig,
      isArm,
    );
    const linkerScriptPath = "linker.ld";
    await writeFile(
      join(projectDir, linkerScriptPath),
      linkerScriptContent,
      "utf8",
    );

    // Build and save manifest
    const manifest: DecompSliceManifest = {
      target_sha256: targetSha256,
      total_slices: contiguousSlices.length,
      slices: contiguousSlices,
      linker_script_path: linkerScriptPath,
    };

    await writeFile(
      join(projectDir, "slices.json"),
      JSON.stringify(manifest, null, 2),
      "utf8",
    );

    return manifest;
  }

  /**
   * Search binary for assert file paths (e.g. "core/crc32.c", "src/drivers/uart.c").
   */
  private mineAssertPaths(
    buffer: Buffer,
  ): Array<{ path: string; offset: number; module: string }> {
    const results: Array<{ path: string; offset: number; module: string }> = [];
    const text = buffer.toString("latin1");
    const regex = /(?:[a-zA-Z0-9_\-./]+\/)?([a-zA-Z0-9_-]+)\.(?:c|h)\b/g;

    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const fullMatch = match[0];
      const fileName = match[1] ?? "unit";
      let module = "core";
      if (
        fullMatch.includes("driver") ||
        fullMatch.includes("uart") ||
        fullMatch.includes("gpio")
      ) {
        module = "drivers";
      } else if (fullMatch.includes("boot") || fullMatch.includes("startup")) {
        module = "boot";
      }
      results.push({
        path: fullMatch,
        offset: match.index,
        module,
      });
    }

    return results;
  }

  /**
   * Parse ELF symbols or ARM Cortex-M vectors to extract candidate function slices.
   */
  private identifySlices(
    buffer: Buffer,
    isArm: boolean,
    imageBase: bigint,
    assertPaths: Array<{ path: string; offset: number; module: string }>,
  ): DecompSlice[] {
    // 1. Try parsing ELF symbols if ELF
    if (
      buffer.length >= 52 &&
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46
    ) {
      const elfSlices = this.tryParseElfSymbols(buffer, assertPaths);
      if (elfSlices.length > 0) return elfSlices;

      const ehFrameSlices = this.tryParseElfEhFrame(buffer, assertPaths);
      if (ehFrameSlices.length > 0) return ehFrameSlices;
    }

    // 2. Try parsing ARM Cortex-M Vector Table
    if (isArm && buffer.length >= 64) {
      const cortexSlices = this.tryParseCortexM(buffer, imageBase, assertPaths);
      if (cortexSlices.length > 0) return cortexSlices;
    }

    // 3. Try heuristic function prologue scanning for stripped or raw binaries
    const heuristicSlices = this.tryParseHeuristics(
      buffer,
      isArm,
      imageBase,
      assertPaths,
    );
    if (heuristicSlices.length > 0) return heuristicSlices;

    return [];
  }

  /**
   * Extract function symbols from ELF .symtab / .strtab if present.
   */
  private tryParseElfSymbols(
    buffer: Buffer,
    assertPaths: Array<{ path: string; offset: number; module: string }>,
  ): DecompSlice[] {
    const is64 = buffer[4] === 2;
    const isLE = buffer[5] === 1;
    const readU16 = (o: number) =>
      isLE ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o);
    const readU32 = (o: number) =>
      isLE ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);
    const readU64 = (o: number) =>
      isLE ? buffer.readBigUInt64LE(o) : buffer.readBigUInt64BE(o);

    const shOff = is64 ? Number(readU64(40)) : readU32(32);
    const shEntSize = readU16(is64 ? 58 : 46);
    const shNum = readU16(is64 ? 60 : 48);
    const shStrNdx = readU16(is64 ? 62 : 50);

    if (shOff === 0 || shOff + shNum * shEntSize > buffer.length) return [];

    let symTabOff = 0;
    let symTabSize = 0;
    let symEntSize = 0;
    let strTabOff = 0;

    // Find .symtab and .strtab
    for (let i = 0; i < shNum; i++) {
      const sOff = shOff + i * shEntSize;
      const type = readU32(sOff + 4);
      const offset = is64 ? Number(readU64(sOff + 24)) : readU32(sOff + 16);
      const size = is64 ? Number(readU64(sOff + 32)) : readU32(sOff + 20);
      const entsize = is64 ? Number(readU64(sOff + 56)) : readU32(sOff + 36);
      const link = readU32(sOff + (is64 ? 40 : 28));

      if (type === 2) {
        // SHT_SYMTAB
        symTabOff = offset;
        symTabSize = size;
        symEntSize = entsize || (is64 ? 24 : 16);

        // Associated string table
        if (link < shNum) {
          const strHeaderOff = shOff + link * shEntSize;
          strTabOff = is64
            ? Number(readU64(strHeaderOff + 24))
            : readU32(strHeaderOff + 16);
        }
      }
    }

    if (symTabOff === 0 || strTabOff === 0 || symEntSize === 0) return [];

    const slices: DecompSlice[] = [];
    const count = Math.floor(symTabSize / symEntSize);
    const seenNames = new Map<string, number>();

    for (let i = 0; i < count; i++) {
      const entOff = symTabOff + i * symEntSize;
      const nameIdx = readU32(entOff);
      const info = buffer[entOff + (is64 ? 4 : 12)]!;
      const symType = info & 0xf;
      const symBind = info >> 4; // 0 = LOCAL, 1 = GLOBAL, 2 = WEAK
      const value = is64 ? readU64(entOff + 8) : BigInt(readU32(entOff + 4));
      const size = is64 ? Number(readU64(entOff + 16)) : readU32(entOff + 8);
      const shndx = is64 ? readU16(entOff + 6) : readU16(entOff + 14);

      // Skip undefined symbols (SHN_UNDEF = 0)
      if (shndx === 0) continue;

      // STT_FUNC = 2
      if (symType === 2 && size > 0) {
        let symName = "";
        if (strTabOff + nameIdx < buffer.length) {
          const zero = buffer.indexOf(0, strTabOff + nameIdx);
          if (zero !== -1) {
            symName = buffer.toString("utf8", strTabOff + nameIdx, zero);
          }
        }

        if (symName && !symName.startsWith("__") && !symName.startsWith(".")) {
          // Convert value (virtual address or section offset) to file offset via section headers
          let fileOffset = Number(value & 0xffffffffn);
          if (shndx > 0 && shndx < shNum) {
            const secHdrOff = shOff + shndx * shEntSize;
            const secAddr = is64
              ? readU64(secHdrOff + 16)
              : BigInt(readU32(secHdrOff + 12));
            const secOffset = is64
              ? Number(readU64(secHdrOff + 24))
              : readU32(secHdrOff + 16);
            if (secAddr > 0n && value >= secAddr) {
              fileOffset = secOffset + Number(value - secAddr);
            } else if (secAddr === 0n) {
              fileOffset = secOffset + Number(value);
            }
          }

          if (fileOffset + size <= buffer.length) {
            let module = "core";
            const symLower = symName.toLowerCase();
            const matchingAssert = assertPaths.find((p) => {
              const baseName =
                p.path.split("/").pop()?.split(".")[0]?.toLowerCase() ?? "";
              return baseName !== "" && symLower.includes(baseName);
            });

            if (matchingAssert) {
              module = matchingAssert.module;
            } else if (
              symLower.includes("driver") ||
              symLower.includes("uart") ||
              symLower.includes("gpio") ||
              symLower.includes("i2c") ||
              symLower.includes("spi")
            ) {
              module = "drivers";
            } else if (
              symLower.includes("boot") ||
              symLower.includes("start") ||
              symLower.includes("reset") ||
              symLower.includes("init")
            ) {
              module = "boot";
            } else if (assertPaths[0]) {
              module = assertPaths[0].module;
            }

            const countForName = seenNames.get(symName) ?? 0;
            seenNames.set(symName, countForName + 1);
            const uniqueSuffix = countForName === 0 ? "" : `_${countForName}`;
            const uniqueSymName = `${symName}${uniqueSuffix}`;

            slices.push({
              id: `func_${uniqueSymName}`,
              name: symName,
              type: "function",
              offset: fileOffset,
              size,
              address: `0x${value.toString(16).padStart(8, "0")}`,
              asm_file: `asm/${module}/${uniqueSymName}.s`,
              source_file: `src/${module}/${uniqueSymName}.c`,
              status: "spliced",
              is_global: (symBind === 1 || symBind === 2) && countForName === 0,
            });
          }
        }
      }
    }

    return slices;
  }

  /**
   * Parse stripped ELF using .eh_frame_hdr binary search table and .dynsym.
   * Carves 100% of function boundaries even with symbols completely stripped.
   */
  private tryParseElfEhFrame(
    buffer: Buffer,
    assertPaths: Array<{ path: string; offset: number; module: string }>,
  ): DecompSlice[] {
    const is64 = buffer[4] === 2;
    const isLE = buffer[5] === 1;
    const readU16 = (o: number) =>
      isLE ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o);
    const readU32 = (o: number) =>
      isLE ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);
    const readI32 = (o: number) =>
      isLE ? buffer.readInt32LE(o) : buffer.readInt32BE(o);
    const readU64 = (o: number) =>
      isLE ? buffer.readBigUInt64LE(o) : buffer.readBigUInt64BE(o);

    const shOff = is64 ? Number(readU64(40)) : readU32(32);
    const shEntSize = readU16(is64 ? 58 : 46);
    const shNum = readU16(is64 ? 60 : 48);
    const shStrNdx = readU16(is64 ? 62 : 50);

    let ehHdrOff = 0;
    let ehHdrAddr = 0n;

    const dynSymbols = new Map<number, string>();

    if (
      shOff > 0 &&
      shOff + shNum * shEntSize <= buffer.length &&
      shStrNdx < shNum
    ) {
      const strHdrOff = shOff + shStrNdx * shEntSize;
      const shStrTabOff = is64
        ? Number(readU64(strHdrOff + 24))
        : readU32(strHdrOff + 16);

      let dynSymOff = 0;
      let dynSymSize = 0;
      let dynSymEnt = 0;
      let dynStrOff = 0;

      for (let i = 0; i < shNum; i++) {
        const sOff = shOff + i * shEntSize;
        const nameIdx = readU32(sOff);
        const type = readU32(sOff + 4);
        const sAddr = is64 ? readU64(sOff + 16) : BigInt(readU32(sOff + 12));
        const sFileOff = is64 ? Number(readU64(sOff + 24)) : readU32(sOff + 16);
        const sSize = is64 ? Number(readU64(sOff + 32)) : readU32(sOff + 20);
        const sEnt = is64 ? Number(readU64(sOff + 56)) : readU32(sOff + 36);
        const link = readU32(sOff + (is64 ? 40 : 28));

        let secName = "";
        if (shStrTabOff + nameIdx < buffer.length) {
          const zero = buffer.indexOf(0, shStrTabOff + nameIdx);
          if (zero !== -1) {
            secName = buffer.toString("utf8", shStrTabOff + nameIdx, zero);
          }
        }

        if (secName === ".eh_frame_hdr") {
          ehHdrOff = sFileOff;
          ehHdrAddr = sAddr;
        } else if (type === 11) {
          // SHT_DYNSYM
          dynSymOff = sFileOff;
          dynSymSize = sSize;
          dynSymEnt = sEnt || (is64 ? 24 : 16);
          if (link < shNum) {
            const linkHdrOff = shOff + link * shEntSize;
            dynStrOff = is64
              ? Number(readU64(linkHdrOff + 24))
              : readU32(linkHdrOff + 16);
          }
        }
      }

      if (dynSymOff > 0 && dynStrOff > 0 && dynSymEnt > 0) {
        const dCount = Math.floor(dynSymSize / dynSymEnt);
        for (let i = 0; i < dCount; i++) {
          const ent = dynSymOff + i * dynSymEnt;
          const nIdx = readU32(ent);
          const info = buffer[ent + (is64 ? 4 : 12)]!;
          const symVal = is64 ? readU64(ent + 8) : BigInt(readU32(ent + 4));
          if ((info & 0xf) === 2 && symVal > 0n) {
            if (dynStrOff + nIdx < buffer.length) {
              const zero = buffer.indexOf(0, dynStrOff + nIdx);
              if (zero !== -1) {
                const sName = buffer.toString("utf8", dynStrOff + nIdx, zero);
                if (sName && !sName.startsWith("__")) {
                  dynSymbols.set(Number(symVal), sName);
                }
              }
            }
          }
        }
      }
    }

    if (ehHdrOff === 0 || ehHdrOff + 12 > buffer.length) return [];

    const fdeCount = readU32(ehHdrOff + 8);
    if (fdeCount === 0 || fdeCount > 100000) return [];

    const rawFuncs: Array<{
      addr: number;
      offset: number;
      name?: string | undefined;
    }> = [];

    for (let i = 0; i < fdeCount; i++) {
      const entryOff = ehHdrOff + 12 + i * 8;
      if (entryOff + 8 > buffer.length) break;
      const initialPcRel = readI32(entryOff);
      const funcAddr = Number(ehHdrAddr) + initialPcRel;
      if (funcAddr <= 0) continue;

      let fileOff = funcAddr;
      if (shOff > 0) {
        for (let s = 0; s < shNum; s++) {
          const sOff = shOff + s * shEntSize;
          const sAddr = is64 ? readU64(sOff + 16) : BigInt(readU32(sOff + 12));
          const sSize = is64 ? Number(readU64(sOff + 32)) : readU32(sOff + 20);
          const sFile = is64 ? Number(readU64(sOff + 24)) : readU32(sOff + 16);
          if (
            BigInt(funcAddr) >= sAddr &&
            BigInt(funcAddr) < sAddr + BigInt(sSize)
          ) {
            fileOff = sFile + (funcAddr - Number(sAddr));
            break;
          }
        }
      }

      if (fileOff > 0 && fileOff < buffer.length) {
        const dynName = dynSymbols.get(funcAddr);
        rawFuncs.push({ addr: funcAddr, offset: fileOff, name: dynName });
      }
    }

    if (rawFuncs.length === 0) return [];

    rawFuncs.sort((a, b) => a.offset - b.offset);

    const uniqueFuncs: Array<{
      addr: number;
      offset: number;
      name?: string | undefined;
    }> = [];
    for (const f of rawFuncs) {
      if (
        uniqueFuncs.length === 0 ||
        uniqueFuncs[uniqueFuncs.length - 1]!.offset !== f.offset
      ) {
        uniqueFuncs.push(f);
      }
    }

    const slices: DecompSlice[] = [];
    for (let i = 0; i < uniqueFuncs.length; i++) {
      const cur = uniqueFuncs[i]!;
      const next = uniqueFuncs[i + 1];
      const size = next
        ? next.offset - cur.offset
        : Math.min(64, buffer.length - cur.offset);

      if (size <= 0 || cur.offset + size > buffer.length) continue;

      const symName =
        cur.name ?? `sub_${cur.addr.toString(16).padStart(6, "0")}`;
      let module = "core";
      if (cur.name === "main" || cur.name === "_start") {
        module = "boot";
      }

      slices.push({
        id: `func_${symName}`,
        name: symName,
        type: "function",
        offset: cur.offset,
        size,
        address: `0x${cur.addr.toString(16).padStart(8, "0")}`,
        asm_file: `asm/${module}/${symName}.s`,
        source_file: `src/${module}/${symName}.c`,
        status: "spliced",
        is_global: Boolean(cur.name),
      });
    }

    return slices;
  }

  /**
   * Scans executable sections for function entry prologues (fallback for raw firmware / stripped non-ELF).
   */
  private tryParseHeuristics(
    buffer: Buffer,
    isArm: boolean,
    imageBase: bigint,
    assertPaths: Array<{ path: string; offset: number; module: string }>,
  ): DecompSlice[] {
    const entryPoints: number[] = [];

    if (!isArm) {
      // Scan for x86_64 prologues
      for (let i = 0; i < buffer.length - 4; i++) {
        if (
          buffer[i] === 0xf3 &&
          buffer[i + 1] === 0x0f &&
          buffer[i + 2] === 0x1e &&
          buffer[i + 3] === 0xfa
        ) {
          entryPoints.push(i);
        } else if (
          buffer[i] === 0x55 &&
          buffer[i + 1] === 0x48 &&
          buffer[i + 2] === 0x89 &&
          buffer[i + 3] === 0xe5 &&
          (i === 0 ||
            buffer[i - 1] === 0xc3 ||
            buffer[i - 1] === 0x90 ||
            i % 16 === 0)
        ) {
          entryPoints.push(i);
        }
      }
    } else {
      // Scan for ARM Thumb prologues: push {..., lr}
      for (let i = 0; i < buffer.length - 2; i += 2) {
        if ((buffer[i + 1]! & 0xff) === 0xb5 && (i === 0 || i % 4 === 0)) {
          entryPoints.push(i);
        }
      }
    }

    if (entryPoints.length === 0) return [];

    const sorted = [...new Set(entryPoints)].sort((a, b) => a - b);
    const slices: DecompSlice[] = [];

    for (let i = 0; i < sorted.length; i++) {
      const off = sorted[i]!;
      const nextOff = sorted[i + 1] ?? Math.min(off + 64, buffer.length);
      const size = nextOff - off;
      if (size < 4 || off + size > buffer.length) continue;

      const addr = imageBase + BigInt(off);
      const name = `sub_${off.toString(16).padStart(6, "0")}`;

      slices.push({
        id: `func_${name}`,
        name,
        type: "function",
        offset: off,
        size,
        address: `0x${addr.toString(16).padStart(8, "0")}`,
        asm_file: `asm/core/${name}.s`,
        source_file: `src/core/${name}.c`,
        status: "spliced",
        is_global: false,
      });
    }

    return slices;
  }

  /**
   * Parse Cortex-M vector table vectors as entry points.
   */
  private tryParseCortexM(
    buffer: Buffer,
    imageBase: bigint,
    assertPaths: Array<{ path: string; offset: number; module: string }>,
  ): DecompSlice[] {
    const slices: DecompSlice[] = [];
    const vectorNames = [
      "Initial_SP",
      "Reset_Handler",
      "NMI_Handler",
      "HardFault_Handler",
      "MemManage_Handler",
      "BusFault_Handler",
      "UsageFault_Handler",
      "Reserved7",
      "Reserved8",
      "Reserved9",
      "Reserved10",
      "SVC_Handler",
      "DebugMon_Handler",
      "Reserved13",
      "PendSV_Handler",
      "SysTick_Handler",
    ];

    // Slices for vector table itself (first 64 bytes)
    slices.push({
      id: "sec_vectors",
      name: "vectors",
      type: "literal_pool",
      offset: 0,
      size: 64,
      address: `0x${imageBase.toString(16).padStart(8, "0")}`,
      asm_file: "asm/boot/startup_cortex_m.s",
      status: "spliced",
    });

    const entries: Array<{ name: string; addr: number }> = [];

    for (let i = 1; i < 16; i++) {
      const addr = buffer.readUInt32LE(i * 4);
      // Valid Thumb address in Flash
      if (
        addr >= Number(imageBase) &&
        addr <= Number(imageBase) + buffer.length
      ) {
        const clearThumb = addr & ~1;
        const offset = clearThumb - Number(imageBase);
        if (offset >= 64 && offset < buffer.length) {
          entries.push({
            name: vectorNames[i] ?? `Handler_${i}`,
            addr: clearThumb,
          });
        }
      }
    }

    // Sort entries by address
    entries.sort((a, b) => a.addr - b.addr);

    for (let i = 0; i < entries.length; i++) {
      const cur = entries[i]!;
      const next = entries[i + 1];
      const offset = cur.addr - Number(imageBase);
      const nextOffset = next
        ? next.addr - Number(imageBase)
        : Math.min(offset + 64, buffer.length);
      const size = Math.max(8, nextOffset - offset);

      slices.push({
        id: `func_${cur.name}`,
        name: cur.name,
        type: "function",
        offset,
        size,
        address: `0x${cur.addr.toString(16).padStart(8, "0")}`,
        asm_file: `asm/boot/${cur.name}.s`,
        source_file: `src/core/${cur.name}.c`,
        status: "spliced",
      });
    }

    return slices;
  }

  /**
   * Take identified slices and fill every gap with padding/literal_pool slices
   * to guarantee 100% contiguous linear partitioning with zero gaps.
   */
  private makeContiguous(
    slices: DecompSlice[],
    totalLength: number,
    imageBase: bigint,
  ): DecompSlice[] {
    // Sort slices by offset ascending, then by size descending (prefer larger slice on identical offset)
    const sorted = [...slices].sort((a, b) => {
      if (a.offset !== b.offset) {
        return a.offset - b.offset;
      }
      return b.size - a.size;
    });
    const contiguous: DecompSlice[] = [];
    let currentOffset = 0;

    for (const slice of sorted) {
      if (slice.offset < currentOffset) {
        // Overlap or already subsumed
        if (slice.offset + slice.size <= currentOffset) {
          // Fully subsumed slice, skip to prevent byte duplication in Day 0 Link
          continue;
        }
        // Partially overlapping slice: truncate the head that was already emitted
        const overlap = currentOffset - slice.offset;
        const adjustedSlice: DecompSlice = {
          ...slice,
          offset: currentOffset,
          size: slice.size - overlap,
        };
        contiguous.push(adjustedSlice);
        currentOffset = adjustedSlice.offset + adjustedSlice.size;
        continue;
      }

      if (slice.offset > currentOffset) {
        // Gap detected -> create explicit padding / literal pool slice
        const gapSize = slice.offset - currentOffset;
        const gapAddr = imageBase + BigInt(currentOffset);
        const padName = `pad_${currentOffset.toString(16).padStart(6, "0")}`;

        contiguous.push({
          id: padName,
          name: padName,
          type: "padding",
          offset: currentOffset,
          size: gapSize,
          address: `0x${gapAddr.toString(16).padStart(8, "0")}`,
          asm_file: `asm/padding/${padName}.s`,
          status: "spliced",
        });
      }

      contiguous.push(slice);
      currentOffset = slice.offset + slice.size;
    }

    // Trailing gap at the end
    if (currentOffset < totalLength) {
      const trailSize = totalLength - currentOffset;
      const trailAddr = imageBase + BigInt(currentOffset);
      const trailName = `pad_tail_${currentOffset.toString(16).padStart(6, "0")}`;

      contiguous.push({
        id: trailName,
        name: trailName,
        type: "data",
        offset: currentOffset,
        size: trailSize,
        address: `0x${trailAddr.toString(16).padStart(8, "0")}`,
        asm_file: `asm/data/${trailName}.s`,
        status: "spliced",
      });
    }

    return contiguous;
  }

  /**
   * Emits a relocatable assembly stub for a slice.
   */
  generateAsmStub(slice: DecompSlice, isArm: boolean): string {
    const isFunc = slice.type === "function";
    const cleanId = slice.id.replace(/[^a-zA-Z0-9_]/g, "_");
    const sectionName = isFunc ? `.text.${cleanId}` : `.${cleanId}`;
    const flags = isFunc ? '"ax", %progbits' : '"a", %progbits';

    const lines: string[] = [
      `# REA Matching Decompilation Slice: ${slice.name} (${slice.type})`,
      `# Offset: 0x${slice.offset.toString(16)} | Size: ${slice.size} bytes`,
    ];

    if (isArm) {
      lines.push(".syntax unified");
    }

    lines.push(`.section ${sectionName}, ${flags}`, `.balign 1`);

    // Every slice must emit .global to eliminate the GNU ld local symbol trap
    lines.push(`.global ${slice.name}`);

    // If a semantic name is assigned, emit a weak alias pointing to the original stub symbol
    if (slice.semantic_name) {
      lines.push(
        `.weak ${slice.semantic_name}`,
        `.set ${slice.semantic_name}, ${slice.name}`,
        `.global ${slice.semantic_name}`,
      );
    }

    if (isFunc) {
      lines.push(`.type ${slice.name}, %function`);
      if (isArm) {
        lines.push(".thumb_func");
      }
    }

    lines.push(
      `${slice.name}:`,
      `    .incbin "target.bin", ${slice.offset}, ${slice.size}`,
      `    .size ${slice.name}, . - ${slice.name}`,
      "",
    );

    return lines.join("\n");
  }

  /**
   * Generates a memory-pinned linker script placing sections in exact linear sequence.
   */
  generateLinkerScript(
    slices: DecompSlice[],
    imageBase: bigint,
    isArm: boolean,
  ): string {
    const sectionEntries = slices
      .map((s) => {
        const cleanId = s.id.replace(/[^a-zA-Z0-9_]/g, "_");
        const secName =
          s.type === "function" ? `.text.${cleanId}` : `.${cleanId}`;
        const fallbackSec =
          s.type === "function" ? `.text.${s.name}` : `.${s.name}`;
        return `        KEEP(*(${secName} ${secName}.* ${fallbackSec} ${fallbackSec}.*))`;
      })
      .join("\n");

    const provides = slices
      .filter(
        (s): s is DecompSlice & { semantic_name: string } =>
          typeof s.semantic_name === "string" && s.semantic_name.length > 0,
      )
      .map((s) => `    PROVIDE(${s.name} = ${s.semantic_name});`);
    const providesBlock =
      provides.length > 0 ? `${provides.join("\n")}\n\n` : "";

    if (isArm) {
      return `/* REA Memory-Pinned Linker Script (Day 0 Link Invariant) */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x${imageBase.toString(16).padStart(8, "0")}, LENGTH = 1024K
    RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
${providesBlock}    .target_all : {
${sectionEntries}
    } > FLASH

    /DISCARD/ : {
        *(.note*)
        *(.comment*)
        *(.eh_frame*)
    }
}
`;
    }

    return `/* REA Memory-Pinned Linker Script (Day 0 Link Invariant) */
SECTIONS
{
${providesBlock}    . = 0x${imageBase.toString(16).padStart(8, "0")};
    .target_all : {
${sectionEntries}
    }

    /DISCARD/ : {
        *(.note*)
        *(.comment*)
        *(.eh_frame*)
    }
}
`;
  }
}
