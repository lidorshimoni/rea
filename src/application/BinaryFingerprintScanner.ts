import { readFile } from "node:fs/promises";
import type { DecompBinaryFingerprint } from "../domain/decompilationAnalysis.js";

/** Well-known MSVC Rich Header product ID descriptions. */
const MSVC_PRODUCT_IDS: Record<number, string> = {
  0x0093: "VS2008 SP1 C++ Compiler",
  0x0094: "VS2008 SP1 C Compiler",
  0x0095: "VS2008 SP1 MASM",
  0x0096: "VS2008 SP1 Linker",
  0x00aa: "VS2010 C++ Compiler",
  0x00ab: "VS2010 C Compiler",
  0x00ac: "VS2010 Linker",
  0x00eb: "VS2012 C++ Compiler",
  0x00ec: "VS2012 C Compiler",
  0x00ed: "VS2012 Linker",
  0x0103: "VS2013 C++ Compiler",
  0x0104: "VS2013 C Compiler",
  0x0105: "VS2013 MASM",
  0x0106: "VS2013 Linker",
  0x010d: "VS2015 C++ Compiler",
  0x010e: "VS2015 C Compiler",
  0x0107: "VS2015 Linker",
  0x0119: "VS2017 C++ Compiler",
  0x011a: "VS2017 C Compiler",
  0x011b: "VS2017 Linker",
  0x012b: "VS2019 C++ Compiler",
  0x012c: "VS2019 C Compiler",
  0x012d: "VS2019 Linker",
  0x013d: "VS2022 C++ Compiler",
  0x013e: "VS2022 C Compiler",
  0x013f: "VS2022 Linker",
};

/**
 * Scans a target binary or raw firmware image to detect format, architecture,
 * compiler signatures, and layout.
 */
export class BinaryFingerprintScanner {
  /** Inspect a binary file from filesystem. */
  async scan(filePath: string): Promise<DecompBinaryFingerprint> {
    const buffer = await readFile(filePath);
    return this.scanBuffer(buffer);
  }

  /** Inspect binary bytes directly. */
  scanBuffer(buffer: Buffer): DecompBinaryFingerprint {
    // 1. Check for ELF magic: 0x7F 'E' 'L' 'F'
    if (
      buffer.length >= 52 &&
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46
    ) {
      return this.scanElf(buffer);
    }

    // 2. Check for PE magic: 'M' 'Z' with e_lfanew
    if (buffer.length >= 64 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
      const peOffset = buffer.readUInt32LE(60);
      if (
        peOffset + 24 <= buffer.length &&
        buffer[peOffset] === 0x50 &&
        buffer[peOffset + 1] === 0x45 &&
        buffer[peOffset + 2] === 0x00 &&
        buffer[peOffset + 3] === 0x00
      ) {
        return this.scanPe(buffer, peOffset);
      }
    }

    // 3. Check for ARM Cortex-M Vector Table (firmware)
    const cortexM = this.tryScanCortexM(buffer);
    if (cortexM !== undefined) {
      return cortexM;
    }

    // Default unknown binary
    return {
      format: "UNKNOWN",
      architecture: "unknown",
      bits: 32,
      endianness: "little",
      image_base: "0x00000000",
      entry_point: "0x00000000",
      recommended_toolchain: "gcc",
      sections: [],
      feasible_1to1_match: false,
    };
  }

  private scanElf(buffer: Buffer): DecompBinaryFingerprint {
    const is64 = buffer[4] === 2;
    const isLittleEndian = buffer[5] === 1;
    const endianness = isLittleEndian ? "little" : "big";
    const bits = is64 ? 64 : 32;

    const readU16 = (o: number) =>
      isLittleEndian ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o);
    const readU32 = (o: number) =>
      isLittleEndian ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);
    const readU64 = (o: number) =>
      isLittleEndian ? buffer.readBigUInt64LE(o) : buffer.readBigUInt64BE(o);

    const machine = readU16(18);
    let architecture: DecompBinaryFingerprint["architecture"] = "unknown";
    let recommended_toolchain = "gcc";

    switch (machine) {
      case 3:
        architecture = "x86";
        recommended_toolchain = "gcc -m32";
        break;
      case 62:
        architecture = "x86_64";
        recommended_toolchain = "gcc";
        break;
      case 40:
        architecture = "arm";
        recommended_toolchain = "arm-none-eabi-gcc";
        break;
      case 183:
        architecture = "arm"; // aarch64
        recommended_toolchain = "aarch64-linux-gnu-gcc";
        break;
      case 8:
      case 10:
        architecture = "mips";
        recommended_toolchain = "mips-linux-gnu-gcc";
        break;
      case 20:
      case 21:
        architecture = "powerpc";
        recommended_toolchain = "powerpc-linux-gnu-gcc";
        break;
      case 243:
        architecture = "riscv";
        recommended_toolchain = "riscv64-unknown-elf-gcc";
        break;
    }

    const entryPoint = is64
      ? readU64(24).toString(16)
      : readU32(24).toString(16);
    const shOff = is64 ? Number(readU64(40)) : readU32(32);
    const shEntSize = readU16(is64 ? 58 : 46);
    const shNum = readU16(is64 ? 60 : 48);
    const shStrNdx = readU16(is64 ? 62 : 50);

    const sections: DecompBinaryFingerprint["sections"] = [];
    let detectedCompiler = "";

    if (
      shOff > 0 &&
      shOff + shNum * shEntSize <= buffer.length &&
      shStrNdx < shNum
    ) {
      const strTableHdrOff = shOff + shStrNdx * shEntSize;
      const strTableOff = is64
        ? Number(readU64(strTableHdrOff + 24))
        : readU32(strTableHdrOff + 16);

      for (let i = 0; i < shNum; i++) {
        const sOff = shOff + i * shEntSize;
        const nameIdx = readU32(sOff);
        const type = readU32(sOff + 4);
        const flags = is64
          ? readU64(sOff + 8).toString(16)
          : readU32(sOff + 8).toString(16);
        const addr = is64 ? readU64(sOff + 16) : BigInt(readU32(sOff + 12));
        const offset = is64 ? Number(readU64(sOff + 24)) : readU32(sOff + 16);
        const size = is64 ? Number(readU64(sOff + 32)) : readU32(sOff + 20);

        let sectionName = "";
        if (strTableOff + nameIdx < buffer.length) {
          const zeroIdx = buffer.indexOf(0, strTableOff + nameIdx);
          if (zeroIdx !== -1) {
            sectionName = buffer.toString(
              "utf8",
              strTableOff + nameIdx,
              zeroIdx,
            );
          }
        }

        if (sectionName) {
          sections.push({
            name: sectionName,
            virtual_address: `0x${addr.toString(16).padStart(8, "0")}`,
            virtual_size: size,
            raw_size: size,
            flags: `0x${flags}`,
          });

          // Look for .comment section for GCC/Clang version string
          if (sectionName === ".comment" && offset + size <= buffer.length) {
            const comment = buffer
              .toString("utf8", offset, offset + size)
              .replace(/\0/g, " ")
              .trim();
            if (comment) detectedCompiler = comment;
          }
        }
      }
    }

    if (detectedCompiler.includes("GCC")) {
      recommended_toolchain = detectedCompiler.split("\n")[0] ?? "gcc";
    } else if (detectedCompiler.includes("clang")) {
      recommended_toolchain = detectedCompiler.split("\n")[0] ?? "clang";
    }

    return {
      format: is64 ? "ELF64" : "ELF32",
      architecture,
      bits,
      endianness,
      image_base: sections[0]?.virtual_address ?? "0x00400000",
      entry_point: `0x${entryPoint.padStart(8, "0")}`,
      recommended_toolchain,
      sections,
      feasible_1to1_match: true,
    };
  }

  private scanPe(buffer: Buffer, peOffset: number): DecompBinaryFingerprint {
    const machine = buffer.readUInt16LE(peOffset + 4);
    const numSections = buffer.readUInt16LE(peOffset + 6);
    const optHeaderSize = buffer.readUInt16LE(peOffset + 20);
    const optHeaderOffset = peOffset + 24;

    const magic = buffer.readUInt16LE(optHeaderOffset);
    const is64 = magic === 0x20b; // PE32+
    const bits = is64 ? 64 : 32;

    let architecture: DecompBinaryFingerprint["architecture"] = "unknown";
    let recommended_toolchain = "msvc-19.x";

    if (machine === 0x14c) {
      architecture = "x86";
      recommended_toolchain = "cl.exe (x86)";
    } else if (machine === 0x8664) {
      architecture = "x86_64";
      recommended_toolchain = "cl.exe (x64)";
    } else if (machine === 0xaa64) {
      architecture = "arm";
      recommended_toolchain = "cl.exe (arm64)";
    }

    const entryPointRva = buffer.readUInt32LE(optHeaderOffset + 16);
    const imageBase = is64
      ? buffer.readBigUInt64LE(optHeaderOffset + 24)
      : BigInt(buffer.readUInt32LE(optHeaderOffset + 28));

    // Parse Sections
    const sectionHeadersOffset = optHeaderOffset + optHeaderSize;
    const sections: DecompBinaryFingerprint["sections"] = [];

    for (let i = 0; i < numSections; i++) {
      const sOff = sectionHeadersOffset + i * 40;
      if (sOff + 40 > buffer.length) break;

      const rawName = buffer
        .toString("utf8", sOff, sOff + 8)
        .replace(/\0/g, "")
        .trim();
      const virtualSize = buffer.readUInt32LE(sOff + 8);
      const virtualAddr = buffer.readUInt32LE(sOff + 12);
      const rawSize = buffer.readUInt32LE(sOff + 16);
      const characteristics = buffer.readUInt32LE(sOff + 36);

      sections.push({
        name: rawName,
        virtual_address: `0x${(imageBase + BigInt(virtualAddr)).toString(16).padStart(8, "0")}`,
        virtual_size: virtualSize,
        raw_size: rawSize,
        flags: `0x${characteristics.toString(16)}`,
      });
    }

    // Parse MSVC Rich Header between DOS header (0x40) and PE header
    const richHeader = this.parseRichHeader(buffer, peOffset);

    return {
      format: is64 ? "PE32+" : "PE32",
      architecture,
      bits,
      endianness: "little",
      image_base: `0x${imageBase.toString(16).padStart(8, "0")}`,
      entry_point: `0x${(imageBase + BigInt(entryPointRva)).toString(16).padStart(8, "0")}`,
      recommended_toolchain:
        richHeader?.compilers_detected[0] ?? recommended_toolchain,
      msvc_rich_header: richHeader,
      sections,
      feasible_1to1_match: true,
    };
  }

  private parseRichHeader(
    buffer: Buffer,
    peOffset: number,
  ): DecompBinaryFingerprint["msvc_rich_header"] | undefined {
    // Rich header ends with 'Rich' (0x68636952) followed by 4-byte XOR key
    const searchLimit = Math.min(peOffset, 1024);
    let richIndex = -1;

    for (let i = 0x40; i < searchLimit - 8; i += 4) {
      if (buffer.readUInt32LE(i) === 0x68636952) {
        richIndex = i;
        break;
      }
    }

    if (richIndex === -1) return undefined;

    const xorKey = buffer.readUInt32LE(richIndex + 4);
    // Walk backward to find 'DanS' XORed with xorKey
    const dansXored = 0x536e6144 ^ xorKey;
    let dansIndex = -1;

    for (let i = richIndex - 4; i >= 0x40; i -= 4) {
      if (buffer.readUInt32LE(i) === dansXored) {
        dansIndex = i;
        break;
      }
    }

    if (dansIndex === -1) return undefined;

    const entries: Array<{
      product_id: number;
      build_number: number;
      count: number;
      description: string;
    }> = [];
    const compilersDetected = new Set<string>();

    // Between dansIndex + 16 and richIndex are entries of 8 bytes: [comp_id_build, count]
    for (let i = dansIndex + 16; i < richIndex; i += 8) {
      const compIdBuild = buffer.readUInt32LE(i) ^ xorKey;
      const count = buffer.readUInt32LE(i + 4) ^ xorKey;
      const productId = (compIdBuild >> 16) & 0xffff;
      const buildNumber = compIdBuild & 0xffff;
      const desc =
        MSVC_PRODUCT_IDS[productId] ??
        `Unknown MSVC Tool (0x${productId.toString(16)})`;

      entries.push({
        product_id: productId,
        build_number: buildNumber,
        count,
        description: desc,
      });

      if (desc.includes("Compiler") || desc.includes("Linker")) {
        compilersDetected.add(`${desc} [Build ${buildNumber}]`);
      }
    }

    return {
      xor_key: `0x${xorKey.toString(16).padStart(8, "0")}`,
      compilers_detected: [...compilersDetected],
      entries,
    };
  }

  private tryScanCortexM(buffer: Buffer): DecompBinaryFingerprint | undefined {
    if (buffer.length < 64) return undefined;

    // Vector 0: Initial SP (points to SRAM: 0x20000000 - 0x20080000)
    const initialSp = buffer.readUInt32LE(0);
    // Vector 1: Reset_Handler (Thumb address in Flash: 0x08000000 - 0x08100000 or 0x00000000 - 0x00100000)
    const resetHandler = buffer.readUInt32LE(4);

    const isSramSp =
      (initialSp >= 0x20000000 && initialSp <= 0x200fffff) ||
      (initialSp >= 0x10000000 && initialSp <= 0x1000ffff); // CCRAM

    const isFlashReset =
      (resetHandler >= 0x08000000 && resetHandler <= 0x081fffff) ||
      (resetHandler >= 0x00000000 && resetHandler <= 0x001fffff);

    // In ARM Thumb, code addresses in vector table must have bit 0 set (Thumb bit)
    const hasThumbBit = (resetHandler & 1) === 1;

    if (isSramSp && isFlashReset && hasThumbBit) {
      const flashBase =
        resetHandler >= 0x08000000 ? "0x08000000" : "0x00000000";
      const sramBase = initialSp >= 0x20000000 ? "0x20000000" : "0x10000000";

      return {
        format: "ARM_CORTEX_M_RAW",
        architecture: "arm-thumb",
        bits: 32,
        endianness: "little",
        image_base: flashBase,
        entry_point: `0x${(resetHandler & ~1).toString(16).padStart(8, "0")}`,
        flash_base: flashBase,
        sram_base: sramBase,
        initial_sp: `0x${initialSp.toString(16).padStart(8, "0")}`,
        recommended_toolchain: "arm-none-eabi-gcc",
        sections: [
          {
            name: ".vectors",
            virtual_address: flashBase,
            virtual_size: 64,
            raw_size: 64,
            flags: "0x40",
          },
          {
            name: ".text",
            virtual_address: `0x${(BigInt(flashBase) + 64n).toString(16).padStart(8, "0")}`,
            virtual_size: Math.max(0, buffer.length - 64),
            raw_size: Math.max(0, buffer.length - 64),
            flags: "0x60000020",
          },
        ],
        feasible_1to1_match: true,
      };
    }

    return undefined;
  }
}
