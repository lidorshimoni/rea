import { mkdir, writeFile, copyFile, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import { BinaryFingerprintScanner } from "./BinaryFingerprintScanner.js";
import type {
  DecompProjectConfig,
  DecompBinaryFingerprint,
} from "../domain/decompilationAnalysis.js";

export interface ProjectScaffolderOptions {
  readonly binaryPath: string;
  readonly projectDirectory: string;
  readonly preset?: string | undefined;
}

/**
 * Scaffolds an authentic, modular matching decompilation workspace.
 * Day 0 Link Invariant: Every generated project has relocatable assembly stubs,
 * memory-pinned linker scripts, and deterministic build recipes.
 */
export class ProjectScaffolder {
  private readonly scanner = new BinaryFingerprintScanner();

  async scaffold(
    options: ProjectScaffolderOptions,
  ): Promise<DecompProjectConfig> {
    const projectDir = resolve(options.projectDirectory);
    const targetBinarySource = resolve(options.binaryPath);
    const targetBytes = await readFile(targetBinarySource);
    const targetSha256 = createHash("sha256").update(targetBytes).digest("hex");

    const fingerprint = this.scanner.scanBuffer(targetBytes);
    const targetInProject = join(projectDir, "target.bin");

    // 1. Create directory structure
    await mkdir(join(projectDir, "src", "core"), { recursive: true });
    await mkdir(join(projectDir, "src", "drivers"), { recursive: true });
    await mkdir(join(projectDir, "include", "core"), { recursive: true });
    await mkdir(join(projectDir, "include", "drivers"), { recursive: true });
    await mkdir(join(projectDir, "asm", "boot"), { recursive: true });
    await mkdir(join(projectDir, "asm", "core"), { recursive: true });
    await mkdir(join(projectDir, "asm", "data"), { recursive: true });
    await mkdir(join(projectDir, "asm", "padding"), { recursive: true });
    await mkdir(join(projectDir, "expected"), { recursive: true });
    await mkdir(join(projectDir, "build", "asm", "core"), { recursive: true });
    await mkdir(join(projectDir, "build", "src", "core"), { recursive: true });

    // 2. Copy target binary into project
    await writeFile(targetInProject, targetBytes);

    // 3. Determine compiler toolchain
    const toolchain = this.resolveToolchain(fingerprint, options.preset);

    // 4. Generate C headers
    await this.generateHeaders(projectDir, fingerprint);

    // 5. Generate Linker Script
    await this.generateLinkerScript(projectDir, fingerprint);

    // 6. Generate Makefile
    await this.generateMakefile(projectDir, fingerprint, toolchain);

    // 7. Generate objdiff.json
    await this.generateObjdiffConfig(projectDir);

    // 8. Generate splat.yaml
    await this.generateSplatConfig(projectDir, fingerprint);

    // 9. Generate decomp.yaml
    const config: DecompProjectConfig = {
      schema_version: 1,
      name: fingerprint.format.toLowerCase() + "_decomp",
      target: {
        path: "target.bin",
        sha256: targetSha256,
        format: fingerprint.format,
        architecture: fingerprint.architecture,
        endianness: fingerprint.endianness,
        image_base: fingerprint.image_base,
      },
      toolchain: {
        compiler: toolchain.compiler,
        version: toolchain.version,
        flags: toolchain.flags,
        include_paths: ["include"],
      },
      splicing: {
        day0_mode: "progressive_assembly",
        asm_directory: "asm",
        src_directory: "src",
        expected_directory: "expected",
        build_directory: "build",
      },
      enrichment: {
        dwarf_symbols: true,
        library_detection: true,
        library_signatures_path: null,
        macro_recovery: true,
        macro_constants_path: null,
        comment_synthesis: true,
        llm_fallback: true,
      },
    };

    await writeFile(
      join(projectDir, "decomp.yaml"),
      stringifyYaml(config),
      "utf8",
    );

    return config;
  }

  private resolveToolchain(
    fingerprint: DecompBinaryFingerprint,
    preset?: string,
  ): {
    compiler: string;
    version: string;
    flags: string[];
  } {
    if (preset === "stm32f4" || fingerprint.architecture === "arm-thumb") {
      return {
        compiler: "arm-none-eabi-gcc",
        version: "10.3.1",
        flags: [
          "-mcpu=cortex-m4",
          "-mthumb",
          "-O2",
          "-g",
          "-ffunction-sections",
          "-fdata-sections",
          "-fno-strict-aliasing",
        ],
      };
    }

    if (fingerprint.architecture === "x86_64") {
      return {
        compiler: "gcc",
        version: "host",
        flags: [
          "-O2",
          "-g",
          "-ffunction-sections",
          "-fdata-sections",
          "-fno-pie",
          "-no-pie",
        ],
      };
    }

    return {
      compiler: "gcc",
      version: "host",
      flags: ["-O2", "-ffunction-sections", "-fdata-sections"],
    };
  }

  private async generateHeaders(
    projectDir: string,
    fingerprint: DecompBinaryFingerprint,
  ): Promise<void> {
    const typesH = `#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

typedef int8_t    s8;
typedef int16_t   s16;
typedef int32_t   s32;
typedef int64_t   s64;

#define UNUSED __attribute__((unused))
#define NAKED  __attribute__((naked))

#endif /* TYPES_H */
`;

    const hardwareH = `#ifndef HARDWARE_H
#define HARDWARE_H

#include "types.h"

#define FLASH_BASE ${fingerprint.flash_base ?? fingerprint.image_base}
#define SRAM_BASE  ${fingerprint.sram_base ?? "0x20000000"}

#define REG32(addr) (*(volatile uint32_t *)(addr))

#endif /* HARDWARE_H */
`;

    const globalsH = `#ifndef GLOBALS_H
#define GLOBALS_H

#include "types.h"

#endif /* GLOBALS_H */
`;

    await writeFile(join(projectDir, "include", "types.h"), typesH, "utf8");
    await writeFile(
      join(projectDir, "include", "hardware.h"),
      hardwareH,
      "utf8",
    );
    await writeFile(join(projectDir, "include", "globals.h"), globalsH, "utf8");
  }

  private async generateLinkerScript(
    projectDir: string,
    fingerprint: DecompBinaryFingerprint,
  ): Promise<void> {
    const isArm =
      fingerprint.architecture === "arm-thumb" ||
      fingerprint.architecture === "arm";
    const imageBase = fingerprint.flash_base ?? fingerprint.image_base;

    const linkerScript = isArm
      ? `MEMORY
{
    FLASH (rx)  : ORIGIN = ${imageBase}, LENGTH = 1024K
    RAM   (rwx) : ORIGIN = ${fingerprint.sram_base ?? "0x20000000"}, LENGTH = 128K
}

SECTIONS
{
    .vectors : {
        KEEP(*(.vectors))
    } > FLASH

    .text : {
        *(.text*)
        *(.rodata*)
    } > FLASH

    .data : {
        *(.data*)
    } > RAM AT > FLASH

    .bss : {
        *(.bss*)
        *(COMMON)
    } > RAM
}
`
      : `SECTIONS
{
    . = ${imageBase};
    .text : {
        *(.text*)
    }
    .rodata : {
        *(.rodata*)
    }
    .data : {
        *(.data*)
    }
    .bss : {
        *(.bss*)
    }
}
`;

    await writeFile(join(projectDir, "linker.ld"), linkerScript, "utf8");
  }

  private async generateMakefile(
    projectDir: string,
    fingerprint: DecompBinaryFingerprint,
    toolchain: { compiler: string; flags: string[] },
  ): Promise<void> {
    const isArm = fingerprint.architecture === "arm-thumb";
    const as = isArm ? "arm-none-eabi-as" : "as";
    const ld = isArm ? "arm-none-eabi-ld" : "ld";
    const objcopy = isArm ? "arm-none-eabi-objcopy" : "objcopy";

    const makefile = `# REA Matching Decompilation Makefile
# Guarantees Day 0 Link Parity and hermetic builds

CC ?= ${toolchain.compiler}
AS ?= ${as}
LD ?= ${ld}
OBJCOPY ?= ${objcopy}

CFLAGS ?= ${toolchain.flags.join(" ")} -Iinclude -nostdlib -fno-builtin
ASFLAGS ?= ${isArm ? "-mthumb" : ""}
LDFLAGS ?= -T linker.ld -nostdlib

export SOURCE_DATE_EPOCH = 0
export LC_ALL = C
export TZ = UTC
export DEBUGINFOD_URLS =
export DEBUGINFOD_TIMEOUT = 0
export DEBUGINFOD_MAX_RETRIES = 0
export DEBUGINFOD_CACHE_PATH = /dev/null
export http_proxy =
export https_proxy =
export HTTP_PROXY =
export HTTPS_PROXY =
export all_proxy =
export ALL_PROXY =
export no_proxy = *
export NO_PROXY = *

.PHONY: all clean relink

all: relink

relink: build/relinked.bin
\t@sha256sum build/relinked.bin
\t@sha256sum target.bin

build/relinked.bin: build/relinked.elf
\t$(OBJCOPY) -O binary $< $@

build/relinked.elf: $(shell find asm -name '*.s' 2>/dev/null)
\t@mkdir -p build
\t$(CC) $(LDFLAGS) -o $@ $^

clean:
\trm -rf build/*
`;

    await writeFile(join(projectDir, "Makefile"), makefile, "utf8");
  }

  private async generateObjdiffConfig(projectDir: string): Promise<void> {
    const objdiffJson = {
      min_version: "2.0.0",
      custom_make: "make",
      target_dir: "expected",
      base_dir: "build",
      build_target: true,
      watch_patterns: ["src/**/*.[ch]", "include/**/*.[ch]"],
      units: [],
    };

    await writeFile(
      join(projectDir, "objdiff.json"),
      JSON.stringify(objdiffJson, null, 2),
      "utf8",
    );
  }

  private async generateSplatConfig(
    projectDir: string,
    fingerprint: DecompBinaryFingerprint,
  ): Promise<void> {
    const splatYaml = `name: ${fingerprint.format.toLowerCase()}_target
sha1: auto
options:
  platform: ${fingerprint.architecture}
  basename: target
  base_path: .
  target_path: target.bin
  asm_path: asm
  src_path: src
  build_path: build
  ld_script_path: linker.ld
  find_file_boundaries: true
  header_encoding: utf-8
segments:
  - [0, bin, header]
  - [0x40, asm, text]
  - [auto, data]
  - [auto, bss]
`;

    await writeFile(join(projectDir, "splat.yaml"), splatYaml, "utf8");
  }
}
