# Firmware Matching Decompilation & Source Reconstruction Roadmap

## Executive Summary

REA's Matching Decompilation Suite successfully achieved 100% bit-exact recompilation, Day 0 relink parity, and complete semantic naming on userland executables (such as stripped ELF64 SQLite). However, decompiling **arbitrary embedded and bare-metal firmware** into working, readable, recompilable source code introduces a fundamentally distinct set of physical and architectural constraints:

```
+----------------------------------------------------------------------------------------------------+
|                         USERLAND VS. BARE-METAL FIRMWARE DECOMPILATION                             |
+------------------------------------+------------------------------------+--------------------------+
| USERLAND EXECUTABLE (ELF / PE)     | BARE-METAL EMBEDDED FIRMWARE       | KEY ARCHITECTURAL GAP    |
+------------------------------------+------------------------------------+--------------------------+
| Standard OS loader & dynamic linker| No OS, no loader; flat SPI Flash   | Base address & memory map|
| Structured sections (.text, .rodata)| Raw binary blobs without headers   | Splicer offset inference |
| Standard libc POSIX system calls   | Direct MMIO hardware registers     | SVD / CMSIS register map |
| Host ABI (x86_64 System V, MS x64) | Thumb-2, RISC-V, Xtensa, TriCore   | Multi-arch cross toolchains|
| Execution begins at main() / _start| Hardware Reset Vector & NVIC / IVT | CRT & ISR reconstruction |
| Single linear execution / threads  | RTOS tasks (FreeRTOS, Zephyr)      | Concurrency & TCB recovery|
| Host simulation (./relinked.bin)   | Physical MCU & peripheral buses    | QEMU / Renode emulation  |
+------------------------------------+------------------------------------+--------------------------+
```

To bridge this gap and enable REA to turn **any raw firmware dump into compiling, usable source code**, eight major functional modules must be integrated into REA's domain and application layers.

---

## 1. Current State in REA

REA currently possesses initial building blocks for embedded firmware, but they are limited to heuristic scanning and container extraction:

1. **Firmware Extraction (`FirmwareProvider`)**:
   - Integrates Binwalk 3.1.0 and Unblob 26.6.4 to unpack containerized filesystems (SquashFS, UBIFS, CramFS, JFFS2, CPIO).
   - Designed for embedded Linux rootfs inspection, but does not decompile bare-metal microcontrollers or synthesize firmware source.
2. **Binary Fingerprinting (`BinaryFingerprintScanner`)**:
   - Contains `tryScanCortexM()` to detect 32-bit ARM Cortex-M NVIC tables (verifying that Vector 0 points to SRAM `0x20000000..0x200fffff` and Vector 1 points to Flash `0x08000000..0x081fffff`).
   - Does not support RISC-V, Xtensa, MIPS, AVR, or custom memory layouts.
3. **Project Scaffolding (`ProjectScaffolder`)**:
   - Contains a rudimentary `baremetal_arm_cortex_m` preset emitting a two-region linker script (`FLASH` and `RAM`).
   - Assumes GCC `arm-none-eabi-gcc` and thumb flags, but lacks hardware headers, register definitions, or vector tables.

---

## 2. Comprehensive Gap Analysis: The 8 Missing Capabilities

### Gap 1: Memory Map & Base Address Discovery for Flat Binaries

#### The Problem

Raw firmware dumps (from SPI NOR flash, NAND flash, or EEPROMs) have no ELF headers, section tables, or symbol tables. A binary extracted from flash might execute from `0x08000000` (STM32 Flash), `0x00000000` (NXP/Atmel), `0x00010000` (Nordic SoftDevice offset), or `0x40000000` (ESP32 IRAM).

If the image base address is incorrect by even a single byte:

- Literal pool pointers (e.g. `ldr r0, [pc, #offset]` $\to$ `0x08001234`) point to invalid memory.
- PC-relative switch/jump tables evaluate to illegal instructions.
- Cross-references to string literals and peripheral registers cannot be resolved.

#### Proposed Solution: Statistical Pointer & Cross-Reference Solver

Add `rea_infer_firmware_layout` to [`src/application/BinaryFingerprintScanner.ts`](file:///home/lidor/projects/rea/src/application/BinaryFingerprintScanner.ts):

1. **Pointer Cluster Frequency Scoring**: Scan 32-bit words in the binary and compute candidate base addresses $A_{\text{base}}$:
   $$\text{Score}(A_{\text{base}}) = \sum_{w \in \text{Words}} \mathbf{1}\left(A_{\text{base}} \le w < A_{\text{base}} + \text{Len}\right) \times \text{Validity}(w - A_{\text{base}})$$
   where validity checks whether the dereferenced target is a valid instruction alignment (Thumb: odd address, ARM/RISC-V: 4-byte aligned).
2. **String Table Alignment**: Correlate pointers against identified ASCII/UTF-8 string boundaries.
3. **RAM Boundary Inference**: Identify pointers falling outside the flash image boundary but clustered within known SRAM ranges (`0x20000000` for ARM, `0x3FFB0000` for ESP32).

---

### Gap 2: Peripheral & MMIO Register Mapping (SVD / CMSIS / ATDF Parser)

#### The Problem

Firmware interacts with physical hardware through Memory-Mapped I/O (MMIO). A standard decompiler outputs unreadable pointer arithmetic:

```c
// What raw decompilers produce:
*(volatile uint32_t *)0x40021018 |= 0x00000004;
*(volatile uint32_t *)0x40011004 = 0x444444b4;
*(volatile uint32_t *)0x4001100c = 0x00000010;
```

Without domain context, an analyst or AI agent cannot determine that this code enables GPIO Port C clock, sets Pin 13 to output mode, and toggles the onboard LED.

#### Proposed Solution: SVD / CMSIS Hardware Header Synthesis

Add `rea_import_firmware_svd` to REA:

1. **CMSIS-SVD (System View Description) Ingestion**: Ingest standard XML-based SVD files published by chip vendors (ST, NXP, Microchip, TI, Espressif, Nordic, Raspberry Pi).
2. **Automated Header Synthesis**: Generate [`include/hardware.h`](file:///home/lidor/projects/rea/scratch/opencode_cleanroom/include/hardware.h) containing exact peripheral struct layouts:
   ```c
   typedef struct {
       volatile uint32_t MODER;
       volatile uint32_t OTYPER;
       volatile uint32_t OSPEEDR;
       volatile uint32_t PUPDR;
       volatile uint32_t IDR;
       volatile uint32_t ODR;
       volatile uint32_t BSRR;
   } GPIO_TypeDef;

   #define GPIOC ((GPIO_TypeDef *)0x40020800)
   #define RCC   ((RCC_TypeDef *)0x40023800)
   ```
3. **AST MMIO Transpilation**: [`DecompilerAstTranspiler.ts`](file:///home/lidor/projects/rea/src/application/DecompilerAstTranspiler.ts) rewrites raw pointer dereferences into symbolic peripheral accesses:
   ```c
   // Transpiled readable source code:
   RCC->AHB1ENR |= RCC_AHB1ENR_GPIOCEN;
   GPIOC->MODER |= GPIO_MODER_MODER13_0;
   GPIOC->BSRR = GPIO_PIN_13;
   ```

---

### Gap 3: Interrupt Vector Tables (IVT) & CRT Startup Decompilation

#### The Problem

Userland applications start at `_start()` or `main()`. Bare-metal firmware starts at hardware power-on through the Interrupt Vector Table (IVT):

1. Hardware loads Initial Stack Pointer from offset `0x00` and branches to `Reset_Handler` at offset `0x04`.
2. `Reset_Handler` executes the C Runtime initialization (CRT):
   - Copies initialized `.data` variables from Flash (LMA) to SRAM (VMA).
   - Zeroes the uninitialized `.bss` segment in SRAM.
   - Initializes system clocks (`SystemInit`).
   - Jumps to `main()`.
3. Asynchronous peripheral events trigger Interrupt Service Routines (ISRs): `SysTick_Handler`, `USART1_IRQHandler`, `DMA1_Stream0_IRQHandler`.

#### Proposed Solution: IVT & CRT Reconstruction Engine

Add `rea_reconstruct_firmware_startup`:

1. **Vector Table Decoder**: Automatically parse the initial vector table matching the MCU architecture (ARM NVIC, RISC-V MTVEC, Xtensa exception vectors).
2. **ISR Binding**: Map interrupt vectors to designated semantic C functions (`EXTI0_IRQHandler`, `TIM2_IRQHandler`).
3. **CRT Splicing**: Recognize and isolate the flash-to-RAM `memcpy` and `.bss` `memset` loops, generating a canonical `startup_<mcu>.c` and exporting linker memory boundaries (`_sidata`, `_sdata`, `_edata`, `_sbss`, `_ebss`).

---

### Gap 4: Cross-Architecture & Multi-Toolchain Splicing Matrix

#### The Problem

SQLite ran on `x86_64` using host `gcc` and GNU `as`. Embedded firmware spans diverse architectures and proprietary toolchains:

| Architecture         | Common Processors         | Instruction Set Peculiarities                                             |
| :------------------- | :------------------------ | :------------------------------------------------------------------------ |
| **ARM Cortex-M**     | STM32, nRF52, SAMD, LPC   | Thumb-2 (16/32-bit mix), IT conditional blocks, literal pools             |
| **ARM Cortex-A / R** | Allwinner, i.MX, Zynq     | ARM/Thumb interworking (`bx`, `.thumb_func`, `.arm`)                      |
| **RISC-V (RV32/64)** | ESP32-C3/C6, CH32V, GD32V | Relaxed PC-relative jumps (`auipc`), compressed instructions (RVC)        |
| **Xtensa**           | ESP8266, ESP32, ESP32-S3  | Windowed register ABI (`entry`, `rotw`), literal pools preceding function |
| **MIPS / microMIPS** | Atheros, MediaTek routers | Branch delay slots, `$gp` relative global data addressing                 |

Furthermore, industrial firmware is compiled with proprietary toolchains:

- **Keil ArmCC (v5) / ArmClang (v6)**: Custom register calling conventions, stack guards, and micro-inlining.
- **IAR Embedded Workbench (`iccarm`)**: Unique section naming conventions (`.iar.init_table`, `??DataTable`).
- **Espressif ESP-IDF Toolchain**: Non-standard Xtensa GCC toolchain with ESP32 ROM function linking.

#### Proposed Solution: Multi-Architecture Toolchain Adapter

1. **Instruction Set Mode Tracking**: Enhance [`LinearPartitionSplicer.ts`](file:///home/lidor/projects/rea/src/application/LinearPartitionSplicer.ts) to track execution modes (e.g. `.thumb` vs `.arm`, `.option rvc` vs `.option norvc`).
2. **Literal Pool Relocation**: In ARM Thumb-2 and Xtensa, constant pools (`.word 0x...`) are placed inside the `.text` section right after unconditional jumps. The slicer must group literal pools with their parent function slice to prevent broken references.
3. **Containerized Toolchain Engine**: Supply containerized cross-compilers (`arm-none-eabi-gcc`, `riscv-none-elf-gcc`, `xtensa-esp32-elf-gcc`) managed hermetically via REA.

---

### Gap 5: Multi-Region Memory Splicing (LMA vs VMA Flash/RAM Splicing)

#### The Problem

In userland executables, Virtual Memory Address (VMA) equals Load Memory Address (LMA).
In microcontrollers:

- Flash is read-only at LMA `0x08000000`.
- Initialized `.data` variables are stored in Flash (LMA `0x08040000`), but must be accessed in SRAM at VMA `0x20000000`.
- Specialized microcontrollers have heterogeneous SRAM banks: Core-Coupled Memory (CCM/TCM at `0x10000000`), Backup SRAM, and external SPI RAM.

#### Proposed Solution: Dual-Address Splicing

Update [`LinearPartitionSplicer.ts`](file:///home/lidor/projects/rea/src/application/LinearPartitionSplicer.ts) and linker script generator:

1. Generate dual-memory linker regions:
   ```ld
   MEMORY
   {
       FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
       SRAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
       CCMRAM (rw) : ORIGIN = 0x10000000, LENGTH = 64K
   }
   SECTIONS
   {
       .text : { *(.text*) *(.rodata*) } > FLASH
       .data : {
           _sdata = .;
           *(.data*)
           _edata = .;
       } > SRAM AT > FLASH
       _sidata = LOADADDR(.data);
       .bss : {
           _sbss = .;
           *(.bss*) *(COMMON)
           _ebss = .;
       } > SRAM
   }
   ```
2. Correctly associate initial data values with their Flash storage location while referencing their RAM runtime symbols in C code.

---

### Gap 6: RTOS Kernel & Task Model Decompilation

#### The Problem

Modern IoT firmware does not execute a single `while(1)` super-loop in `main()`. Instead, it initializes an RTOS (FreeRTOS, Zephyr, ThreadX, uC/OS, RT-Thread) and spawns concurrent tasks:

```c
xTaskCreate(vTelemetryTask, "telemetry", 512, NULL, 3, &xTelemetryHandle);
xTaskCreate(vNetworkTask,   "network",  1024, NULL, 2, &xNetworkHandle);
vTaskStartScheduler();
```

Decompilers treating the call graph as a single tree miss the entire concurrency model, task priorities, inter-task communication (queues, semaphores, mutexes, event groups), and task stack layouts.

#### Proposed Solution: RTOS Deconstruction Pass

Add `rea_detect_rtos_objects` to REA:

1. **Kernel Signature Recognition**: Detect RTOS kernel versions and data structures (e.g. FreeRTOS `pxCurrentTCB`, `pxReadyTasksLists`, `xSuspendedTaskList`).
2. **Task Graph Synthesis**: Automatically trace all `xTaskCreate` / `k_thread_create` invocations to construct a concurrency map showing every thread entry point, assigned priority, stack allocation, and associated queues.
3. **Kernel De-synthesis**: Offer the option to replace the binary's inlined RTOS kernel routines with clean, upstream open-source RTOS headers and sources.

---

### Gap 7: Vendor HAL & SDK Signature Database

#### The Problem

In firmware binaries, **60% to 85% of total code volume consists of vendor SDK boilerplate**:

- STM32Cube HAL/LL (`HAL_UART_Transmit`, `HAL_GPIO_Init`, `HAL_RCC_ClockConfig`)
- Espressif ESP-IDF (`esp_wifi_init`, `esp_http_client_perform`, `nvs_flash_init`)
- Nordic nRF5 SDK / SoftDevice BLE stacks (`sd_ble_gap_adv_start`)
- NXP MCUXpresso / Microchip Harmony

Decompiling thousands of repetitive vendor driver functions wastes massive token budgets and generates brittle, non-standard code.

#### Proposed Solution: Curated Embedded SDK Signature Catalog

Expand [`src/data/signatures/defaultSignatures.ts`](file:///home/lidor/projects/rea/src/data/signatures/defaultSignatures.ts):

1. **Curated SDK Signatures**: Ingest FLIRT patterns and opcode hash trees for popular versions of STM32Cube, ESP-IDF, and nRF SDK.
2. **SDK Replacement & Linking**: When an SDK function is identified with $\ge 95\%$ confidence, REA replaces its assembly stub with the authentic vendor C source or links directly against the vendor static archive (`libstm32_hal.a`).
3. **Targeted Lifting**: Focus 100% of the decompiler's reasoning capacity on the proprietary application logic (state machines, custom protocols, crypto, algorithms).

---

### Gap 8: Emulation & Dynamic Execution Verification (Renode / QEMU Harness)

#### The Problem

For a host Linux executable, verification is simple: execute `./build/relinked.bin` and assert stdout/exit code.
For bare-metal firmware, an analyst rarely has the exact physical PCB, programmer (J-Link / ST-Link), or logic analyzer connected to the developer machine. Furthermore, running code on physical hardware carries bricking risks.

#### Proposed Solution: Automated Emulation Harness Generator

Add `rea_scaffold_emulation_harness`:

1. **Renode / QEMU Configuration Synthesis**: Generate automated [Renode](https://renode.io/) `.resc` scripts or `qemu-system-arm` invocation commands:
   ```python
   # Generated renode harness (machine.resc)
   mach create "stm32f4"
   machine LoadPlatformDescription @platforms/cpus/stm32f4_discovery.repl
   sysbus LoadELF @build/relinked.elf
   emulation CreateServerSocketTerminal 1234 "term"
   connector Connect sysbus.usart1 term
   start
   ```
2. **Virtual Peripheral Stubs**: Stub serial UART, SPI flash responses, and I2C sensors so the reconstructed firmware boots, passes self-tests, and emits readable console output in headless CI.

---

## 3. Prioritized Implementation Roadmap

```
+----------------------------------------------------------------------------------------------------+
|                               FIRMWARE DECOMPILATION ROADMAP PHASES                                |
+------------------------------------+------------------------------------+--------------------------+
| PHASE 1: HARDWARE SEMANTICS (P0)   | PHASE 2: RUNTIME & SPLICER (P1)    | PHASE 3: VERIFICATION    |
| - SVD / CMSIS Header Synthesizer   | - IVT & CRT Startup Decompiler     | - RTOS Task Model Solver |
| - Base Address Clustering Solver   | - Thumb-2 / RISC-V Mode Splicer    | - Vendor SDK Signatures  |
| - Memory Map & Boundary Detector   | - Flash/RAM LMA vs VMA Splicer     | - Renode / QEMU Harness  |
+------------------------------------+------------------------------------+--------------------------+
```

|      Phase       | Milestone Name                      | New MCP Tools & CLI Commands                                              | Deliverables & Artifacts                                                                                                                                |
| :--------------: | :---------------------------------- | :------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Phase 1 (P0)** | **Hardware Semantics & Addressing** | `rea_import_firmware_svd`<br>`rea_infer_firmware_layout`                  | • SVD parser producing `include/hardware.h`<br>• Statistical base address solver for flat `.bin`<br>• Transpiler rewriting raw MMIO pointers to structs |
| **Phase 2 (P1)** | **Architecture & Startup CRT**      | `rea_reconstruct_firmware_startup`<br>`rea_build_decomp_unit (arm/riscv)` | • Vector Table decoder & `startup_<mcu>.c`<br>• ARM Thumb-2 literal pool grouper in splicer<br>• LMA/VMA multi-memory linker script generator           |
| **Phase 3 (P2)** | **Ecosystem & RTOS Recovery**       | `rea_detect_rtos_objects`<br>`rea_import_vendor_sdk`                      | • FreeRTOS / Zephyr task and queue graph extractor<br>• Vendor SDK signature database (STM32, ESP-IDF)<br>• Automated SDK stub substitution             |
| **Phase 4 (P3)** | **Dynamic Emulation & Testing**     | `rea_scaffold_emulation_harness`<br>`rea_test_firmware_emulation`         | • Renode / QEMU script generator<br>• Headless UART boot test runner<br>• End-to-end firmware matching decompilation benchmark                          |

---

## 4. Proposed MCP Tool Contracts

### 1. `rea_import_firmware_svd`

```json
{
  "name": "import_firmware_svd",
  "description": "Imports a CMSIS-SVD hardware description file to generate symbolic peripheral headers and MMIO struct mappings.",
  "parameters": {
    "project_directory": { "type": "string" },
    "svd_path": {
      "type": "string",
      "description": "Path to CMSIS-SVD XML file or standard chip identifier (e.g. 'STM32F407')"
    },
    "output_header": { "type": "string", "default": "include/hardware.h" }
  }
}
```

### 2. `rea_infer_firmware_layout`

```json
{
  "name": "infer_firmware_layout",
  "description": "Statistically analyzes pointer tables, literal pools, and string boundaries to discover the image base address and SRAM layout of a raw flat binary.",
  "parameters": {
    "binary_path": { "type": "string" },
    "architecture": {
      "type": "string",
      "enum": ["arm-thumb", "arm", "riscv32", "riscv64", "xtensa", "mips"]
    }
  }
}
```

### 3. `rea_reconstruct_firmware_startup`

```json
{
  "name": "reconstruct_firmware_startup",
  "description": "Decompiles the Interrupt Vector Table (IVT), Reset_Handler, Flash-to-RAM copy loop, and BSS-zeroing sequence into a standard C startup file.",
  "parameters": {
    "project_directory": { "type": "string" },
    "vector_table_address": { "type": "string", "default": "0x08000000" }
  }
}
```

### 4. `rea_scaffold_emulation_harness`

```json
{
  "name": "scaffold_emulation_harness",
  "description": "Generates a headless Renode or QEMU virtual machine test harness to verify firmware execution and UART console output.",
  "parameters": {
    "project_directory": { "type": "string" },
    "emulator": { "type": "string", "enum": ["renode", "qemu"] },
    "target_platform": {
      "type": "string",
      "description": "e.g. 'stm32f4_discovery', 'esp32', 'virt-riscv'"
    }
  }
}
```

---

## 5. Summary

With these eight capabilities, REA will expand beyond desktop/server ELF/PE binaries into a universal embedded reverse engineering and matching decompilation platform. Analysts and autonomous agents will be able to supply a raw SPI flash dump or microcontroller binary and obtain a clean, compilable C99/C++ project with genuine peripheral structs, authentic vector tables, and verifiable bit-exact relink parity.
