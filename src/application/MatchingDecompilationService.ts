import { existsSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve, basename, dirname } from "node:path";
import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";
import { BinaryFingerprintScanner } from "./BinaryFingerprintScanner.js";
import { ProjectScaffolder } from "./ProjectScaffolder.js";
import { LinearPartitionSplicer } from "./LinearPartitionSplicer.js";
import { BuiltInObjectDiffer } from "./BuiltInObjectDiffer.js";
import { AstPermuter } from "./AstPermuter.js";
import { DwarfSymbolExtractor } from "./DwarfSymbolExtractor.js";
import { LibrarySignatureDetector } from "./LibrarySignatureDetector.js";
import { MacroConstantRecoverer } from "./MacroConstantRecoverer.js";
import { SourceCommentAnnotator } from "./SourceCommentAnnotator.js";
import { execFileOutput } from "../process/ExecFileOutput.js";
import { createAirgapEnv } from "../process/AirgapEnvironment.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceSubjectTarget,
} from "../domain/evidence.js";
import { evaluateReconstructionObligationLedger } from "./ReconstructionObligationLedgerEvaluation.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import type { BinaryArchitecture } from "../domain/binaryTargetTypes.js";
import {
  decompRequestSchema,
  decompProjectConfigSchema,
  type DecompOperation,
  type DecompBinaryFingerprint,
  type DecompProjectConfig,
  type DecompSliceManifest,
  type DecompBuildResult,
  type DecompDiffResult,
  type DecompPermuteResult,
  type DecompSyncObligationsResult,
  type DecompEnrichSymbolsResult,
  type DecompDetectLibrariesResult,
  type DecompRecoverMacrosResult,
  type DecompAnnotateSourceResult,
  type DecompEnrichProjectResult,
} from "../domain/decompilationAnalysis.js";
import {
  deriveReconstructionObligationCandidates,
  type ReconstructionObligationCandidate,
} from "./ReconstructionObligationCandidates.js";
import type {
  ReconstructionObligationManifest,
  ReviewedReconstructionObligation,
} from "../domain/reconstructionObligationLedgerSchemas.js";
import {
  createEvidenceBundle,
  type EvidenceBundle,
} from "../domain/evidenceBundle.js";

export const DECOMPILATION_PROVIDER = {
  id: "rea-decompilation",
  name: "REA matching decompilation provider",
  version: "1",
} as const;

/**
 * Master Matching Decompilation and Progressive Recompilation Application Service.
 * Unites reconnaissance scanner, modular scaffolder, linear partition splicer,
 * relocation-masked object differ, AST permuter, formal obligation ledger synchronizer,
 * and semantic enrichment suite (DWARF symbols, library detection, macro recovery, comment synthesis).
 */
export class MatchingDecompilationService {
  private readonly scanner = new BinaryFingerprintScanner();
  private readonly scaffolder = new ProjectScaffolder();
  private readonly splicer = new LinearPartitionSplicer();
  private readonly differ = new BuiltInObjectDiffer();
  private readonly permuter = new AstPermuter();
  private readonly dwarfExtractor = new DwarfSymbolExtractor();
  private readonly libraryDetector = new LibrarySignatureDetector();
  private readonly macroRecoverer = new MacroConstantRecoverer();
  private readonly commentAnnotator = new SourceCommentAnnotator();

  /** Unified application-level executor returning Evidence or AnalysisError. */
  async execute(
    operation: DecompOperation,
    input: unknown,
    options?: { signal?: AbortSignal | undefined },
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true) {
      return err(new AnalysisCancelledError(operation));
    }
    const parsed = decompRequestSchema.safeParse({ operation, input });
    if (!parsed.success) {
      return err(new AnalysisInputError(operation, { cause: parsed.error }));
    }

    try {
      const toJson = (val: unknown): JsonValue =>
        JSON.parse(JSON.stringify(val)) as JsonValue;
      let evidence: Evidence;
      switch (parsed.data.operation) {
        case "inspect_decomp_binary": {
          const targetPath = resolve(parsed.data.input.path);
          const targetBytes = await readFile(targetPath);
          const targetSha256 = createHash("sha256")
            .update(targetBytes)
            .digest("hex");
          const res = await this.inspectBinary(targetPath);
          evidence = createEvidence(
            this.toEvidenceTarget(
              targetPath,
              targetSha256,
              res.format,
              res.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.fingerprint",
              operation: "inspect_decomp_binary",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "observed",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "init_decomp_project": {
          const res = await this.initProject(parsed.data.input);
          evidence = createEvidence(
            this.toEvidenceTarget(
              res.target.path,
              res.target.sha256,
              res.target.format,
              res.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.project",
              operation: "init_decomp_project",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "derived",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "split_decomp_slices": {
          const res = await this.splitSlices(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              res.target_sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.slices",
              operation: "split_decomp_slices",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "derived",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "build_decomp_unit": {
          const res = await this.buildUnit(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.build",
              operation: "build_decomp_unit",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "observed",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "check_decomp_unit": {
          const res = await this.checkUnit(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.diff",
              operation: "check_decomp_unit",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "observed",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "permute_decomp_symbol": {
          const res = await this.permuteSymbol(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.permute",
              operation: "permute_decomp_symbol",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "observed",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "sync_decomp_obligations": {
          const res = await this.syncObligations(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.sync",
              operation: "sync_decomp_obligations",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "derived",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "enrich_decomp_symbols": {
          const res = await this.enrichSymbols(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.symbols",
              operation: "enrich_decomp_symbols",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "observed",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "detect_decomp_libraries": {
          const res = await this.detectLibraries(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.libraries",
              operation: "detect_decomp_libraries",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "inferred",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "recover_decomp_macros": {
          const res = await this.recoverMacros(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.macros",
              operation: "recover_decomp_macros",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "inferred",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "annotate_decomp_source": {
          const res = await this.annotateSource(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.annotations",
              operation: "annotate_decomp_source",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "derived",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
        case "enrich_decomp_project": {
          const res = await this.enrichProject(parsed.data.input);
          const config = await this.loadConfig(
            resolve(parsed.data.input.project_directory),
          );
          evidence = createEvidence(
            this.toEvidenceTarget(
              config.target.path,
              config.target.sha256,
              config.target.format,
              config.target.architecture,
            ),
            DECOMPILATION_PROVIDER,
            {
              predicateType: "rea.decompilation.enrichment",
              operation: "enrich_decomp_project",
              parameters: jsonObjectSchema.parse(toJson(parsed.data.input)),
              result: toJson(res),
              rawResult: null,
              confidence: "derived",
              authority: "shipped-artifact",
              environment: null,
              limitations: [],
              evidenceLinks: [],
            },
          );
          break;
        }
      }
      return ok(evidence);
    } catch (caught: unknown) {
      const message = caught instanceof Error ? caught.message : String(caught);
      return err(new AnalysisOutputError(operation, message));
    }
  }

  private mapToEvidenceFormat(format: string): "elf" | "pe" | "file" {
    if (format.startsWith("ELF")) return "elf";
    if (format.startsWith("PE")) return "pe";
    return "file";
  }

  private mapToEvidenceArchitecture(
    arch: string | undefined,
  ): BinaryArchitecture | undefined {
    switch (arch) {
      case "x86":
      case "x86_64":
      case "arm":
      case "arm64":
      case "arm-thumb":
      case "mips":
      case "powerpc":
      case "riscv":
        return arch;
      default:
        return undefined;
    }
  }

  private toEvidenceTarget(
    path: string,
    sha256: string,
    format: string,
    arch?: string,
  ): EvidenceSubjectTarget {
    const architecture = this.mapToEvidenceArchitecture(arch);
    return {
      path,
      sha256,
      format: this.mapToEvidenceFormat(format),
      ...(architecture !== undefined ? { architecture } : {}),
    };
  }

  /** 1. Inspect target binary or raw firmware image. */
  async inspectBinary(path: string): Promise<DecompBinaryFingerprint> {
    return this.scanner.scan(resolve(path));
  }

  /** 2. Scaffold authentic modular matching decompilation project. */
  async initProject(options: {
    readonly binary_path: string;
    readonly project_directory: string;
    readonly preset?: string | undefined;
  }): Promise<DecompProjectConfig> {
    return this.scaffolder.scaffold({
      binaryPath: options.binary_path,
      projectDirectory: options.project_directory,
      preset: options.preset,
    });
  }

  /** 3. Contiguous linear partitioning into relocatable assembly stubs. */
  async splitSlices(options: {
    readonly project_directory: string;
    readonly target_path?: string | undefined;
  }): Promise<DecompSliceManifest> {
    return this.splicer.split({
      projectDirectory: options.project_directory,
      targetPath: options.target_path,
    });
  }

  /** 4. Build single unit or relink entire binary for Day 0 invariant verification. */
  async buildUnit(options: {
    readonly project_directory: string;
    readonly symbol?: string | undefined;
    readonly unit?: string | undefined;
    readonly relink?: boolean | undefined;
  }): Promise<DecompBuildResult> {
    const projectDir = resolve(options.project_directory);
    const config = await this.loadConfig(projectDir);

    if (options.relink) {
      return this.relinkBinary(projectDir, config);
    }

    const symbol = options.symbol ?? "unit";
    return this.compileSingleUnit(projectDir, config, symbol, options.unit);
  }

  /** 5. Compare recompiled candidate object with target slice using relocation masking. */
  async checkUnit(options: {
    readonly project_directory: string;
    readonly symbol: string;
    readonly unit?: string | undefined;
  }): Promise<DecompDiffResult> {
    const projectDir = resolve(options.project_directory);
    const config = await this.loadConfig(projectDir);
    const symbol = options.symbol;

    // Ensure baseline expected .o and candidate compiled .o exist
    const expectedObj = join(
      projectDir,
      config.splicing.build_directory,
      "asm",
      "core",
      `${symbol}.o`,
    );
    const compiledObj = join(
      projectDir,
      config.splicing.build_directory,
      "src",
      "core",
      `${symbol}.o`,
    );

    // Build expected object if missing
    await this.ensureObjectBuilt(projectDir, config, symbol, "asm");
    // Build compiled object if missing
    await this.ensureObjectBuilt(projectDir, config, symbol, "src");

    return this.differ.diff({
      unit: options.unit ?? `src/core/${symbol}.c`,
      symbol,
      expectedPath: expectedObj,
      compiledPath: compiledObj,
    });
  }

  /** 6. Permute symbol source and compiler flags to climb toward 100% match. */
  async permuteSymbol(options: {
    readonly project_directory: string;
    readonly symbol: string;
    readonly unit?: string | undefined;
    readonly max_iters?: number | undefined;
    readonly strategy?: ("hierarchical" | "local_only") | undefined;
  }): Promise<DecompPermuteResult> {
    return this.permuter.permute({
      projectDirectory: options.project_directory,
      symbol: options.symbol,
      unit: options.unit,
      max_iters: options.max_iters,
      strategy: options.strategy,
    });
  }

  /** 7. Sync matched functions into ReconstructionObligationLedger under native-abi authority. */
  async syncObligations(options: {
    readonly project_directory: string;
  }): Promise<DecompSyncObligationsResult> {
    const projectDir = resolve(options.project_directory);
    const config = await this.loadConfig(projectDir);

    // Read slices manifest
    let manifest: DecompSliceManifest;
    try {
      const raw = await readFile(join(projectDir, "slices.json"), "utf8");
      manifest = JSON.parse(raw) as DecompSliceManifest;
    } catch {
      manifest = {
        target_sha256: config.target.sha256,
        total_slices: 0,
        slices: [],
        linker_script_path: "linker.ld",
      };
    }

    const verifiedSymbols: string[] = [];
    const reviewedObligations: ReviewedReconstructionObligation[] = [];
    const manifestBindings: ReconstructionObligationManifest["bindings"] = [];
    const evidenceList: Evidence[] = [];

    const mapFormat = (f: string) => {
      if (f.startsWith("ELF")) return "elf" as const;
      if (f.startsWith("PE")) return "pe" as const;
      return "file" as const;
    };

    // 1. Create baseline observation evidence for target binary
    const binaryEvidence = createEvidence(
      this.toEvidenceTarget(
        join(projectDir, config.target.path),
        config.target.sha256,
        config.target.format,
        config.target.architecture,
      ),
      DECOMPILATION_PROVIDER,
      {
        predicateType: "rea.binary.inspection",
        operation: "inspect_target_binary",
        parameters: {
          path: config.target.path,
          image_base: config.target.image_base,
        },
        result: {
          format: config.target.format,
          sha256: config.target.sha256,
          slices_count: manifest.slices.length,
        },
        rawResult: null,
        confidence: "observed",
        authority: "shipped-artifact",
        environment: null,
        limitations: [],
        evidenceLinks: [],
      },
    );
    evidenceList.push(binaryEvidence);

    // 2. Check each function slice and build reviewed obligations
    for (const slice of manifest.slices) {
      if (slice.type !== "function") continue;

      const obligationId = `native-abi:symbol:${slice.name}`;
      const srcFile = slice.source_file ?? `src/core/${slice.name}.c`;
      const fullSrcPath = join(projectDir, srcFile);
      const isLifted = slice.status === "lifted" || existsSync(fullSrcPath);

      let is100Percent = false;
      if (isLifted) {
        try {
          const diff = await this.checkUnit({
            project_directory: projectDir,
            symbol: slice.name,
            unit: srcFile,
          });
          if (diff.status === "matched" && diff.similarity === 1) {
            is100Percent = true;
            verifiedSymbols.push(slice.name);
            slice.status = "lifted";
          }
        } catch {
          // Not yet compilable or lifted
        }
      }

      const reviewed: ReviewedReconstructionObligation = {
        obligation_id: obligationId,
        obligation_version: 1,
        title: `Verify 1:1 matching decompilation for function ${slice.name}`,
        application_layer: "native-abi",
        family: "matching_decompilation",
        target: {
          artifact_sha256: config.target.sha256,
          application_node_id: null,
          semantic_node_id: null,
          location: `offset 0x${slice.offset.toString(16)}`,
        },
        required: isLifted,
        required_case_kinds: ["positive"],
        required_original_authority: "static",
        required_fixture_authority: "native-abi",
        required_verifier_authority: "native-abi",
        requires_parser_type: false,
        dependency_obligation_ids: [],
        residual_unknown_ids: [],
        unavailable_authority: [],
        required_next_evidence: [],
        disposition: isLifted ? "active" : "out-of-scope",
        review_evidence_ids: [binaryEvidence.evidence_id],
      };
      reviewedObligations.push(reviewed);

      if (is100Percent) {
        // Create authentic rea.reconstruction-proof Evidence
        const proofEvidence = createEvidence(
          this.toEvidenceTarget(
            join(projectDir, config.target.path),
            config.target.sha256,
            config.target.format,
            config.target.architecture,
          ),
          DECOMPILATION_PROVIDER,
          {
            predicateType: "rea.reconstruction-proof",
            operation: "verify_reconstruction_obligations",
            parameters: {
              symbol: slice.name,
              project_directory: projectDir,
            },
            result: {
              passed: true,
              obligation_ids: [obligationId],
              fixture_ids: ["target.bin"],
              case_kinds: ["positive"],
              verifier_ids: ["objdiff"],
              claim_ids: ["match_100_percent_bit_exact"],
            },
            rawResult: null,
            confidence: "observed",
            authority: "shipped-artifact",
            environment: null,
            limitations: [],
            evidenceLinks: [],
          },
        );
        evidenceList.push(proofEvidence);

        const ownerSha256 = createHash("sha256")
          .update(srcFile + ":" + slice.name)
          .digest("hex");

        manifestBindings.push({
          obligation_id: obligationId,
          owner: {
            module_path: srcFile,
            symbol: slice.name,
            owner_sha256: ownerSha256,
          },
          parser_type: null,
          original_cases: [
            {
              kind: "positive",
              evidence_id: binaryEvidence.evidence_id,
              location: `offset 0x${slice.offset.toString(16)}`,
            },
          ],
          fixtures: [
            {
              fixture_id: "target.bin",
              case_kind: "positive",
              authority: "native-abi",
              evidence_ids: [proofEvidence.evidence_id],
            },
          ],
          verifier: {
            verifier_id: "objdiff",
            claim_id: "match_100_percent_bit_exact",
            command: `rea check-decomp-unit --symbol ${slice.name}`,
            authority: "native-abi",
            status: "pass",
            result_evidence_id: proofEvidence.evidence_id,
            enumerated_obligation_ids: [obligationId],
            nondeterminism: {
              mode: "total-order",
              specification:
                "Deterministic instruction-level relocation-masked match.",
            },
          },
        });
      }
    }

    // Build evidence bundle
    const evidenceBundle = createEvidenceBundle(evidenceList);

    const obligationManifest: ReconstructionObligationManifest = {
      bindings: manifestBindings,
      contradictions: [],
    };

    // Derive candidates from reviewed obligations
    const { candidates, limitations } =
      deriveReconstructionObligationCandidates(
        evidenceBundle,
        reviewedObligations,
      );

    // Evaluate the ledger mathematically
    const ledger = evaluateReconstructionObligationLedger({
      candidates,
      bundle: evidenceBundle,
      manifest: obligationManifest,
      generationLimitations: limitations,
    });

    // Save updated slices and ledger.json
    await writeFile(
      join(projectDir, "slices.json"),
      JSON.stringify(manifest, null, 2),
      "utf8",
    );
    await writeFile(
      join(projectDir, "ledger.json"),
      JSON.stringify(ledger, null, 2),
      "utf8",
    );

    const isClosed =
      ledger.status === "ready" &&
      ledger.summary.required_open === 0 &&
      ledger.summary.verified > 0;

    return {
      verified_symbols: verifiedSymbols,
      total_obligations: reviewedObligations.length,
      ledger_closed: isClosed,
      closure_digest: isClosed ? ledger.closure_digest : undefined,
    };
  }

  private async loadConfig(projectDir: string): Promise<DecompProjectConfig> {
    const raw = await readFile(join(projectDir, "decomp.yaml"), "utf8");
    return decompProjectConfigSchema.parse(parseYaml(raw));
  }

  /** Ingests DWARF debug info to extract signatures, parameters, and structs. */
  async enrichSymbols(input: {
    readonly project_directory: string;
    readonly binary_path?: string | undefined;
    readonly output_header_dir?: string | undefined;
  }): Promise<DecompEnrichSymbolsResult> {
    const projectDir = resolve(input.project_directory);
    const config = await this.loadConfig(projectDir);
    const binaryPath = input.binary_path
      ? resolve(input.binary_path)
      : join(projectDir, config.target.path);
    return this.dwarfExtractor.extract({
      projectDirectory: projectDir,
      binaryPath,
      outputHeaderDir: input.output_header_dir,
    });
  }

  /** Detects statically linked 3rd-party libraries using in-tree signatures. */
  async detectLibraries(input: {
    readonly project_directory: string;
    readonly binary_path?: string | undefined;
    readonly signatures_path?: string | undefined;
    readonly use_llm_fallback?: boolean | undefined;
  }): Promise<DecompDetectLibrariesResult> {
    const projectDir = resolve(input.project_directory);
    const config = await this.loadConfig(projectDir);
    const binaryPath = input.binary_path
      ? resolve(input.binary_path)
      : join(projectDir, config.target.path);
    const signaturesPath =
      input.signatures_path ??
      config.enrichment?.library_signatures_path ??
      undefined;
    const useLlmFallback =
      input.use_llm_fallback ?? config.enrichment?.llm_fallback ?? true;
    return this.libraryDetector.detect({
      projectDirectory: projectDir,
      binaryPath,
      signaturesPath,
      useLlmFallback,
    });
  }

  /** Deterministically recovers magic numbers and constants into macros.h. */
  async recoverMacros(input: {
    readonly project_directory: string;
    readonly constants_path?: string | undefined;
    readonly target_source_path?: string | undefined;
  }): Promise<DecompRecoverMacrosResult> {
    const projectDir = resolve(input.project_directory);
    const config = await this.loadConfig(projectDir);
    const constantsPath =
      input.constants_path ??
      config.enrichment?.macro_constants_path ??
      undefined;
    return this.macroRecoverer.recover({
      projectDirectory: projectDir,
      constantsPath,
      targetSourcePath: input.target_source_path,
    });
  }

  /** Synthesizes structured Doxygen and intent comments for C source files. */
  async annotateSource(input: {
    readonly project_directory: string;
    readonly symbol?: string | undefined;
    readonly source_file?: string | undefined;
    readonly style?: "doxygen" | "intent" | "both" | undefined;
  }): Promise<DecompAnnotateSourceResult> {
    const projectDir = resolve(input.project_directory);
    return this.commentAnnotator.annotate({
      projectDirectory: projectDir,
      symbol: input.symbol,
      sourceFile: input.source_file,
      style: input.style,
    });
  }

  /** Master orchestrator coordinating all SDES enrichment modules. */
  async enrichProject(input: {
    readonly project_directory: string;
    readonly dwarf_symbols?: boolean | undefined;
    readonly library_detection?: boolean | undefined;
    readonly macro_recovery?: boolean | undefined;
    readonly comment_synthesis?: boolean | undefined;
  }): Promise<DecompEnrichProjectResult> {
    const projectDir = resolve(input.project_directory);
    const config = await this.loadConfig(projectDir);
    const enrichmentConfig = config.enrichment;

    const runDwarf =
      input.dwarf_symbols ?? enrichmentConfig?.dwarf_symbols ?? true;
    const runLibraries =
      input.library_detection ?? enrichmentConfig?.library_detection ?? true;
    const runMacros =
      input.macro_recovery ?? enrichmentConfig?.macro_recovery ?? true;
    const runComments =
      input.comment_synthesis ?? enrichmentConfig?.comment_synthesis ?? true;

    let dwarfResult: DecompEnrichSymbolsResult | undefined;
    if (runDwarf) {
      try {
        dwarfResult = await this.enrichSymbols({
          project_directory: projectDir,
        });
      } catch {
        // DWARF might not be present in stripped targets
      }
    }

    let libraryResult: DecompDetectLibrariesResult | undefined;
    if (runLibraries) {
      libraryResult = await this.detectLibraries({
        project_directory: projectDir,
      });
    }

    let macroResult: DecompRecoverMacrosResult | undefined;
    if (runMacros) {
      macroResult = await this.recoverMacros({
        project_directory: projectDir,
      });
    }

    let commentResult: DecompAnnotateSourceResult | undefined;
    if (runComments) {
      commentResult = await this.annotateSource({
        project_directory: projectDir,
      });
    }

    const summaryParts: string[] = [
      `Enriched project: ${config.name}.`,
      dwarfResult
        ? `Recovered ${dwarfResult.total_functions_recovered} functions and ${dwarfResult.total_types_recovered} types from DWARF.`
        : "No DWARF symbols extracted.",
      libraryResult
        ? `Detected ${libraryResult.total_libraries_detected} 3rd-party libraries (${libraryResult.total_symbols_identified} symbols).`
        : "No 3rd-party libraries detected.",
      macroResult
        ? `Recovered ${macroResult.total_macros} magic constants into ${macroResult.header_path}.`
        : "No macros recovered.",
      commentResult
        ? `Added ${commentResult.total_comments_added} comments across ${commentResult.annotated_files.length} files.`
        : "No comments synthesized.",
    ];

    return {
      project_directory: projectDir,
      dwarf_symbols: dwarfResult,
      library_detection: libraryResult,
      macro_recovery: macroResult,
      comment_synthesis: commentResult,
      summary: summaryParts.join(" "),
    };
  }

  private async ensureObjectBuilt(
    projectDir: string,
    config: DecompProjectConfig,
    symbol: string,
    mode: "asm" | "src",
  ): Promise<void> {
    const isArm = config.target.architecture === "arm-thumb";
    const asTool = isArm ? "arm-none-eabi-as" : "as";
    const ccTool = config.toolchain.compiler;

    if (mode === "asm") {
      const asmPath = join(projectDir, "asm", "core", `${symbol}.s`);
      const outDir = join(projectDir, "build", "asm", "core");
      const outPath = join(outDir, `${symbol}.o`);
      await mkdir(outDir, { recursive: true });

      try {
        await execFileOutput(
          asTool,
          [
            isArm ? "-mthumb" : "",
            "-I",
            projectDir,
            asmPath,
            "-o",
            outPath,
          ].filter(Boolean),
          { cwd: projectDir, env: createAirgapEnv() },
        );
      } catch {
        // Asm compilation failed or file not found
      }
    } else {
      const srcPath = join(projectDir, "src", "core", `${symbol}.c`);
      const outDir = join(projectDir, "build", "src", "core");
      const outPath = join(outDir, `${symbol}.o`);
      await mkdir(outDir, { recursive: true });

      try {
        await execFileOutput(
          ccTool,
          [
            ...config.toolchain.flags,
            "-I",
            join(projectDir, "include"),
            "-c",
            srcPath,
            "-o",
            outPath,
          ],
          { cwd: projectDir, env: createAirgapEnv() },
        );
      } catch {
        // C compilation failed or file not found
      }
    }
  }

  private async compileSingleUnit(
    projectDir: string,
    config: DecompProjectConfig,
    symbol: string,
    unit?: string,
  ): Promise<DecompBuildResult> {
    const srcFile = unit
      ? join(projectDir, unit)
      : join(projectDir, "src", "core", `${symbol}.c`);
    const outDir = join(projectDir, "build", "src", "core");
    const outFile = join(outDir, `${symbol}.o`);
    await mkdir(outDir, { recursive: true });

    try {
      const { stdout, stderr } = await execFileOutput(
        config.toolchain.compiler,
        [
          ...config.toolchain.flags,
          "-I",
          join(projectDir, "include"),
          "-c",
          srcFile,
          "-o",
          outFile,
        ],
        { cwd: projectDir, env: createAirgapEnv() },
      );

      // Also ensure baseline asm object is built for comparisons
      await this.ensureObjectBuilt(projectDir, config, symbol, "asm");

      return {
        unit: unit ?? `src/core/${symbol}.c`,
        symbol,
        success: true,
        compiler_output: (stdout + "\n" + stderr).trim(),
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        unit: unit ?? `src/core/${symbol}.c`,
        symbol,
        success: false,
        compiler_output: message,
      };
    }
  }

  private async relinkBinary(
    projectDir: string,
    config: DecompProjectConfig,
  ): Promise<DecompBuildResult> {
    const isArm = config.target.architecture === "arm-thumb";
    const ldTool = isArm ? "arm-none-eabi-ld" : "ld";
    const objcopyTool = isArm ? "arm-none-eabi-objcopy" : "objcopy";
    const asTool = isArm ? "arm-none-eabi-as" : "as";

    const buildDir = join(projectDir, config.splicing.build_directory);
    await mkdir(buildDir, { recursive: true });

    // Read slices to know object files to assemble & link
    let manifest: DecompSliceManifest;
    try {
      const raw = await readFile(join(projectDir, "slices.json"), "utf8");
      manifest = JSON.parse(raw) as DecompSliceManifest;
    } catch {
      return {
        success: false,
        compiler_output: `Cannot relink: slices.json missing. Run split_decomp_slices first.`,
        relink_success: false,
      };
    }

    const objFiles: string[] = [];

    // Assemble all slice stubs, replacing with lifted src .o where available
    for (const slice of manifest.slices) {
      const sliceAsm = join(projectDir, slice.asm_file);
      const sliceObj = join(
        buildDir,
        "asm",
        slice.asm_file.replace(/\.s$/, ".o"),
      );
      const srcObj = slice.source_file
        ? join(buildDir, "src", slice.source_file.replace(/\.c$/, ".o"))
        : undefined;

      await mkdir(dirname(sliceObj), { recursive: true });

      // Check if candidate .o exists and matches
      let useSrcObj = false;
      if (srcObj) {
        try {
          const diff = await this.differ.diff({
            unit: slice.source_file!,
            symbol: slice.name,
            expectedPath: sliceObj,
            compiledPath: srcObj,
          });
          if (diff.status === "matched" && diff.similarity === 1) {
            useSrcObj = true;
          }
        } catch {
          // Fall back to asm stub
        }
      }

      if (useSrcObj && srcObj) {
        objFiles.push(srcObj);
      } else {
        // Assemble asm stub
        try {
          await execFileOutput(
            asTool,
            [
              isArm ? "-mthumb" : "",
              "-I",
              projectDir,
              sliceAsm,
              "-o",
              sliceObj,
            ].filter(Boolean),
            { cwd: projectDir, env: createAirgapEnv() },
          );
          objFiles.push(sliceObj);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          return {
            success: false,
            compiler_output: `Assembling ${slice.asm_file} failed: ${message}`,
            relink_success: false,
          };
        }
      }
    }

    const relinkedElf = join(buildDir, "relinked.elf");
    const relinkedBin = join(buildDir, "relinked.bin");
    const linkerScript = join(projectDir, manifest.linker_script_path);

    try {
      // Link
      await execFileOutput(
        ldTool,
        ["-T", linkerScript, "-nostdlib", ...objFiles, "-o", relinkedElf],
        { cwd: projectDir, env: createAirgapEnv() },
      );

      // Objcopy to binary
      await execFileOutput(
        objcopyTool,
        ["-O", "binary", relinkedElf, relinkedBin],
        { cwd: projectDir, env: createAirgapEnv() },
      );

      // Verify SHA256 match
      const relinkedBytes = await readFile(relinkedBin);
      const relinkSha256 = createHash("sha256")
        .update(relinkedBytes)
        .digest("hex");
      const targetBytes = await readFile(join(projectDir, config.target.path));
      const targetSha256 = createHash("sha256")
        .update(targetBytes)
        .digest("hex");

      const fullMatch = relinkSha256 === targetSha256;

      return {
        success: true,
        compiler_output: `Relink successful. Parity match: ${fullMatch ? "100.0% EXACT" : "MISMATCH"}`,
        relink_success: true,
        relink_sha256: relinkSha256,
        target_sha256: targetSha256,
        full_binary_match: fullMatch,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        compiler_output: `Linker execution failed: ${message}`,
        relink_success: false,
      };
    }
  }
}
