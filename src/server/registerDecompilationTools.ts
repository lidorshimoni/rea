import type { McpServer, ServerContext } from "@modelcontextprotocol/server";
import type { BinarySessionPort } from "../application/BinarySession.js";
import { MatchingDecompilationService } from "../application/MatchingDecompilationService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { ToolContract } from "../contracts/toolContractTypes.js";
import type { DecompOperation } from "../domain/decompilationAnalysis.js";
import type { Logger } from "../logger.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult } from "./toolResult.js";

const DECOMPILATION_OPERATIONS: readonly DecompOperation[] = [
  "inspect_decomp_binary",
  "init_decomp_project",
  "split_decomp_slices",
  "build_decomp_unit",
  "check_decomp_unit",
  "permute_decomp_symbol",
  "sync_decomp_obligations",
  "enrich_decomp_symbols",
  "detect_decomp_libraries",
  "recover_decomp_macros",
  "annotate_decomp_source",
  "enrich_decomp_project",
  "rename_decomp_symbol",
];

/** Bind matching decompilation handlers to their exact named schemas. */
export const registerDecompilationTools = (
  server: McpServer,
  service: MatchingDecompilationService,
  logger: Logger,
  recordEvidence?: BinarySessionPort["recordEvidence"],
): void => {
  const handler =
    (contract: ToolContract<DecompOperation>) =>
    async (input: unknown, context: ServerContext) => {
      const result = await logToolExecution(logger, contract.name, () =>
        service.execute(contract.name, input, {
          signal: context.mcpReq.signal,
        }),
      );
      if (!result.ok) return toCallToolResult(result, contract);
      const recorded = recordEvidence?.(result.value);
      return recorded !== undefined && !recorded.ok
        ? toCallToolResult(recorded, contract)
        : toCallToolResult(result, contract);
    };

  for (const name of DECOMPILATION_OPERATIONS) {
    const contract = toolContract(name);
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
