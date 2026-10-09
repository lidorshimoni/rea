#!/usr/bin/env node

import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const runtimeFiles = [
  "dist/server/registerDecompilationTools.js",
  "dist/application/MatchingDecompilationService.js",
  "dist/logger.js",
];

async function compiledRuntimeExists(paths) {
  for (const path of paths) {
    try {
      await access(resolve(packageRoot, path));
    } catch {
      return false;
    }
  }
  return true;
}

if (!(await compiledRuntimeExists(runtimeFiles))) {
  process.stderr.write(
    `REA's compiled runtime is missing. Run \`npm run build:cached\` in ${packageRoot} to build REA first.\n`,
  );
  process.exitCode = 1;
} else {
  const { registerDecompilationTools } =
    await import("../dist/server/registerDecompilationTools.js");
  const { MatchingDecompilationService } =
    await import("../dist/application/MatchingDecompilationService.js");
  const { silentLogger } = await import("../dist/logger.js");

  const createServer = () => {
    const service = new MatchingDecompilationService();
    const server = new McpServer(
      {
        name: "rea-decompilation",
        version: "4.1.0",
      },
      {
        capabilities: {},
        instructions:
          "REA Matching Decompilation and Progressive Recompilation MCP Server. Exposes 13 surgical reverse engineering, slicing, relocation-masked diffing, permutation, and semantic naming tools.",
      },
    );
    registerDecompilationTools(server, service, silentLogger);
    return server;
  };

  const handle = serveStdio(createServer);

  const shutdown = async () => {
    try {
      await handle.close();
    } finally {
      process.exit(0);
    }
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  process.stdin.once("end", shutdown);
  process.stdin.once("close", shutdown);
}
