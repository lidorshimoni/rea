import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const entrypoint = resolve(
  process.env.REA_CLI_ENTRYPOINT ?? join(repository, "scripts/rea.mjs"),
);

// Preflight required host toolchain
const requiredTools = ["gcc", "as", "ld", "objdump"];
for (const tool of requiredTools) {
  try {
    await exec(tool, ["--version"]);
  } catch {
    process.stderr.write(
      `Preflight check failed: '${tool}' is not available in PATH.\n` +
        `Matching decompilation verification lane requires GNU binutils and GCC.\n`,
    );
    process.exit(1);
  }
}

const cli = async (args) => {
  const response = await exec(
    process.execPath,
    [entrypoint, ...args, "--format", "json"],
    {
      cwd: repository,
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  return JSON.parse(response.stdout);
};

console.log(
  "==> Running Matching Decompilation & Progressive Recompilation verification...",
);

const tempDir = await mkdtemp(join(tmpdir(), "rea-verify-decomp-"));

try {
  const fixtureDir = join(repository, "tests", "fixtures", "decomp");
  const targetBin = join(tempDir, "target.bin");
  const projectDir = join(tempDir, "project");

  // Step 1: Compile authentic fixture binary
  console.log("--> Compiling target binary from authentic C fixtures...");
  await exec("gcc", [
    "-O2",
    "-fno-pie",
    "-no-pie",
    "-ffunction-sections",
    join(fixtureDir, "main.c"),
    join(fixtureDir, "crc32.c"),
    join(fixtureDir, "globals.c"),
    join(fixtureDir, "jump_tables.c"),
    "-o",
    targetBin,
  ]);

  // Step 2: CLI inspect-decomp-binary
  console.log("--> CLI: inspect-decomp-binary...");
  const inspectEvidence = await cli(["inspect-decomp-binary", targetBin]);
  assert.equal(inspectEvidence.predicate_type, "rea.decompilation.fingerprint");
  const fp = inspectEvidence.normalized_result;
  assert.equal(fp.architecture, "x86_64");
  assert.equal(fp.format, "ELF64");
  console.log(
    `    Binary architecture: ${fp.architecture}, format: ${fp.format}`,
  );

  // Step 3: CLI init-decomp-project
  console.log("--> CLI: init-decomp-project...");
  const initEvidence = await cli([
    "init-decomp-project",
    targetBin,
    projectDir,
  ]);
  assert.equal(initEvidence.predicate_type, "rea.decompilation.project");
  console.log("    Project scaffolded successfully.");

  // Step 4: CLI split-decomp-slices
  console.log("--> CLI: split-decomp-slices...");
  const splitEvidence = await cli(["split-decomp-slices", projectDir]);
  assert.equal(splitEvidence.predicate_type, "rea.decompilation.slices");
  const manifest = splitEvidence.normalized_result;
  assert.ok(manifest.total_slices > 0, "Must create slices");
  console.log(
    `    Created ${manifest.total_slices} slices with linear partitioning.`,
  );

  // Step 5: Day 0 Link Invariant Verification
  console.log(
    "--> CLI: build-decomp-unit --relink (verifying Day 0 Link Invariant)...",
  );
  const relinkEvidence = await cli([
    "build-decomp-unit",
    projectDir,
    "--relink",
  ]);
  assert.equal(relinkEvidence.predicate_type, "rea.decompilation.build");
  const relinkResult = relinkEvidence.normalized_result;
  assert.equal(relinkResult.relink_success, true, "Relink must succeed");
  assert.equal(
    relinkResult.full_binary_match,
    true,
    "Must be 100% bit-exact match",
  );
  assert.equal(relinkResult.relink_sha256, relinkResult.target_sha256);
  console.log(
    `    Day 0 Link Invariant VERIFIED: 100.0% bit-exact SHA256 match!`,
  );

  // Step 6: Progressive Function Lifting & Relocation-Masked Diffing
  console.log(
    "--> Progressive lifting: copying authentic crc32.c into src/core/crc32.c...",
  );
  await writeFile(
    join(projectDir, "src", "core", "crc32.c"),
    await readFile(join(fixtureDir, "crc32.c"), "utf8"),
  );

  console.log("--> CLI: check-decomp-unit crc32...");
  const checkEvidence = await cli(["check-decomp-unit", projectDir, "crc32"]);
  assert.equal(checkEvidence.predicate_type, "rea.decompilation.diff");
  const diffResult = checkEvidence.normalized_result;
  assert.equal(diffResult.status, "matched");
  assert.equal(diffResult.similarity, 1);
  assert.equal(diffResult.match_percent, 100);
  assert.equal(diffResult.sample_mismatches.length, 0);
  console.log(
    "    Relocation-masked diffing VERIFIED: 100.0% machine code match for crc32!",
  );

  // Step 7: CLI permute-decomp-symbol
  console.log("--> CLI: permute-decomp-symbol crc32...");
  const permuteEvidence = await cli([
    "permute-decomp-symbol",
    projectDir,
    "crc32",
    "--max-iters",
    "2",
  ]);
  assert.equal(permuteEvidence.predicate_type, "rea.decompilation.permute");
  const permuteResult = permuteEvidence.normalized_result;
  assert.equal(permuteResult.best_similarity, 1);
  console.log("    Permutation engine verified.");

  // Step 8: Cryptographic Obligation Closure
  console.log(
    "--> CLI: sync-decomp-obligations (closing ReconstructionObligationLedger)...",
  );
  const syncEvidence = await cli(["sync-decomp-obligations", projectDir]);
  assert.equal(syncEvidence.predicate_type, "rea.decompilation.sync");
  const syncResult = syncEvidence.normalized_result;
  assert.ok(syncResult.verified_symbols.includes("crc32"));
  assert.equal(
    syncResult.ledger_closed,
    true,
    "Ledger must achieve mathematical closure",
  );
  assert.ok(
    typeof syncResult.closure_digest === "string" &&
      syncResult.closure_digest.length === 64,
  );

  const ledgerRaw = await readFile(join(projectDir, "ledger.json"), "utf8");
  const ledger = JSON.parse(ledgerRaw);
  assert.equal(ledger.status, "ready");
  assert.equal(ledger.summary.required_open, 0);
  assert.ok(ledger.summary.verified >= 1);
  assert.equal(ledger.closure_digest, syncResult.closure_digest);
  console.log(`    Cryptographic Obligation Closure VERIFIED!`);
  console.log(`    Closure digest: ${syncResult.closure_digest}`);
  console.log(
    `    Ledger status: ${ledger.status}, verified: ${ledger.summary.verified}, required_open: ${ledger.summary.required_open}`,
  );

  console.log(
    "\n==> All Matching Decompilation verification checks passed successfully!",
  );
} finally {
  await rm(tempDir, { recursive: true, force: true }).catch(() => {});
}
