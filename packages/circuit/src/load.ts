// Node-side helper to load the compiled bin artifact emitted by
// `nargo compile --workspace`. Split from `prover.ts` so prover.ts stays
// environment-agnostic (callers in a bundler can import the JSON directly).

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { CompiledCircuit } from "@noir-lang/noir_js";

// Resolve relative to the package root (dist/load.js when compiled,
// src/load.ts in tests via tsx/vitest) so downstream callers get a stable
// default location.
function packageRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // `src/` and `dist/` are both one level below the package root.
  return resolve(here, "..");
}

export const DEFAULT_BIN_PATH = "nr/target/amazon_zktls_bin.json";
export const DELIVERY_CODE_BIN_PATH =
  "nr/target/amazon_zktls_delivery_code.json";

export async function loadCircuit(relPath: string = DEFAULT_BIN_PATH): Promise<CompiledCircuit> {
  const abs = resolve(packageRoot(), relPath);
  const raw = await readFile(abs, "utf-8");
  return JSON.parse(raw) as CompiledCircuit;
}

export async function loadDeliveryCodeCircuit(): Promise<CompiledCircuit> {
  return loadCircuit(DELIVERY_CODE_BIN_PATH);
}
