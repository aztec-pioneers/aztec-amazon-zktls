"use client";

import {
  AttestationProver,
  type AnyCircuitInputs,
  type ProverInit,
} from "@amazon-zktls/circuit";
import {
  getProverRuntimeProfile,
  getSharedBarretenberg,
} from "@/lib/prover-runtime";

export interface BrowserProofResult<Outputs> {
  proof: Uint8Array;
  publicInputs: readonly string[];
  outputs: Outputs;
  durationMs: number;
}

export async function proveInBrowser<Outputs>({
  circuit,
  inputs,
  decodeOutputs,
  log,
  parseLog,
}: {
  circuit: ProverInit["circuit"];
  inputs: AnyCircuitInputs;
  decodeOutputs: (publicInputs: readonly string[]) => Outputs;
  log: (message: string) => void;
  parseLog: string;
}): Promise<BrowserProofResult<Outputs>> {
  const t0 = performance.now();
  let prover: AttestationProver | null = null;

  try {
    const { isolated, threads } = getProverRuntimeProfile();
    log(
      isolated
        ? `crossOriginIsolated=true; using ${threads} threads`
        : "crossOriginIsolated=false; falling back to single-threaded WASM (check COEP/COOP headers)",
    );

    log(parseLog);
    log("initializing shared bb.js runtime (WasmWorker, SRS load)");
    const bb = await getSharedBarretenberg(threads);
    prover = new AttestationProver({ circuit, bb });
    await prover.init();

    log("prove (witness + UltraHonk)");
    const proof = await prover.prove(inputs);

    log("verify");
    const ok = await prover.verify(proof);
    if (!ok) throw new Error("local verify returned false");

    const durationMs = Math.round(performance.now() - t0);
    log(
      `done: ${proof.proof.length}-byte proof, ${proof.publicInputs.length} public inputs, ${durationMs}ms`,
    );
    return {
      proof: proof.proof,
      publicInputs: proof.publicInputs,
      outputs: decodeOutputs(proof.publicInputs),
      durationMs,
    };
  } finally {
    try {
      await prover?.destroy();
    } catch {
      /* noop */
    }
  }
}
