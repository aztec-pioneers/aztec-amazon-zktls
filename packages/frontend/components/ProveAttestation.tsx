"use client";

import { useCallback, useState } from "react";
import {
  AttestationProver,
  centsToCurrency,
  decodePublicOutputs,
  parseAttestation,
  type DecodedOutputs,
  type PrimusAttestation,
  type ProverInit,
} from "@amazon-zktls/circuit";
// Compiled bin pulled in directly from the circuit workspace. The
// nargo target dir is symlinked into node_modules via pnpm so the JSON
// is bundled by Next at build time. After every `pnpm --filter
// @amazon-zktls/circuit build:nr`, restart `next dev` to pick up the
// new bytecode.
import compiledCircuit from "@amazon-zktls/circuit/nr/target/amazon_zktls_bin.json";

type Status = "idle" | "running" | "success" | "error";

export interface ProveAttestationProps {
  attestation: PrimusAttestation;
  plaintexts: Record<string, string>;
}

interface ProveResult {
  proof: Uint8Array;
  publicInputs: readonly string[];
  outputs: DecodedOutputs;
  durationMs: number;
}

export function ProveAttestation({
  attestation,
  plaintexts,
}: ProveAttestationProps) {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ProveResult | null>(null);

  const log = useCallback((msg: string) => {
    setLogs((l) => [...l, msg]);
    console.log("[prove]", msg);
  }, []);

  const handleProve = useCallback(async () => {
    setStatus("running");
    setError(null);
    setResult(null);
    setLogs([]);
    const t0 = performance.now();
    let prover: AttestationProver | null = null;
    try {
      const isolated = typeof window !== "undefined" && window.crossOriginIsolated;
      const cores = navigator.hardwareConcurrency || 4;
      const threads = isolated ? cores : 1;
      log(
        isolated
          ? `crossOriginIsolated=true; using ${threads} threads`
          : `crossOriginIsolated=false; falling back to single-threaded WASM (check COEP/COOP headers)`,
      );

      log("parsing attestation into circuit inputs");
      const inputs = parseAttestation(attestation, plaintexts);

      log("initializing bb.js (WasmWorker, SRS load)");
      prover = new AttestationProver({
        // CompiledCircuit shape; cast through unknown because Next's JSON
        // type inference doesn't carry the noir_js types.
        circuit: compiledCircuit as unknown as ProverInit["circuit"],
        threads,
      });
      await prover.init();

      log("prove (witness + UltraHonk)");
      const proof = await prover.prove(inputs);

      log("verify");
      const ok = await prover.verify(proof);
      if (!ok) throw new Error("local verify returned false");

      const outputs = decodePublicOutputs(proof.publicInputs);
      const durationMs = Math.round(performance.now() - t0);
      log(
        `done: ${proof.proof.length}-byte proof, ${proof.publicInputs.length} public inputs, ${durationMs}ms`,
      );
      setResult({
        proof: proof.proof,
        publicInputs: proof.publicInputs,
        outputs,
        durationMs,
      });
      setStatus("success");
    } catch (e) {
      const msg = e instanceof Error ? `${e.message}\n${e.stack ?? ""}` : JSON.stringify(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    } finally {
      // bb.js holds a worker pool open; release it so the page doesn't keep
      // workers alive between prove sessions.
      try {
        await prover?.destroy();
      } catch {
        /* noop */
      }
    }
  }, [attestation, plaintexts, log]);

  const handleDownloadProof = useCallback(() => {
    if (!result) return;
    const ts =
      (attestation as { timestamp?: number | string })?.timestamp ?? Date.now();
    // proof bytes as 0x hex; publicInputs already arrive as hex strings.
    const payload = {
      proof:
        "0x" +
        Array.from(result.proof)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      publicInputs: result.publicInputs,
      outputs: {
        asin: result.outputs.asin,
        grandTotalCents: result.outputs.grandTotalCents.toString(),
        addressCommitment:
          "0x" + result.outputs.addressCommitment.toString(16).padStart(64, "0"),
        nullifier:
          "0x" + result.outputs.nullifier.toString(16).padStart(64, "0"),
      },
      attestationTimestamp: ts,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `proof-${ts}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [attestation, result]);

  return (
    <section
      className="result"
      style={{
        marginTop: 16,
        borderTop: "1px solid currentColor",
        paddingTop: 12,
      }}
    >
      <h2 style={{ marginTop: 0 }}>Generate proof</h2>
      <p style={{ fontSize: 12, color: "#666", margin: "0 0 12px" }}>
        Runs the Noir circuit (<code>amazon_zktls_bin</code>) over the
        attestation bytes you just collected. ECDSA, URL prefix, four
        sha256 binds, ASIN extraction, grand-total parsing, address
        commitment, and nullifier all happen in-circuit. Multi-threaded
        WASM via SharedArrayBuffer; needs cross-origin isolation
        (COEP/COOP headers) to use the worker pool.
      </p>

      <button
        type="button"
        onClick={handleProve}
        disabled={status === "running"}
      >
        {status === "running" ? "Proving…" : "Generate proof"}
      </button>{" "}
      <span className={`status status-${status}`}>{status}</span>

      {error && (
        <pre
          style={{
            color: "#b91c1c",
            border: "1px solid #b91c1c",
            padding: "6px 8px",
            borderRadius: 4,
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
            marginTop: 12,
          }}
        >
          {error}
        </pre>
      )}

      {result && (
        <div style={{ marginTop: 16 }}>
          <h3 style={{ margin: "0 0 8px" }}>Public outputs</h3>
          <table style={{ borderCollapse: "collapse", fontSize: 13 }}>
            <tbody>
              <tr>
                <td style={cellL}>ASIN</td>
                <td style={cellR}>
                  <code>{result.outputs.asin}</code>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Grand total</td>
                <td style={cellR}>
                  <code>{centsToCurrency(result.outputs.grandTotalCents)}</code>{" "}
                  <span style={{ fontSize: 11, opacity: 0.6 }}>
                    ({result.outputs.grandTotalCents.toString()} cents)
                  </span>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Address commitment</td>
                <td style={cellR}>
                  <code style={{ fontSize: 11 }}>
                    0x{result.outputs.addressCommitment.toString(16).padStart(64, "0")}
                  </code>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Nullifier</td>
                <td style={cellR}>
                  <code style={{ fontSize: 11 }}>
                    0x{result.outputs.nullifier.toString(16).padStart(64, "0")}
                  </code>
                </td>
              </tr>
            </tbody>
          </table>
          <p style={{ fontSize: 12, color: "#666", margin: "12px 0 8px" }}>
            Proof size: {result.proof.length} bytes ·{" "}
            {result.publicInputs.length} public inputs · prove + verify in{" "}
            {result.durationMs}ms.
          </p>
          <button type="button" onClick={handleDownloadProof}>
            Download proof.json
          </button>
        </div>
      )}

      {logs.length > 0 && (
        <details open={status !== "success"}>
          <summary>Prove logs</summary>
          <pre>{logs.join("\n")}</pre>
        </details>
      )}
    </section>
  );
}

const cellL: React.CSSProperties = {
  padding: "4px 12px 4px 0",
  fontWeight: 500,
  verticalAlign: "top",
};
const cellR: React.CSSProperties = {
  padding: "4px 0",
  verticalAlign: "top",
};
