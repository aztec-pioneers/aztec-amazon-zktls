"use client";

import { useCallback, useState } from "react";
import {
  AttestationProver,
  decodeDeliveryCodePublicOutputs,
  parseDeliveryCodeAttestation,
  type AmazonDeliveryCodeAttestation,
  type DecodedDeliveryCodeOutputs,
  type ProverInit,
} from "@amazon-zktls/circuit";
import {
  getProverRuntimeProfile,
  getSharedBarretenberg,
} from "@/lib/prover-runtime";
import compiledDeliveryCodeCircuit from "@amazon-zktls/circuit/nr/target/amazon_zktls_delivery_code.json";

type Status = "idle" | "running" | "success" | "error";

export interface ProveDeliveryCodeProps {
  attestation: AmazonDeliveryCodeAttestation;
  plaintexts: Record<string, string>;
}

interface ProveDeliveryCodeResult {
  proof: Uint8Array;
  publicInputs: readonly string[];
  outputs: DecodedDeliveryCodeOutputs;
  durationMs: number;
}

export function ProveDeliveryCode({
  attestation,
  plaintexts,
}: ProveDeliveryCodeProps) {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ProveDeliveryCodeResult | null>(null);

  const log = useCallback((msg: string) => {
    setLogs((l) => [...l, msg]);
    console.log("[prove:delivery_code]", msg);
  }, []);

  const handleProve = useCallback(async () => {
    setStatus("running");
    setError(null);
    setResult(null);
    setLogs([]);
    const t0 = performance.now();
    let prover: AttestationProver | null = null;
    try {
      const { isolated, threads } = getProverRuntimeProfile();
      log(
        isolated
          ? `crossOriginIsolated=true; using ${threads} threads`
          : `crossOriginIsolated=false; falling back to single-threaded WASM (check COEP/COOP headers)`,
      );

      log("parsing delivery-code attestation into circuit inputs");
      const inputs = parseDeliveryCodeAttestation(attestation, plaintexts);

      log("initializing shared bb.js runtime (WasmWorker, SRS load)");
      const bb = await getSharedBarretenberg(threads);
      prover = new AttestationProver({
        circuit: compiledDeliveryCodeCircuit as unknown as ProverInit["circuit"],
        bb,
      });
      await prover.init();

      log("prove (witness + UltraHonk)");
      const proof = await prover.prove(inputs);

      log("verify");
      const ok = await prover.verify(proof);
      if (!ok) throw new Error("local verify returned false");

      const outputs = decodeDeliveryCodePublicOutputs(proof.publicInputs);
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
    const payload = {
      proof:
        "0x" +
        Array.from(result.proof)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      publicInputs: result.publicInputs,
      outputs: result.outputs,
      attestationTimestamp: ts,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `delivery-code-proof-${ts}.json`;
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
      <h2 style={{ marginTop: 0 }}>Generate delivery-code proof</h2>
      <p style={{ fontSize: 12, color: "#666", margin: "0 0 12px" }}>
        Runs the delivery-code Noir circuit over the attestation. The circuit
        verifies the Primus signature, full public tracking URL, delivery
        status, pickup-code and order-id signed sha256 hashes, and extracts the
        fixed-size pickup code and order id as public outputs.
      </p>

      <button
        type="button"
        onClick={handleProve}
        disabled={status === "running"}
      >
        {status === "running" ? "Proving..." : "Generate delivery-code proof"}
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
                <td style={cellL}>Pickup code</td>
                <td style={cellR}>
                  <code>{result.outputs.pickupCode}</code>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Order id</td>
                <td style={cellR}>
                  <code>{result.outputs.orderId}</code>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Allowed URL</td>
                <td style={cellR}>
                  <code>{result.outputs.allowedUrl}</code>
                </td>
              </tr>
              <tr>
                <td style={cellL}>Request URL</td>
                <td style={cellR}>
                  <code style={{ fontSize: 11, wordBreak: "break-all" }}>
                    {result.outputs.requestUrl}
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
            Download delivery-code-proof.json
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
