"use client";

import { useCallback, useState } from "react";
import {
  decodeDeliveryCodePublicOutputs,
  parseDeliveryCodeAttestation,
  type AmazonDeliveryCodeAttestation,
  type DecodedDeliveryCodeOutputs,
  type ProverInit,
} from "@amazon-zktls/circuit";
import {
  attestationTimestamp,
  bytesToHex,
  downloadJson,
  errorMessageWithStack,
  type UiStatus,
} from "@/lib/browser-utils";
import {
  proveInBrowser,
  type BrowserProofResult,
} from "@/lib/proof-flow";
import compiledDeliveryCodeCircuit from "@amazon-zktls/circuit/nr/target/amazon_zktls_delivery_code.json";

export interface ProveDeliveryCodeProps {
  attestation: AmazonDeliveryCodeAttestation;
  plaintexts: Record<string, string>;
}

type ProveDeliveryCodeResult =
  BrowserProofResult<DecodedDeliveryCodeOutputs>;

export function ProveDeliveryCode({
  attestation,
  plaintexts,
}: ProveDeliveryCodeProps) {
  const [status, setStatus] = useState<UiStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ProveDeliveryCodeResult | null>(null);

  const log = useCallback((msg: string) => {
    setLogs((l) => [...l, msg]);
  }, []);

  const handleProve = useCallback(async () => {
    setStatus("running");
    setError(null);
    setResult(null);
    setLogs([]);
    try {
      const inputs = parseDeliveryCodeAttestation(attestation, plaintexts);
      const proofResult = await proveInBrowser({
        circuit: compiledDeliveryCodeCircuit as unknown as ProverInit["circuit"],
        inputs,
        decodeOutputs: decodeDeliveryCodePublicOutputs,
        log,
        parseLog: "parsing delivery-code attestation into circuit inputs",
      });
      setResult(proofResult);
      setStatus("success");
    } catch (e) {
      const msg = errorMessageWithStack(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    }
  }, [attestation, plaintexts, log]);

  const handleDownloadProof = useCallback(() => {
    if (!result) return;
    const ts = attestationTimestamp(attestation);
    const payload = {
      proof: "0x" + bytesToHex(result.proof),
      publicInputs: result.publicInputs,
      outputs: result.outputs,
      attestationTimestamp: ts,
    };
    downloadJson(`delivery-code-proof-${ts}.json`, payload);
  }, [attestation, result]);

  return (
    <section className="result prove-panel">
      <h2>Generate delivery-code proof</h2>
      <p className="muted">
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
        <pre className="proof-error">{error}</pre>
      )}

      {result && (
        <div className="proof-output">
          <h3>Public outputs</h3>
          <table className="output-table">
            <tbody>
              <tr>
                <td className="output-key">Pickup code</td>
                <td className="output-value">
                  <code>{result.outputs.pickupCode}</code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Order id</td>
                <td className="output-value">
                  <code>{result.outputs.orderId}</code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Allowed URL</td>
                <td className="output-value">
                  <code>{result.outputs.allowedUrl}</code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Request URL</td>
                <td className="output-value">
                  <code className="wide-code">
                    {result.outputs.requestUrl}
                  </code>
                </td>
              </tr>
            </tbody>
          </table>
          <p className="muted proof-meta">
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
