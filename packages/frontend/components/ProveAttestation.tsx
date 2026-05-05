"use client";

import { useCallback, useState } from "react";
import {
  centsToCurrency,
  decodePublicOutputs,
  parseAttestation,
  type AmazonOrderSummaryAttestation,
  type DecodedOutputs,
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
// Compiled bin pulled in directly from the circuit workspace. The
// nargo target dir is symlinked into node_modules via pnpm so the JSON
// is bundled by Next at build time. After every `pnpm --filter
// @amazon-zktls/circuit build:nr`, restart `next dev` to pick up the
// new bytecode.
import compiledCircuit from "@amazon-zktls/circuit/nr/target/amazon_zktls_bin.json";

export interface ProveAttestationProps {
  attestation: AmazonOrderSummaryAttestation;
  plaintexts: Record<string, string>;
}

type ProveResult = BrowserProofResult<DecodedOutputs>;

export function ProveAttestation({
  attestation,
  plaintexts,
}: ProveAttestationProps) {
  const [status, setStatus] = useState<UiStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ProveResult | null>(null);

  const log = useCallback((msg: string) => {
    setLogs((l) => [...l, msg]);
  }, []);

  const handleProve = useCallback(async () => {
    setStatus("running");
    setError(null);
    setResult(null);
    setLogs([]);
    try {
      const inputs = parseAttestation(attestation, plaintexts);
      const proofResult = await proveInBrowser({
        circuit: compiledCircuit as unknown as ProverInit["circuit"],
        inputs,
        decodeOutputs: decodePublicOutputs,
        log,
        parseLog: "parsing attestation into circuit inputs",
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
    // proof bytes as 0x hex; publicInputs already arrive as hex strings.
    const payload = {
      proof: "0x" + bytesToHex(result.proof),
      publicInputs: result.publicInputs,
      outputs: {
        asin: result.outputs.asin,
        grandTotalCents: result.outputs.grandTotalCents.toString(),
        addressCommitment:
          "0x" + result.outputs.addressCommitment.toString(16).padStart(64, "0"),
        nullifier:
          "0x" + result.outputs.nullifier.toString(16).padStart(64, "0"),
        shipmentDate: result.outputs.shipmentDate.toString(),
      },
      attestationTimestamp: ts,
    };
    downloadJson(`proof-${ts}.json`, payload);
  }, [attestation, result]);

  return (
    <section className="result prove-panel">
      <h2>Generate proof</h2>
      <p className="muted">
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
        <pre className="proof-error">{error}</pre>
      )}

      {result && (
        <div className="proof-output">
          <h3>Public outputs</h3>
          <table className="output-table">
            <tbody>
              <tr>
                <td className="output-key">ASIN</td>
                <td className="output-value">
                  <code>{result.outputs.asin}</code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Grand total</td>
                <td className="output-value">
                  <code>{centsToCurrency(result.outputs.grandTotalCents)}</code>{" "}
                  <span className="subtle">
                    ({result.outputs.grandTotalCents.toString()} cents)
                  </span>
                </td>
              </tr>
              <tr>
                <td className="output-key">Address commitment</td>
                <td className="output-value">
                  <code className="wide-code">
                    0x{result.outputs.addressCommitment.toString(16).padStart(64, "0")}
                  </code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Nullifier</td>
                <td className="output-value">
                  <code className="wide-code">
                    0x{result.outputs.nullifier.toString(16).padStart(64, "0")}
                  </code>
                </td>
              </tr>
              <tr>
                <td className="output-key">Shipment date</td>
                <td className="output-value">
                  <code>{result.outputs.shipmentDate.toString()}</code>
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
