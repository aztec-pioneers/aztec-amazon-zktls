"use client";

import { useCallback, useState } from "react";
import { getPrimus } from "@/lib/primus-client";
import {
  attestationTimestamp,
  downloadJson,
  errorMessage,
  timestampedLog,
  type UiStatus,
} from "@/lib/browser-utils";
import { resolveSignedPlaintext } from "@/lib/primus-extraction";
import {
  buildSha256AttestationRequest,
  getAllJsonResponseRows,
  parseAttestationHashes,
  plaintextsByKey,
  signPrimusRequest,
  type PrimusAttestationLike,
} from "@/lib/primus-flow";
import {
  ProveAttestation,
  type ProveAttestationProps,
} from "./ProveAttestation";
import {
  AttestedFieldCards,
  type AttestedFieldRow,
} from "./AttestedFieldCards";

type FieldRow = AttestedFieldRow;

const FIELD_PATHS = [
  {
    key: "shipmentStatus",
    xpath: '//*[@id="shipment-top-row"]/div[1]/div[1]/h4[1]',
  },
  {
    key: "productTitle",
    xpath:
      '//*[@id="orderDetails"]/div[1]/div[3]/div[1]/div[1]/div[7]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[2]/div[1]/div[1]/div[1]/div[2]/div[1]/div[1]/div[1]/a[1]',
  },
  {
    key: "shipTo",
    xpath:
      '//*[@id="orderDetails"]/div[1]/div[3]/div[1]/div[1]/div[6]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/div[1]/ul[1]',
  },
  {
    key: "grandTotal",
    xpath:
      '//*[@id="od-subtotals"]/div[1]/div[1]/ul[1]/li[6]/span[1]/div[1]/div[2]/span[1]',
  },
] as const;
const FIELD_KEYS = FIELD_PATHS.map((f) => f.key);

const TEMPLATE_ID =
  process.env.NEXT_PUBLIC_PRIMUS_INVOICE_TEMPLATE_ID ??
  "";
const DEFAULT_ORDER_ID = process.env.NEXT_PUBLIC_AMAZON_ORDER_ID ?? "";

function buildLaunchPage(orderId: string): string {
  return `https://www.amazon.com/gp/css/summary/print.html?orderID=${encodeURIComponent(
    orderId.trim(),
  )}`;
}

export default function AttestPurchaseBrowser() {
  const [orderId, setOrderId] = useState(DEFAULT_ORDER_ID);
  const [status, setStatus] = useState<UiStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] =
    useState<PrimusAttestationLike | null>(null);
  const [rows, setRows] = useState<FieldRow[] | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const log = (line: string) =>
    setLogs((prev) => [...prev, timestampedLog(line)]);

  const handleAttest = useCallback(async () => {
    if (!TEMPLATE_ID) {
      setError("NEXT_PUBLIC_PRIMUS_INVOICE_TEMPLATE_ID is not set");
      setStatus("error");
      return;
    }

    setStatus("running");
    setError(null);
    setAttestation(null);
    setRows(null);
    setLogs([]);

    try {
      log("loading Primus SDK (browser, dynamic import)");
      const primus = await getPrimus();

      const launchPage = buildLaunchPage(orderId);
      log(`generateRequestParams template=${TEMPLATE_ID}`);
      log(`launch_page=${launchPage}`);
      const requestStr = buildSha256AttestationRequest(primus, {
        templateId: TEMPLATE_ID,
        fields: FIELD_KEYS,
        launchPage,
      });

      log("POST /api/primus/sign (server signs with appSecret)");
      const signResult = await signPrimusRequest(requestStr);

      log(
        "startAttestation — Primus extension takes over, opens Amazon, captures the print.html TLS response",
      );
      const att = await primus.startAttestation(signResult);
      log("attestation returned, verifying signature");

      const ok = primus.verifyAttestation(att);
      if (!ok) throw new Error("verifyAttestation returned false");
      log("signature verified");

      const hashes = parseAttestationHashes(att, log);
      const allJson = getAllJsonResponseRows(primus, att);

      const tableRows: FieldRow[] = await Promise.all(
        FIELD_PATHS.map(async ({ key, xpath }) => {
          const signedHash = hashes[key] ?? "(missing)";
          const resolved = await resolveSignedPlaintext({
            allJson,
            key,
            xpath,
            signedHash,
          });
          return { key, signedHash, ...resolved };
        }),
      );

      setAttestation(att);
      setRows(tableRows);
      setStatus("success");
    } catch (e) {
      const msg = errorMessage(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    }
  }, [orderId]);

  const handleDownload = useCallback(() => {
    if (!attestation) return;
    const payload = {
      ...attestation,
      _plaintexts: rows ? plaintextsByKey(rows) : {},
    };
    downloadJson(
      `attestation-${attestationTimestamp(attestation)}.json`,
      payload,
    );
  }, [attestation, rows]);

  return (
    <div className="attest">
      <section className="row">
        <label className="field">
          Order ID
          <input
            type="text"
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            disabled={status === "running"}
          />
        </label>
      </section>

      <section className="row">
        <button
          type="button"
          onClick={handleAttest}
          disabled={status === "running" || !orderId.trim() || !TEMPLATE_ID}
        >
          {status === "running" ? "Attesting…" : "Attest Amazon purchase"}
        </button>
        <span className={`status status-${status}`}>{status}</span>
      </section>

      {error && (
        <section className="error">
          <strong>Error:</strong> {error}
          <p className="hint">
            If the popup never appeared, the Primus Chrome extension is
            probably not installed or not enabled.
          </p>
        </section>
      )}

      {status === "success" && rows && (
        <section className="result">
          <h2>Attested fields</h2>
          <p className="muted">
            For each field: the signed <code>sha256</code> hash (public — goes
            into the verifier&apos;s public input) sits next to the plaintext
            outer HTML that produced it (private — Noir re-hashes this to
            match).
          </p>
          <AttestedFieldCards
            rows={rows}
            plaintextTitle="plaintext outer HTML (Noir private input)"
          />
          <button type="button" onClick={handleDownload}>
            Download attestation.json
          </button>
        </section>
      )}

      {status === "success" && attestation !== null && rows ? (
        <ProveAttestation
          attestation={
            attestation as ProveAttestationProps["attestation"]
          }
          plaintexts={plaintextsByKey(rows)}
        />
      ) : null}

      {logs.length > 0 && (
        <details open={status !== "success"}>
          <summary>Logs</summary>
          <pre>{logs.join("\n")}</pre>
        </details>
      )}
    </div>
  );
}
