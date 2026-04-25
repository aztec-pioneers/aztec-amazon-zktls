"use client";

import { useCallback, useState } from "react";
import { getPrimus } from "@/lib/primus-client";

type Status = "idle" | "running" | "success" | "error";

// Primus' generateRequestParams second arg ("userAddress") is a required
// string identifier validated as 0x + 40 hex. NOT a wallet — no signing, no
// gas. When this project is wired to Aztec, derive from the Aztec account
// (e.g. lower 20 bytes of the address hash). For now a fixed placeholder
// keeps the focus on the attestation data.
const RECIPIENT = `0x${"00".repeat(20)}`;

const TEMPLATE_ID = process.env.NEXT_PUBLIC_PRIMUS_TEMPLATE_ID ?? "";
const DEFAULT_ORDER_ID = process.env.NEXT_PUBLIC_AMAZON_ORDER_ID ?? "";

export default function AttestPurchaseBrowser() {
  const [orderId, setOrderId] = useState(DEFAULT_ORDER_ID);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<unknown>(null);
  const [parsedData, setParsedData] = useState<unknown>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const log = (line: string) =>
    setLogs((prev) => [...prev, `[${new Date().toISOString()}] ${line}`]);

  const handleAttest = useCallback(async () => {
    if (!TEMPLATE_ID) {
      setError("NEXT_PUBLIC_PRIMUS_TEMPLATE_ID is not set");
      setStatus("error");
      return;
    }

    setStatus("running");
    setError(null);
    setAttestation(null);
    setParsedData(null);
    setLogs([]);

    try {
      log("loading Primus SDK (browser, dynamic import)");
      const primus = await getPrimus();

      log(`generateRequestParams template=${TEMPLATE_ID}`);
      // The template's `dynamicParamters` declares orderID as user input;
      // the SDK's setAdditionParams is one way to pass it through. If this
      // turns out to be the wrong channel for dynamicParamters, the editor
      // log on Dev Hub will tell us.
      const attRequest = primus.generateRequestParams(TEMPLATE_ID, RECIPIENT);
      attRequest.setAdditionParams(JSON.stringify({ orderID: orderId.trim() }));
      const requestStr = attRequest.toJsonString();

      log("POST /api/primus/sign (server signs with appSecret)");
      const res = await fetch("/api/primus/sign", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ signParams: requestStr }),
      });
      if (!res.ok) {
        throw new Error(
          `sign endpoint returned ${res.status}: ${await res.text()}`,
        );
      }
      const { signResult } = (await res.json()) as { signResult: string };

      log(
        "startAttestation — Primus extension takes over, opens Amazon, captures the print.html TLS response",
      );
      const att = await primus.startAttestation(signResult);
      log("attestation returned, verifying signature");

      const ok = primus.verifyAttestation(att);
      if (!ok) throw new Error("verifyAttestation returned false");
      log("signature verified");

      let parsed: unknown = att.data;
      try {
        parsed = JSON.parse(att.data);
      } catch {
        // attestation.data is sometimes a JSON-encoded object (one key per
        // template field), sometimes a raw string. Show whichever.
      }

      setAttestation(att);
      setParsedData(parsed);
      setStatus("success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : JSON.stringify(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    }
  }, [orderId]);

  const handleDownload = useCallback(() => {
    if (!attestation) return;
    const blob = new Blob([JSON.stringify(attestation, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const ts =
      (attestation as { timestamp?: number | string })?.timestamp ?? Date.now();
    a.download = `attestation-${ts}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [attestation]);

  return (
    <div className="attest">
      <section className="row" style={{ gap: 8 }}>
        <p style={{ margin: 0, fontSize: 13, color: "#444" }}>
          Browser flow — uses{" "}
          <a
            href="https://chromewebstore.google.com/detail/primus/oeiomhmbaapihbilkfkhmlajkeegnjhe"
            target="_blank"
            rel="noreferrer"
          >
            Primus Chrome extension
          </a>{" "}
          + Dev Hub template{" "}
          <code>{TEMPLATE_ID || "(unset)"}</code>. Make sure the extension is
          installed and you&apos;re logged into amazon.com in this browser
          profile.
        </p>
      </section>

      <section className="row">
        <label>
          Order ID:{" "}
          <input
            type="text"
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            disabled={status === "running"}
            style={{
              font: "inherit",
              padding: "6px 10px",
              borderRadius: 4,
              border: "1px solid #d4d4d4",
              width: 220,
            }}
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

      {status === "success" && parsedData !== null && (
        <section className="result">
          <h2>Verified data</h2>
          <pre>{JSON.stringify(parsedData, null, 2)}</pre>
          <button type="button" onClick={handleDownload}>
            Download attestation.json
          </button>
        </section>
      )}

      {attestation !== null && (
        <details>
          <summary>Full attestation object</summary>
          <pre>{JSON.stringify(attestation, null, 2)}</pre>
        </details>
      )}

      {logs.length > 0 && (
        <details open={status !== "success"}>
          <summary>Logs</summary>
          <pre>{logs.join("\n")}</pre>
        </details>
      )}
    </div>
  );
}
