"use client";

import { useCallback, useState } from "react";
import { getPrimus } from "@/lib/primus-client";
import {
  ProveAttestation,
  type ProveAttestationProps,
} from "./ProveAttestation";

type Status = "idle" | "running" | "success" | "error";

type FieldRow = {
  key: string;
  signedHash: string;
  plaintext: string;
  // null = couldn't compute (no plaintext); true/false = sha256 match check.
  // The Noir circuit does this same equality on private input vs public hash.
  verified: boolean | null;
};

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Field keyName + the same XPath the template carries (sans trailing `?`,
// which is the WASM dispatch marker, not a real XPath token). The js-sdk
// doesn't expose a per-field plaintext getter — `getAllJsonResponse` returns
// the full response body — so we re-run the XPath client-side via DOMParser
// to recover the exact outer HTML the attestor hashed.
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

// Pull the raw byte substring of `<tag …>…</tag>` from the source HTML by
// tag-balanced scan starting at `start`. Required because libxml2 (the
// attestor's parser) preserves source bytes — entities like `&quot;` and
// `\r\n` line endings — whereas DOMParser+outerHTML re-serializes them.
function rawElementSlice(
  body: string,
  start: number,
  tagName: string,
): string | null {
  const openTagEnd = body.indexOf(">", start);
  if (openTagEnd === -1) return null;
  const tag = tagName.toLowerCase();
  const openRe = new RegExp(`<${tag}(?=[\\s>/])`, "gi");
  const closeRe = new RegExp(`</${tag}\\s*>`, "gi");
  let depth = 1;
  let pos = openTagEnd + 1;
  while (depth > 0) {
    openRe.lastIndex = pos;
    closeRe.lastIndex = pos;
    const om = openRe.exec(body);
    const cm = closeRe.exec(body);
    if (!cm) return null;
    if (om && om.index < cm.index) {
      depth++;
      pos = om.index + om[0].length;
    } else {
      depth--;
      pos = cm.index + cm[0].length;
      if (depth === 0) return body.substring(start, pos);
    }
  }
  return null;
}

function normalizedTextContent(html: string): string {
  // Browsers normalize text-content whitespace consistently — feed both raw
  // and re-serialized through the same DOMParser to get matchable strings.
  return new DOMParser()
    .parseFromString(`<x>${html}</x>`, "text/html")
    .documentElement.textContent?.trim() ?? "";
}

function extractByXPath(html: string, xpath: string): string | null {
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = doc.evaluate(
      xpath,
      doc,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null,
    ).singleNodeValue as Element | null;
    if (!node) return null;
    const serialized = node.outerHTML;
    const openTagEnd = serialized.indexOf(">");
    const openTag =
      openTagEnd === -1 ? serialized : serialized.substring(0, openTagEnd + 1);
    const targetText = (node.textContent ?? "").trim();

    // Open-tag fingerprint may not be unique (e.g. grandTotal label + value
    // share the exact same `<span class="…">`). Enumerate all occurrences,
    // raw-slice each, and pick whichever has matching textContent.
    let from = 0;
    let firstSlice: string | null = null;
    while (true) {
      const idx = html.indexOf(openTag, from);
      if (idx === -1) break;
      const slice = rawElementSlice(html, idx, node.tagName);
      if (slice) {
        if (!firstSlice) firstSlice = slice;
        if (normalizedTextContent(slice) === targetText) return slice;
      }
      from = idx + openTag.length;
    }

    if (firstSlice) {
      console.warn(
        "[extract] no raw slice with matching textContent; using first occurrence",
        { xpath, targetText },
      );
      return firstSlice;
    }
    console.warn(
      "[extract] open-tag fingerprint not found; falling back to outerHTML",
      { openTag },
    );
    return serialized;
  } catch {
    return null;
  }
}

// Primus' generateRequestParams second arg ("userAddress") is a required
// string identifier validated as 0x + 40 hex. NOT a wallet — no signing, no
// gas. When this project is wired to Aztec, derive from the Aztec account
// (e.g. lower 20 bytes of the address hash). For now a fixed placeholder
// keeps the focus on the attestation data.
const RECIPIENT = `0x${"00".repeat(20)}`;

const TEMPLATE_ID =
  process.env.NEXT_PUBLIC_PRIMUS_INVOICE_TEMPLATE_ID ??
  process.env.NEXT_PUBLIC_PRIMUS_TEMPLATE_ID ??
  "";
const DEFAULT_ORDER_ID = process.env.NEXT_PUBLIC_AMAZON_ORDER_ID ?? "";

// Build the print.html URL the extension will navigate to. The Primus
// extension reads `additionParams.launch_page` and uses it as the navigation
// destination, overriding the template's static baseUrl. That's the
// undocumented channel for "dynamic URL per attestation" — confirmed by
// reading primus-labs/primus-extension's
// padoZKAttestationJSSDK/index.js.
function buildLaunchPage(orderId: string): string {
  return `https://www.amazon.com/gp/css/summary/print.html?orderID=${encodeURIComponent(
    orderId.trim(),
  )}`;
}

export default function AttestPurchaseBrowser() {
  const [orderId, setOrderId] = useState(DEFAULT_ORDER_ID);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<unknown>(null);
  const [rows, setRows] = useState<FieldRow[] | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const log = (line: string) =>
    setLogs((prev) => [...prev, `[${new Date().toISOString()}] ${line}`]);

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
      const attRequest = primus.generateRequestParams(TEMPLATE_ID, RECIPIENT, {
        timeout: 2 * 60 * 1000,
      });
      // `launch_page` is the SDK's undocumented baseUrl-override key (read by
      // the extension's background script). It lets us inject the per-order
      // URL without re-uploading a template per orderID.
      attRequest.setAdditionParams(JSON.stringify({ launch_page: launchPage }));
      // Force SHA256_EX op for every field. Without setAttConditions the
      // extension's default is REVEAL_STRING — and the algorithm WASM rejects
      // REVEAL_STRING on HTML (we verified this on main with the network-
      // core-sdk path). SHA256_EX is the only op the WASM accepts on HTML and
      // is also what `verify_attestation_hashing` consumes downstream.
      // Shape: AttConditions is `AttCondition[]`; each inner array maps 1:1
      // to a request in the template (we have one).
      attRequest.setAttConditions(
        // SHA256_EX isn't in the SDK's typed OpType union but the runtime
        // (and the algorithm WASM) accept it — the extension has an explicit
        // ['SHA256_EX','REVEAL_HEX_STRING'] branch. Cast through unknown.
        [
          FIELD_KEYS.map((field) => ({ field, op: "SHA256_EX" })),
        ] as unknown as Parameters<typeof attRequest.setAttConditions>[0],
      );
      // SHA256_EX never populates the SDK's `_allPrivateData` store (that's a
      // DVC-only path). The plaintext per field comes through
      // `_allJsonResponse` and is only captured when this flag is on.
      attRequest.setAllJsonResponseFlag("true");
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

      // For SHA256_EX, attestation.data is JSON like
      //   `{"shipmentStatus":"<sha256>", "productTitle":"<sha256>", ...}`
      // — the SIGNED hashes (public). The plaintext outer HTML the attestor
      // hashed lives in the SDK's private-data store and is the private
      // input to verify_attestation_hashing.
      let hashes: Record<string, string> = {};
      try {
        hashes = JSON.parse(att.data) as Record<string, string>;
      } catch {
        log("warn: attestation.data was not JSON; leaving hashes empty");
      }
      // `getAllJsonResponse` returns the FULL response body per request (not
      // the per-field extracted text — only network-core-sdk exposes that
      // via getPlainResponse). Re-run each XPath against that body in
      // DOMParser to recover the outer HTML the attestor hashed.
      const requestid = (att as { requestid?: string }).requestid;
      const allJson = (
        requestid
          ? (primus.getAllJsonResponse(requestid) as unknown)
          : null
      ) as { id: string; content: string }[] | null;
      // The template has a single request, so allJson[0].content is the
      // print.html body shared by every resolve. (Multi-request templates
      // would need a per-request map.)
      const fullBody =
        Array.isArray(allJson) && allJson[0] ? allJson[0].content : "";

      const tableRows: FieldRow[] = await Promise.all(
        FIELD_PATHS.map(async ({ key, xpath }) => {
          const signedHash = hashes[key] ?? "(missing)";
          const extracted = extractByXPath(fullBody, xpath);
          const plaintext = extracted ?? "(missing)";
          let verified: boolean | null = null;
          if (extracted !== null && /^[0-9a-f]{64}$/i.test(signedHash)) {
            const localHash = await sha256Hex(extracted);
            verified = localHash.toLowerCase() === signedHash.toLowerCase();
          }
          return { key, signedHash, plaintext, verified };
        }),
      );

      // Full envelope on the console for copying into Noir test inputs.
      console.log("[primus] attestation", att);
      console.log("[primus] full response body length", fullBody.length);
      console.log("[primus] field rows for noir", tableRows);

      setAttestation(att);
      setRows(tableRows);
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
    // Attach extracted plaintexts as a sidecar under `_plaintexts` so the
    // downstream Noir test has everything it needs (private inputs come from
    // here; public inputs from the attestation itself). `_` prefix signals
    // "not part of the canonical Primus payload" — the attestation is still
    // bit-identical to what Primus signed.
    const payload = {
      ...(attestation as Record<string, unknown>),
      _plaintexts: rows
        ? Object.fromEntries(rows.map((r) => [r.key, r.plaintext]))
        : {},
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
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
  }, [attestation, rows]);

  return (
    <div className="attest">
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

      {status === "success" && rows && (
        <section className="result">
          <h2>Attested fields</h2>
          <p style={{ fontSize: 12, color: "#666", margin: "0 0 12px" }}>
            For each field: the signed <code>sha256</code> hash (public — goes
            into the verifier&apos;s public input) sits next to the plaintext
            outer HTML that produced it (private — Noir re-hashes this to
            match). Full attestation logged to the browser console for
            copying into Noir test inputs.
          </p>
          {rows.map((r) => (
            <div
              key={r.key}
              style={{
                border: "1px solid currentColor",
                borderRadius: 6,
                padding: "10px 12px",
                marginBottom: 10,
                opacity: 0.92,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "baseline",
                  gap: 12,
                  marginBottom: 6,
                }}
              >
                <strong style={{ fontSize: 14 }}>
                  {r.key}{" "}
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 500,
                      marginLeft: 6,
                      padding: "1px 6px",
                      borderRadius: 4,
                      border: "1px solid currentColor",
                      opacity: 0.85,
                      color:
                        r.verified === true
                          ? "#16a34a"
                          : r.verified === false
                            ? "#b91c1c"
                            : undefined,
                    }}
                    title="local sha256(plaintext) vs signed hash"
                  >
                    {r.verified === true
                      ? "✓ matches expected"
                      : r.verified === false
                        ? "✗ mismatch"
                        : "—"}
                  </span>
                </strong>
                <code
                  style={{
                    font:
                      "11px ui-monospace, SFMono-Regular, Menlo, monospace",
                    opacity: 0.7,
                    wordBreak: "break-all",
                    textAlign: "right",
                    flex: 1,
                  }}
                  title="signed sha256 (public input)"
                >
                  {r.signedHash}
                </code>
              </div>
              <pre
                style={{
                  margin: 0,
                  font:
                    "12px ui-monospace, SFMono-Regular, Menlo, monospace",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  border: "1px solid currentColor",
                  borderRadius: 4,
                  padding: "6px 8px",
                  maxHeight: 180,
                  overflow: "auto",
                  opacity: 0.85,
                }}
                title="plaintext outer HTML (Noir private input)"
              >
                {r.plaintext}
              </pre>
            </div>
          ))}
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
          plaintexts={Object.fromEntries(
            rows.map((r): [string, string] => [r.key, r.plaintext]),
          )}
        />
      ) : null}

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
