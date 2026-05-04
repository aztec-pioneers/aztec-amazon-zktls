"use client";

import { useCallback, useMemo, useState } from "react";
import { getPrimus } from "@/lib/primus-client";

type Status = "idle" | "running" | "success" | "error";

type DeliveryCodeResult = {
  signedHash: string;
  plaintext: string;
  verified: boolean | null;
};

const PICKUP_CODE_FIELD = "pickupCode";
const PICKUP_CODE_XPATH = '//*[@id="pickupInformation-container"]/h1[1]';
const RECIPIENT = `0x${"00".repeat(20)}`;
const DEFAULT_TEMPLATE_ID = "23a39be5-1dd9-45d7-addb-4ba05e0adb74";

function envOr(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : fallback;
}

const TEMPLATE_ID = envOr(
  process.env.NEXT_PUBLIC_PRIMUS_DELIVERY_CODE_TEMPLATE_ID,
  DEFAULT_TEMPLATE_ID,
);
const DEFAULT_DELIVERY_URL = envOr(
  process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_URL,
  "https://www.amazon.com/gp/your-account/ship-track",
);

function getUrlParam(urlString: string, key: string): string {
  try {
    return (
      new URL(urlString, "https://www.amazon.com").searchParams.get(key) ?? ""
    );
  } catch {
    return "";
  }
}

const DEFAULTS = {
  itemId: envOr(
    process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_ITEM_ID,
    getUrlParam(DEFAULT_DELIVERY_URL, "itemId"),
  ),
  ref: envOr(
    process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_REF,
    getUrlParam(DEFAULT_DELIVERY_URL, "ref"),
  ),
  packageIndex: envOr(
    process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_PACKAGE_INDEX,
    getUrlParam(DEFAULT_DELIVERY_URL, "packageIndex"),
  ),
  orderId: envOr(
    process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_ORDER_ID,
    getUrlParam(DEFAULT_DELIVERY_URL, "orderId"),
  ),
  shipmentId: envOr(
    process.env.NEXT_PUBLIC_AMAZON_DELIVERY_CODE_SHIPMENT_ID,
    getUrlParam(DEFAULT_DELIVERY_URL, "shipmentId"),
  ),
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
  return (
    new DOMParser()
      .parseFromString(`<x>${html}</x>`, "text/html")
      .documentElement.textContent?.trim() ?? ""
  );
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

    return firstSlice ?? serialized;
  } catch {
    return null;
  }
}

function buildLaunchPage(params: {
  baseUrl: string;
  itemId: string;
  ref: string;
  packageIndex: string;
  orderId: string;
  shipmentId: string;
}): string {
  let url: URL;
  try {
    url = new URL(
      params.baseUrl.trim() || DEFAULT_DELIVERY_URL,
      "https://www.amazon.com",
    );
  } catch {
    url = new URL(DEFAULT_DELIVERY_URL);
  }
  const orderedParams = [
    ["itemId", params.itemId],
    ["ref", params.ref],
    ["packageIndex", params.packageIndex],
    ["orderId", params.orderId],
    ["shipmentId", params.shipmentId],
  ] as const;

  for (const [key] of orderedParams) {
    url.searchParams.delete(key);
  }
  for (const [key, value] of orderedParams) {
    const trimmed = value.trim() || getUrlParam(params.baseUrl, key);
    if (trimmed) url.searchParams.append(key, trimmed);
  }
  return url.toString();
}

export default function AttestDeliveryCode() {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_DELIVERY_URL);
  const [itemId, setItemId] = useState(DEFAULTS.itemId);
  const [ref, setRef] = useState(DEFAULTS.ref);
  const [packageIndex, setPackageIndex] = useState(DEFAULTS.packageIndex);
  const [orderId, setOrderId] = useState(DEFAULTS.orderId);
  const [shipmentId, setShipmentId] = useState(DEFAULTS.shipmentId);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<unknown>(null);
  const [result, setResult] = useState<DeliveryCodeResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const launchPage = useMemo(
    () =>
      buildLaunchPage({
        baseUrl,
        itemId,
        ref,
        packageIndex,
        orderId,
        shipmentId,
      }),
    [baseUrl, itemId, ref, packageIndex, orderId, shipmentId],
  );

  const log = (line: string) =>
    setLogs((prev) => [...prev, `[${new Date().toISOString()}] ${line}`]);

  const handleAttest = useCallback(async () => {
    if (!TEMPLATE_ID) {
      setError("NEXT_PUBLIC_PRIMUS_DELIVERY_CODE_TEMPLATE_ID is not set");
      setStatus("error");
      return;
    }

    setStatus("running");
    setError(null);
    setAttestation(null);
    setResult(null);
    setLogs([]);

    try {
      log("loading Primus SDK (browser, dynamic import)");
      const primus = await getPrimus();

      log(`generateRequestParams template=${TEMPLATE_ID}`);
      log(`launch_page=${launchPage}`);
      const attRequest = primus.generateRequestParams(TEMPLATE_ID, RECIPIENT, {
        timeout: 2 * 60 * 1000,
      });
      attRequest.setAdditionParams(JSON.stringify({ launch_page: launchPage }));
      attRequest.setAttConditions(
        [
          [{ field: PICKUP_CODE_FIELD, op: "SHA256_EX" }],
        ] as unknown as Parameters<typeof attRequest.setAttConditions>[0],
      );
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

      log("startAttestation - Primus extension opens Amazon package tracking");
      const att = await primus.startAttestation(signResult);
      log("attestation returned, verifying signature");

      const ok = primus.verifyAttestation(att);
      if (!ok) throw new Error("verifyAttestation returned false");
      log("signature verified");

      let hashes: Record<string, string> = {};
      try {
        hashes = JSON.parse(att.data) as Record<string, string>;
      } catch {
        log("warn: attestation.data was not JSON; leaving hashes empty");
      }

      const requestid = (att as { requestid?: string }).requestid;
      const allJson = (
        requestid
          ? (primus.getAllJsonResponse(requestid) as unknown)
          : null
      ) as { id: string; content: string }[] | null;
      const fullBody =
        Array.isArray(allJson) && allJson[0] ? allJson[0].content : "";
      const extracted = extractByXPath(fullBody, PICKUP_CODE_XPATH);
      const signedHash = hashes[PICKUP_CODE_FIELD] ?? "(missing)";

      let verified: boolean | null = null;
      if (extracted !== null && /^[0-9a-f]{64}$/i.test(signedHash)) {
        const localHash = await sha256Hex(extracted);
        verified = localHash.toLowerCase() === signedHash.toLowerCase();
      }

      console.log("[primus] delivery-code attestation", att);
      console.log("[primus] full response body length", fullBody.length);
      console.log("[primus] pickupCode plaintext", extracted);

      setAttestation(att);
      setResult({
        signedHash,
        plaintext: extracted ?? "(missing)",
        verified,
      });
      setStatus("success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : JSON.stringify(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    }
  }, [launchPage]);

  const handleDownload = useCallback(() => {
    if (!attestation) return;
    const payload = {
      ...(attestation as Record<string, unknown>),
      _plaintexts: {
        pickupCode: result?.plaintext ?? "",
      },
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const ts =
      (attestation as { timestamp?: number | string })?.timestamp ?? Date.now();
    a.download = `delivery-code-attestation-${ts}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [attestation, result]);

  return (
    <div className="attest">
      <section className="row row-wrap">
        <label className="field field-wide">
          Tracking URL
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            disabled={status === "running"}
          />
        </label>
      </section>

      <section className="grid-fields">
        <label className="field">
          itemId
          <input
            type="text"
            value={itemId}
            onChange={(e) => setItemId(e.target.value)}
            disabled={status === "running"}
          />
        </label>
        <label className="field">
          ref
          <input
            type="text"
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            disabled={status === "running"}
          />
        </label>
        <label className="field">
          packageIndex
          <input
            type="text"
            value={packageIndex}
            onChange={(e) => setPackageIndex(e.target.value)}
            disabled={status === "running"}
          />
        </label>
        <label className="field">
          orderId
          <input
            type="text"
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            disabled={status === "running"}
          />
        </label>
        <label className="field">
          shipmentId
          <input
            type="text"
            value={shipmentId}
            onChange={(e) => setShipmentId(e.target.value)}
            disabled={status === "running"}
          />
        </label>
      </section>

      <section className="launch-preview">
        <strong>launch_page</strong>
        <code>{launchPage}</code>
      </section>

      <section className="row">
        <button
          type="button"
          onClick={handleAttest}
          disabled={status === "running" || !TEMPLATE_ID}
        >
          {status === "running" ? "Attesting..." : "Attest delivery code"}
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

      {status === "success" && result && (
        <section className="result">
          <h2>Delivery code attestation</h2>
          <div className="field-card">
            <div className="field-card-header">
              <strong>
                pickupCode{" "}
                <span
                  className={`match-pill match-${String(result.verified)}`}
                  title="local sha256(plaintext) vs signed hash"
                >
                  {result.verified === true
                    ? "match"
                    : result.verified === false
                      ? "mismatch"
                      : "unchecked"}
                </span>
              </strong>
              <code title="signed sha256">{result.signedHash}</code>
            </div>
            <pre title="extracted outer HTML">{result.plaintext}</pre>
          </div>
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
