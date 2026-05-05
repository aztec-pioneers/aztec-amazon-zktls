"use client";

import { useCallback, useMemo, useState } from "react";
import { getPrimus } from "@/lib/primus-client";
import {
  ProveDeliveryCode,
  type ProveDeliveryCodeProps,
} from "./ProveDeliveryCode";

type Status = "idle" | "running" | "success" | "error";

type DeliveryFieldRow = {
  key: string;
  signedHash: string;
  localHash: string;
  plaintext: string;
  value: string;
  source: string;
  verified: boolean | null;
};

type JsonResponseRow = {
  id?: string;
  content?: string;
};

const DELIVERY_STATUS_FIELD = "deliveryStatus";
const DELIVERY_STATUS_XPATH =
  '//*[@id="topContent-container"]/section[@class="pt-card promise-card"]/h1[1]';
const PICKUP_CODE_FIELD = "pickupCode";
const PICKUP_CODE_XPATH = '//*[@id="pickupInformation-container"]/h1[1]';
const ORDER_ID_FIELD = "orderId";
const ORDER_ID_XPATH =
  '//*[@id="ordersInPackage-container"]/div[1]/div[1]/a[1]/@href';
const FIELD_PATHS = [
  {
    key: DELIVERY_STATUS_FIELD,
    xpath: DELIVERY_STATUS_XPATH,
    valueFromPlaintext: (plaintext: string) => normalizedTextContent(plaintext),
  },
  {
    key: PICKUP_CODE_FIELD,
    xpath: PICKUP_CODE_XPATH,
    valueFromPlaintext: (plaintext: string) =>
      normalizedTextContent(plaintext).replace(/^Your pickup code is\s+/i, ""),
  },
  {
    key: ORDER_ID_FIELD,
    xpath: ORDER_ID_XPATH,
    valueFromPlaintext: (plaintext: string) => extractOrderId(plaintext),
  },
] as const;
const FIELD_KEYS = FIELD_PATHS.map((f) => f.key);
const RECIPIENT = `0x${"00".repeat(20)}`;
const DEFAULT_TEMPLATE_ID = "c08ac1d3-851e-472a-8591-00dfacf3c2d7";

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

function getOrderIdParam(urlString: string): string {
  return getUrlParam(urlString, "orderId") || getUrlParam(urlString, "orderID");
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
    getOrderIdParam(DEFAULT_DELIVERY_URL),
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

function isSha256Hex(value: string): boolean {
  return /^[0-9a-f]{64}$/i.test(value);
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

function extractOrderId(plaintext: string): string {
  let href = plaintext;
  if (plaintext.trimStart().startsWith("<")) {
    const parsed = new DOMParser().parseFromString(plaintext, "text/html");
    href = parsed.querySelector("a")?.getAttribute("href") ?? plaintext;
  }
  try {
    const url = new URL(href, "https://www.amazon.com");
    return (
      url.searchParams.get("orderID") ??
      url.searchParams.get("orderId") ??
      href.match(/\borderI[Dd]=([^&]+)/)?.[1] ??
      ""
    );
  } catch {
    return href.match(/\borderI[Dd]=([^&]+)/)?.[1] ?? "";
  }
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
    ).singleNodeValue as Node | null;
    if (!node) return null;
    if (node.nodeType === Node.ATTRIBUTE_NODE) return (node as Attr).value;
    if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? "";
    if (!(node instanceof Element)) return node.textContent ?? "";

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

function rawAttributeCandidate(
  html: string,
  xpath: string,
): { plaintext: string; sourceKind: string } | null {
  const match = xpath.match(/^(.*)\/@([A-Za-z_:][\w:.-]*)$/);
  if (!match) return null;
  const [, elementXPath, attrName] = match;
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = doc.evaluate(
      elementXPath,
      doc,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null,
    ).singleNodeValue as Node | null;
    if (!(node instanceof Element)) return null;

    const rawElement = extractByXPath(html, elementXPath) ?? node.outerHTML;
    const openTagEnd = rawElement.indexOf(">");
    const rawOpenTag =
      openTagEnd === -1 ? rawElement : rawElement.substring(0, openTagEnd + 1);
    const attrRe = new RegExp(
      `\\s${attrName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=(["'])(.*?)\\1`,
      "i",
    );
    const attrMatch = rawOpenTag.match(attrRe);
    return attrMatch
      ? { plaintext: attrMatch[2], sourceKind: "raw-attr" }
      : null;
  } catch {
    return null;
  }
}

function xpathPlaintextCandidates(
  html: string,
  xpath: string,
): { plaintext: string; sourceKind: string }[] {
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = doc.evaluate(
      xpath,
      doc,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null,
    ).singleNodeValue as Node | null;
    if (!node) return [];
    if (node.nodeType === Node.ATTRIBUTE_NODE) {
      const rawAttr = rawAttributeCandidate(html, xpath);
      return [
        ...(rawAttr ? [rawAttr] : []),
        { plaintext: (node as Attr).value, sourceKind: "attr" },
      ];
    }
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent?.trim() ?? "";
      return text ? [{ plaintext: text, sourceKind: "text" }] : [];
    }
    if (!(node instanceof Element)) {
      const text = node.textContent?.trim() ?? "";
      return text ? [{ plaintext: text, sourceKind: "text" }] : [];
    }

    const candidates: { plaintext: string; sourceKind: string }[] = [];
    const seen = new Set<string>();
    const add = (plaintext: string | null | undefined, sourceKind: string) => {
      const value = plaintext ?? "";
      if (!value || seen.has(value)) return;
      seen.add(value);
      candidates.push({ plaintext: value, sourceKind });
    };

    for (const child of Array.from(node.childNodes)) {
      if (child.nodeType !== Node.TEXT_NODE) continue;
      add(child.textContent?.trim(), "direct-text");
    }
    add(node.textContent?.trim(), "text-content");
    add(extractByXPath(html, xpath), "outer-html");
    add(node.outerHTML, "serialized-html");
    return candidates;
  } catch {
    return [];
  }
}

async function resolveSignedPlaintext({
  allJson,
  key,
  xpath,
  signedHash,
}: {
  allJson: JsonResponseRow[] | null;
  key: string;
  xpath: string;
  signedHash: string;
}): Promise<{
  plaintext: string;
  localHash: string;
  source: string;
  verified: boolean | null;
}> {
  const candidates = Array.isArray(allJson)
    ? allJson
        .map((entry, index) => ({
          id: entry.id ?? "",
          content: entry.content ?? "",
          index,
        }))
        .filter((entry) => entry.content)
    : [];
  const canCheck = isSha256Hex(signedHash);

  const check = async (plaintext: string) => {
    const localHash = await sha256Hex(plaintext);
    return {
      localHash,
      verified: canCheck
        ? localHash.toLowerCase() === signedHash.toLowerCase()
        : null,
    };
  };

  const sameId = candidates.filter((entry) => entry.id === key);
  const ordered = [
    ...sameId,
    ...candidates.filter((entry) => entry.id !== key),
  ];

  for (const entry of ordered) {
    const { localHash, verified } = await check(entry.content);
    if (verified) {
      return {
        plaintext: entry.content,
        localHash,
        source: `allJson[${entry.index}]${entry.id ? `:${entry.id}` : ""}`,
        verified,
      };
    }
  }

  let firstExtracted:
    | { plaintext: string; localHash: string; verified: boolean | null; source: string }
    | null = null;
  for (const entry of ordered) {
    const candidates = xpathPlaintextCandidates(entry.content, xpath);
    for (const candidate of candidates) {
      const { localHash, verified } = await check(candidate.plaintext);
      const source = `xpath-${candidate.sourceKind}(allJson[${entry.index}]${
        entry.id ? `:${entry.id}` : ""
      })`;
      const row = { plaintext: candidate.plaintext, localHash, verified, source };
      if (!firstExtracted) firstExtracted = row;
      if (verified) return row;
    }
  }

  if (firstExtracted) return firstExtracted;

  return {
    plaintext: "(missing)",
    localHash: "",
    source: "missing",
    verified: null,
  };
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
  const [result, setResult] = useState<DeliveryFieldRow[] | null>(null);
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

  const handleTrackingUrlChange = useCallback((value: string) => {
    setBaseUrl(value);
    setItemId(getUrlParam(value, "itemId"));
    setRef(getUrlParam(value, "ref"));
    setPackageIndex(getUrlParam(value, "packageIndex"));
    setOrderId(getOrderIdParam(value));
    setShipmentId(getUrlParam(value, "shipmentId"));
  }, []);

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
          FIELD_KEYS.map((field) => ({ field, op: "SHA256_EX" })),
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
      ) as JsonResponseRow[] | null;
      const rows = await Promise.all(
        FIELD_PATHS.map(async ({ key, xpath, valueFromPlaintext }) => {
          const signedHash = hashes[key] ?? "(missing)";
          const resolved = await resolveSignedPlaintext({
            allJson,
            key,
            xpath,
            signedHash,
          });
          const value =
            resolved.plaintext !== "(missing)"
              ? valueFromPlaintext(resolved.plaintext)
              : "";
          return { key, signedHash, value, ...resolved };
        }),
      );

      console.log("[primus] delivery-code attestation", att);
      console.log("[primus] delivery-code allJson", allJson);
      console.log("[primus] delivery-code rows", rows);

      setAttestation(att);
      setResult(rows);
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
      _plaintexts: result
        ? Object.fromEntries(result.map((r) => [r.key, r.plaintext]))
        : {},
      _values: result
        ? Object.fromEntries(result.map((r) => [r.key, r.value]))
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
            onChange={(e) => handleTrackingUrlChange(e.target.value)}
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
          {result.map((row) => (
            <div className="field-card" key={row.key}>
              <div className="field-card-header">
                <strong>
                  {row.key}{" "}
                  <span
                    className={`match-pill match-${String(row.verified)}`}
                    title="local sha256(plaintext) vs signed hash"
                  >
                    {row.verified === true
                      ? "match"
                      : row.verified === false
                        ? "mismatch"
                        : "unchecked"}
                  </span>
                </strong>
                <code title="signed sha256">{row.signedHash}</code>
              </div>
              {row.localHash ? (
                <p className="field-value">
                  <span>local sha256</span>
                  <code>{row.localHash}</code>
                </p>
              ) : null}
              <p className="field-value">
                <span>source</span>
                <code>{row.source}</code>
              </p>
              {row.value ? (
                <p className="field-value">
                  <span>value</span>
                  <code>{row.value}</code>
                </p>
              ) : null}
              <pre title="extracted plaintext hashed by Primus">{row.plaintext}</pre>
            </div>
          ))}
          <button type="button" onClick={handleDownload}>
            Download attestation.json
          </button>
        </section>
      )}

      {status === "success" && attestation !== null && result ? (
        <ProveDeliveryCode
          attestation={
            attestation as ProveDeliveryCodeProps["attestation"]
          }
          plaintexts={Object.fromEntries(
            result.map((r): [string, string] => [r.key, r.plaintext]),
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
