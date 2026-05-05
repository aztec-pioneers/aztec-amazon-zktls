"use client";

import { useCallback, useMemo, useState } from "react";
import { getPrimus } from "@/lib/primus-client";
import {
  attestationTimestamp,
  downloadJson,
  errorMessage,
  timestampedLog,
  type UiStatus,
} from "@/lib/browser-utils";
import {
  extractOrderId,
  normalizedTextContent,
  resolveSignedPlaintext,
} from "@/lib/primus-extraction";
import {
  buildSha256AttestationRequest,
  getAllJsonResponseRows,
  parseAttestationHashes,
  plaintextsByKey,
  signPrimusRequest,
  type PrimusAttestationLike,
} from "@/lib/primus-flow";
import {
  ProveDeliveryCode,
  type ProveDeliveryCodeProps,
} from "./ProveDeliveryCode";
import {
  AttestedFieldCards,
  type AttestedFieldRow,
} from "./AttestedFieldCards";

type DeliveryFieldRow = AttestedFieldRow & {
  value: string;
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
const DEFAULT_TEMPLATE_ID = "c08ac1d3-851e-472a-8591-00dfacf3c2d7";
const DELIVERY_PARAM_KEYS = [
  "itemId",
  "ref",
  "packageIndex",
  "orderId",
  "shipmentId",
] as const;

type DeliveryParamKey = (typeof DELIVERY_PARAM_KEYS)[number];
type DeliveryParams = Record<DeliveryParamKey, string>;

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

const DEFAULTS: DeliveryParams = {
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

function getDeliveryParam(urlString: string, key: DeliveryParamKey): string {
  return key === "orderId" ? getOrderIdParam(urlString) : getUrlParam(urlString, key);
}

function readDeliveryParams(urlString: string): DeliveryParams {
  return Object.fromEntries(
    DELIVERY_PARAM_KEYS.map((key) => [key, getDeliveryParam(urlString, key)]),
  ) as DeliveryParams;
}

function buildLaunchPage(baseUrl: string, params: DeliveryParams): string {
  let url: URL;
  try {
    url = new URL(
      baseUrl.trim() || DEFAULT_DELIVERY_URL,
      "https://www.amazon.com",
    );
  } catch {
    url = new URL(DEFAULT_DELIVERY_URL);
  }

  for (const key of DELIVERY_PARAM_KEYS) {
    url.searchParams.delete(key);
  }
  url.searchParams.delete("orderID");

  for (const key of DELIVERY_PARAM_KEYS) {
    const trimmed = params[key].trim() || getDeliveryParam(baseUrl, key);
    if (trimmed) url.searchParams.append(key, trimmed);
  }
  return url.toString();
}

export default function AttestDeliveryCode() {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_DELIVERY_URL);
  const [deliveryParams, setDeliveryParams] = useState(DEFAULTS);
  const [status, setStatus] = useState<UiStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] =
    useState<PrimusAttestationLike | null>(null);
  const [result, setResult] = useState<DeliveryFieldRow[] | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const launchPage = useMemo(
    () => buildLaunchPage(baseUrl, deliveryParams),
    [baseUrl, deliveryParams],
  );

  const log = (line: string) =>
    setLogs((prev) => [...prev, timestampedLog(line)]);

  const handleTrackingUrlChange = useCallback((value: string) => {
    setBaseUrl(value);
    setDeliveryParams(readDeliveryParams(value));
  }, []);

  const updateDeliveryParam = useCallback(
    (key: DeliveryParamKey, value: string) => {
      setDeliveryParams((current) => ({ ...current, [key]: value }));
    },
    [],
  );

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
      const requestStr = buildSha256AttestationRequest(primus, {
        templateId: TEMPLATE_ID,
        fields: FIELD_KEYS,
        launchPage,
      });

      log("POST /api/primus/sign (server signs with appSecret)");
      const signResult = await signPrimusRequest(requestStr);

      log("startAttestation - Primus extension opens Amazon package tracking");
      const att = await primus.startAttestation(signResult);
      log("attestation returned, verifying signature");

      const ok = primus.verifyAttestation(att);
      if (!ok) throw new Error("verifyAttestation returned false");
      log("signature verified");

      const hashes = parseAttestationHashes(att, log);

      const allJson = getAllJsonResponseRows(primus, att);
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

      setAttestation(att);
      setResult(rows);
      setStatus("success");
    } catch (e) {
      const msg = errorMessage(e);
      log(`error: ${msg}`);
      setError(msg);
      setStatus("error");
    }
  }, [launchPage]);

  const handleDownload = useCallback(() => {
    if (!attestation) return;
    const payload = {
      ...attestation,
      _plaintexts: result ? plaintextsByKey(result) : {},
      _values: result
        ? Object.fromEntries(result.map((r) => [r.key, r.value]))
        : {},
    };
    downloadJson(
      `delivery-code-attestation-${attestationTimestamp(attestation)}.json`,
      payload,
    );
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
        {DELIVERY_PARAM_KEYS.map((key) => (
          <label className="field" key={key}>
            {key}
            <input
              type="text"
              value={deliveryParams[key]}
              onChange={(e) => updateDeliveryParam(key, e.target.value)}
              disabled={status === "running"}
            />
          </label>
        ))}
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
          <AttestedFieldCards
            rows={result}
            plaintextTitle="extracted plaintext hashed by Primus"
          />
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
          plaintexts={plaintextsByKey(result)}
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
