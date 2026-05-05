import { NextResponse } from "next/server";
import { PrimusZKTLS } from "@primuslabs/zktls-js-sdk";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const RECIPIENT = `0x${"00".repeat(20)}`;
const DEFAULT_INVOICE_TEMPLATE_ID = "a76464be-c145-4ec2-852c-9ce286674aa7";
const DEFAULT_DELIVERY_CODE_TEMPLATE_ID =
  "c08ac1d3-851e-472a-8591-00dfacf3c2d7";
const REQUEST_TIMEOUT_MS = 2 * 60 * 1000;
const MAX_SIGN_PARAMS_BYTES = 20_000;
const REQUEST_MAX_AGE_MS = 10 * 60 * 1000;
const REQUEST_MAX_FUTURE_SKEW_MS = 2 * 60 * 1000;

const FLOW_FIELDS = {
  invoice: ["shipmentStatus", "productTitle", "shipTo", "grandTotal"],
  deliveryCode: ["deliveryStatus", "pickupCode", "orderId"],
} as const;

type Flow = keyof typeof FLOW_FIELDS;
type SignRequest = Record<string, unknown>;

let signingPrimus:
  | {
      appId: string;
      appSecret: string;
      promise: Promise<PrimusZKTLS>;
    }
  | null = null;

function getSigningPrimus(
  appId: string,
  appSecret: string,
): Promise<PrimusZKTLS> {
  if (
    signingPrimus &&
    signingPrimus.appId === appId &&
    signingPrimus.appSecret === appSecret
  ) {
    return signingPrimus.promise;
  }

  const promise = (async () => {
    const primus = new PrimusZKTLS();
    await primus.init(appId, appSecret);
    return primus;
  })().catch((error) => {
    if (signingPrimus?.promise === promise) {
      signingPrimus = null;
    }
    throw error;
  });

  signingPrimus = { appId, appSecret, promise };
  return promise;
}

function envOr(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : fallback;
}

function reject(message: string): never {
  throw new Error(message);
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    reject(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function parseJsonRecord(value: string, label: string): Record<string, unknown> {
  try {
    return asRecord(JSON.parse(value), label);
  } catch (e) {
    if (e instanceof Error && e.message.includes("must be an object")) throw e;
    reject(`${label} must be valid JSON`);
  }
}

function assertOnlyKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
) {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allowedSet.has(key)) reject(`${label} has unexpected key '${key}'`);
  }
}

function assertString(value: unknown, expected: string, label: string) {
  if (value !== expected) reject(`${label} must be '${expected}'`);
}

function assertOptionalString(value: unknown, expected: string, label: string) {
  if (value !== undefined && value !== expected) {
    reject(`${label} must be '${expected}'`);
  }
}

function assertTemplateFlow(
  templateId: unknown,
): { flow: Flow; templateId: string } {
  if (typeof templateId !== "string" || templateId.trim() === "") {
    reject("attTemplateID must be a string");
  }
  const invoiceTemplateId = envOr(
    process.env.NEXT_PUBLIC_PRIMUS_INVOICE_TEMPLATE_ID,
    DEFAULT_INVOICE_TEMPLATE_ID,
  );
  const deliveryTemplateId = envOr(
    process.env.NEXT_PUBLIC_PRIMUS_DELIVERY_CODE_TEMPLATE_ID,
    DEFAULT_DELIVERY_CODE_TEMPLATE_ID,
  );
  if (templateId === invoiceTemplateId) return { flow: "invoice", templateId };
  if (templateId === deliveryTemplateId) {
    return { flow: "deliveryCode", templateId };
  }
  reject("attTemplateID is not allowlisted");
}

function assertTimestamp(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    reject("timestamp must be a safe integer");
  }
  const now = Date.now();
  if (value < now - REQUEST_MAX_AGE_MS) reject("timestamp is too old");
  if (value > now + REQUEST_MAX_FUTURE_SKEW_MS) {
    reject("timestamp is too far in the future");
  }
}

function assertRequestId(value: unknown) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  ) {
    reject("requestid must be a UUID");
  }
}

function assertAttConditions(value: unknown, flow: Flow) {
  if (!Array.isArray(value) || value.length !== 1 || !Array.isArray(value[0])) {
    reject("attConditions must contain one request condition group");
  }
  const expectedFields = FLOW_FIELDS[flow];
  const group = value[0] as unknown[];
  if (group.length !== expectedFields.length) {
    reject("attConditions has wrong field count");
  }
  for (let i = 0; i < expectedFields.length; i++) {
    const condition = asRecord(group[i], `attConditions[0][${i}]`);
    assertOnlyKeys(condition, ["field", "op"], `attConditions[0][${i}]`);
    assertString(condition.field, expectedFields[i], `attConditions[0][${i}].field`);
    assertString(condition.op, "SHA256_EX", `attConditions[0][${i}].op`);
  }
}

function assertAmazonUrlBase(url: URL, expectedPath: string) {
  if (url.origin !== "https://www.amazon.com") {
    reject("launch_page must use https://www.amazon.com");
  }
  if (url.pathname !== expectedPath) {
    reject(`launch_page pathname must be ${expectedPath}`);
  }
  if (url.username || url.password || url.port || url.hash) {
    reject("launch_page must not include credentials, port, or hash");
  }
}

function assertAmazonOrderId(value: string, label: string) {
  if (!/^\d{3}-\d{7}-\d{7}$/.test(value)) {
    reject(`${label} must be an Amazon order id`);
  }
}

function assertQueryKeys(url: URL, allowed: readonly string[]) {
  const allowedSet = new Set(allowed);
  for (const key of url.searchParams.keys()) {
    if (!allowedSet.has(key)) reject(`launch_page has unexpected query param '${key}'`);
  }
}

function assertSafeQueryValue(value: string, label: string) {
  if (!/^[A-Za-z0-9_.-]{1,160}$/.test(value)) {
    reject(`${label} has invalid characters`);
  }
}

function assertInvoiceLaunchPage(url: URL) {
  assertAmazonUrlBase(url, "/gp/css/summary/print.html");
  assertQueryKeys(url, ["orderID"]);
  const orderId = url.searchParams.get("orderID") ?? "";
  assertAmazonOrderId(orderId, "launch_page orderID");
}

function assertDeliveryLaunchPage(url: URL) {
  assertAmazonUrlBase(url, "/gp/your-account/ship-track");
  assertQueryKeys(url, ["itemId", "ref", "packageIndex", "orderId", "shipmentId"]);

  const orderId = url.searchParams.get("orderId") ?? "";
  assertAmazonOrderId(orderId, "launch_page orderId");
  for (const key of ["itemId", "shipmentId"] as const) {
    assertSafeQueryValue(url.searchParams.get(key) ?? "", `launch_page ${key}`);
  }
  const packageIndex = url.searchParams.get("packageIndex");
  if (packageIndex !== null && !/^\d{1,4}$/.test(packageIndex)) {
    reject("launch_page packageIndex must be numeric");
  }
  const ref = url.searchParams.get("ref");
  if (ref !== null) assertSafeQueryValue(ref, "launch_page ref");
}

function assertAdditionParams(value: unknown, flow: Flow) {
  if (typeof value !== "string") reject("additionParams must be a JSON string");
  const additionParams = parseJsonRecord(value, "additionParams");
  assertOnlyKeys(additionParams, ["launch_page"], "additionParams");
  if (typeof additionParams.launch_page !== "string") {
    reject("additionParams.launch_page must be a string");
  }
  let url: URL;
  try {
    url = new URL(additionParams.launch_page);
  } catch {
    reject("additionParams.launch_page must be an absolute URL");
  }
  if (flow === "invoice") assertInvoiceLaunchPage(url);
  else assertDeliveryLaunchPage(url);
}

function assertSignParams(signParams: string, appId: string) {
  if (new TextEncoder().encode(signParams).length > MAX_SIGN_PARAMS_BYTES) {
    reject("signParams is too large");
  }
  const parsed = parseJsonRecord(signParams, "signParams") as SignRequest;
  assertOnlyKeys(
    parsed,
    [
      "appId",
      "attTemplateID",
      "userAddress",
      "timestamp",
      "attMode",
      "attConditions",
      "additionParams",
      "requestid",
      "backUrl",
      "computeMode",
      "extendedParams",
      "noProxy",
      "allJsonResponseFlag",
      "timeout",
      "closeDataSourceOnProofComplete",
    ],
    "signParams",
  );

  assertString(parsed.appId, appId, "appId");
  const { flow } = assertTemplateFlow(parsed.attTemplateID);
  assertString(parsed.userAddress, RECIPIENT, "userAddress");
  assertTimestamp(parsed.timestamp);
  assertRequestId(parsed.requestid);

  const attMode = asRecord(parsed.attMode, "attMode");
  assertOnlyKeys(attMode, ["algorithmType", "resultType"], "attMode");
  assertString(attMode.algorithmType, "proxytls", "attMode.algorithmType");
  assertString(attMode.resultType, "plain", "attMode.resultType");

  assertAttConditions(parsed.attConditions, flow);
  assertAdditionParams(parsed.additionParams, flow);
  assertOptionalString(parsed.backUrl, "", "backUrl");
  assertOptionalString(parsed.computeMode, "normal", "computeMode");
  assertOptionalString(parsed.extendedParams, "", "extendedParams");
  if (parsed.noProxy !== true) reject("noProxy must be true");
  assertString(parsed.allJsonResponseFlag, "true", "allJsonResponseFlag");
  if (parsed.timeout !== REQUEST_TIMEOUT_MS) {
    reject(`timeout must be ${REQUEST_TIMEOUT_MS}`);
  }
  if (
    parsed.closeDataSourceOnProofComplete !== undefined &&
    parsed.closeDataSourceOnProofComplete !== true
  ) {
    reject("closeDataSourceOnProofComplete must be true when present");
  }
}

// Production-mode signing route. The browser builds an unsigned AttRequest
// with `generateRequestParams(templateId, userAddress).toJsonString()` and
// POSTs it here; we sign with PRIMUS_APP_SECRET so the secret never reaches
// the client bundle, then return the signed string for `startAttestation`.
export async function POST(req: Request) {
  const appId = process.env.NEXT_PUBLIC_PRIMUS_APP_ID;
  const appSecret = process.env.PRIMUS_APP_SECRET;
  if (!appId || !appSecret) {
    return NextResponse.json(
      { error: "NEXT_PUBLIC_PRIMUS_APP_ID and PRIMUS_APP_SECRET must be set" },
      { status: 500 },
    );
  }

  let body: { signParams?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }
  const { signParams } = body;
  if (typeof signParams !== "string" || signParams.length === 0) {
    return NextResponse.json(
      { error: "signParams (string) required" },
      { status: 400 },
    );
  }
  try {
    assertSignParams(signParams, appId);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "invalid signParams" },
      { status: 400 },
    );
  }

  const primus = await getSigningPrimus(appId, appSecret);
  const signResult = await primus.sign(signParams);
  return NextResponse.json({ signResult });
}
