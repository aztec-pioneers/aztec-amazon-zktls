"use client";

import type { PrimusZKTLS } from "@primuslabs/zktls-js-sdk";
import type { JsonResponseRow } from "@/lib/primus-extraction";

export type PrimusAttestationLike = {
  data?: string;
  requestid?: string;
  timestamp?: number | string;
};

export const PRIMUS_RECIPIENT = `0x${"00".repeat(20)}`;
export const PRIMUS_ATTESTATION_TIMEOUT_MS = 2 * 60 * 1000;

export function buildSha256AttestationRequest(
  primus: PrimusZKTLS,
  params: {
    templateId: string;
    fields: readonly string[];
    launchPage: string;
  },
): string {
  const request = primus.generateRequestParams(
    params.templateId,
    PRIMUS_RECIPIENT,
    { timeout: PRIMUS_ATTESTATION_TIMEOUT_MS },
  );
  request.setAdditionParams(
    JSON.stringify({ launch_page: params.launchPage }),
  );
  request.setAttConditions(
    [
      params.fields.map((field) => ({ field, op: "SHA256_EX" })),
    ] as unknown as Parameters<typeof request.setAttConditions>[0],
  );
  request.setAllJsonResponseFlag("true");
  return request.toJsonString();
}

export async function signPrimusRequest(requestJson: string): Promise<string> {
  const res = await fetch("/api/primus/sign", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ signParams: requestJson }),
  });
  if (!res.ok) {
    throw new Error(`sign endpoint returned ${res.status}: ${await res.text()}`);
  }
  const body = (await res.json()) as { signResult?: unknown };
  if (typeof body.signResult !== "string") {
    throw new Error("sign endpoint did not return signResult");
  }
  return body.signResult;
}

export function parseAttestationHashes(
  attestation: PrimusAttestationLike,
  onWarning?: (message: string) => void,
): Record<string, string> {
  if (typeof attestation.data !== "string") {
    onWarning?.("warn: attestation.data was missing; leaving hashes empty");
    return {};
  }
  try {
    const parsed = JSON.parse(attestation.data);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, string>;
    }
  } catch {
    onWarning?.("warn: attestation.data was not JSON; leaving hashes empty");
    return {};
  }
  onWarning?.("warn: attestation.data was not an object; leaving hashes empty");
  return {};
}

export function getAllJsonResponseRows(
  primus: PrimusZKTLS,
  attestation: PrimusAttestationLike,
): JsonResponseRow[] | null {
  if (!attestation.requestid) return null;
  const response = primus.getAllJsonResponse(attestation.requestid) as unknown;
  if (Array.isArray(response)) return response as JsonResponseRow[];
  if (typeof response === "string") return [{ content: response }];
  return null;
}

export function plaintextsByKey(
  rows: readonly { key: string; plaintext: string }[],
): Record<string, string> {
  return Object.fromEntries(rows.map((row) => [row.key, row.plaintext]));
}
