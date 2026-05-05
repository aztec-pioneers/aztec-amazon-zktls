"use client";

export type UiStatus = "idle" | "running" | "success" | "error";

export function timestampedLog(line: string): string {
  return `[${new Date().toISOString()}] ${line}`;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : JSON.stringify(error);
}

export function errorMessageWithStack(error: unknown): string {
  if (!(error instanceof Error)) return JSON.stringify(error);
  return `${error.message}\n${error.stack ?? ""}`;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function attestationTimestamp(attestation: {
  timestamp?: number | string;
}): number | string {
  return attestation.timestamp ?? Date.now();
}

export function downloadJson(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
