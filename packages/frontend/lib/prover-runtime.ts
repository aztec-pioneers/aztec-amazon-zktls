"use client";

import { Barretenberg } from "@amazon-zktls/circuit";

let sharedBb:
  | {
      threads: number;
      promise: Promise<Barretenberg>;
    }
  | null = null;

export function getProverRuntimeProfile(): {
  isolated: boolean;
  threads: number;
} {
  const isolated = typeof window !== "undefined" && window.crossOriginIsolated;
  const cores = navigator.hardwareConcurrency || 4;
  return { isolated, threads: isolated ? cores : 1 };
}

export function getSharedBarretenberg(threads: number): Promise<Barretenberg> {
  if (!sharedBb || sharedBb.threads !== threads) {
    sharedBb = {
      threads,
      promise: Barretenberg.new({ threads }),
    };
  }
  return sharedBb.promise;
}
