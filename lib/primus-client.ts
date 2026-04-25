"use client";

import type { PrimusZKTLS as PrimusZKTLSType } from "@primuslabs/zktls-js-sdk";

// Lazy singleton. Dynamic-import keeps the browser-only SDK out of the
// server bundle entirely (it has no SSR path; importing it eagerly tries to
// reference `window` during Next.js' RSC pass).
let instance: PrimusZKTLSType | null = null;
let initPromise: Promise<PrimusZKTLSType> | null = null;

export function getPrimus(): Promise<PrimusZKTLSType> {
  if (instance) return Promise.resolve(instance);
  if (initPromise) return initPromise;

  const appId = process.env.NEXT_PUBLIC_PRIMUS_APP_ID;
  if (!appId) {
    return Promise.reject(
      new Error("NEXT_PUBLIC_PRIMUS_APP_ID is not set in .env.local"),
    );
  }

  initPromise = (async () => {
    const { PrimusZKTLS } = await import("@primuslabs/zktls-js-sdk");
    const p = new PrimusZKTLS();
    // Production mode: appSecret stays server-side. Pass only appId here;
    // the API route (/api/primus/sign) does the signing.
    await p.init(appId);
    instance = p;
    return p;
  })();
  return initPromise;
}
