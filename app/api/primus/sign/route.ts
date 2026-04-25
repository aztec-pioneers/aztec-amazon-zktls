import { NextResponse } from "next/server";
import { PrimusZKTLS } from "@primuslabs/zktls-js-sdk";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

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

  // Reuse a single PrimusZKTLS instance per route module — init() is light
  // on the server side (no WASM here, unlike network-core-sdk's path), but
  // there's no reason to re-create it per request.
  const primus = new PrimusZKTLS();
  await primus.init(appId, appSecret);
  const signResult = await primus.sign(signParams);
  return NextResponse.json({ signResult });
}
