# `@amazon-zktls/frontend`

Next.js + React app that drives the browser-side Primus zkTLS flows:

1. **Invoice / order summary** — notarizes Amazon `print.html` and proves
   `shipmentStatus`, `productTitle`, `shipTo`, and `grandTotal`.
2. **Delivery code** — notarizes Amazon package tracking and proves
   `deliveryStatus`, `pickupCode`, and `orderId`.

Both flows use `@primuslabs/zktls-js-sdk` + the Primus Chrome extension for
attestation, then run the matching Noir circuit from
[`@amazon-zktls/circuit`](../circuit/) directly in the browser via bb.js.

## How it works

1. The browser builds a Primus extension request from the selected template
   and Amazon launch URL.
2. The browser POSTs the unsigned request to `/api/primus/sign`.
3. The server signs with `PRIMUS_APP_SECRET`; the secret never reaches the
   client bundle.
4. The Primus extension opens Amazon, captures the matching TLS response, runs
   the template XPaths, computes `sha256(extracted_plaintext)`, and returns a
   signed attestation.
5. The browser verifies the attestation signature, recovers the private
   plaintexts needed by Noir, runs the local proof, and lets the user download
   the attestation/proof JSON.

The Noir circuits re-hash each private plaintext with SHA-256, equate those
hashes to the attestation data, ECDSA-verify the attestor signature, and slice
the public outputs from the signed plaintext bytes.

## Prereqs

- Node.js 18+, `pnpm`.
- A Primus Developer Hub project — get `appId` + `appSecret` at
  https://dev.primuslabs.xyz. 100 free proofs per `appId`.
- Primus browser extension installed and enabled.
- An active amazon.com login in the browser profile used by the extension.

## Run

```bash
cp .env.local.example .env.local   # fill in Primus app/template settings
# from the repo root
pnpm install
pnpm --filter @amazon-zktls/circuit build:nr   # compile the Noir circuit once
pnpm --filter @amazon-zktls/frontend dev       # http://localhost:3000
```

Whenever you change Noir code under `packages/circuit/nr`, rerun
`build:nr` and refresh the browser — the compiled bytecode JSON is
imported directly into the bundle.

## Cross-origin isolation (required for fast proving)

Multi-threaded WASM inside the browser uses `SharedArrayBuffer`, which
the platform only exposes when the page is *cross-origin-isolated*.
This frontend's `next.config.ts` sets the two headers needed:

```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy:   same-origin
```

You can verify isolation in DevTools → Application → Frames → top
frame → "Cross-Origin Isolated: true". Without isolation,
`window.crossOriginIsolated` is `false` and the prove component
falls back to single-threaded WASM (much slower); the prover logs a
warning either way.

If you embed cross-origin sub-resources (CDN scripts, third-party
images, etc.) they need to opt in with
`Cross-Origin-Resource-Policy: cross-origin` or `crossorigin="anonymous"`
attributes — otherwise the browser blocks them under COEP.

The prove component picks `threads = navigator.hardwareConcurrency`
when isolation is on, `1` otherwise.

## XPath dialect

Primus' attestor parser is a restricted XPath 1.0 subset:

- `//*[@id="X"]/tag[N]/tag[N]/...` — id-anchored wildcard descendant, then
  pure child-axis. Every element step requires an explicit `[N]` index.
- Predicates: only `[@id="X"]` works. `[@class="X"]`,
  `[@data-component="X"]`, etc. trip `OtherError|basic_string`.
- No XPath functions anywhere — no `normalize-space`, `text()`,
  `contains()`, `substring*()`, `last()`, parens for grouping.
- Returns the matched element's outer HTML (open tag + attrs + inner +
  close), not its text content.

`scripts/test_xpaths.py` validates paths against local Amazon HTML fixtures
when present. Those fixtures contain account/order data and should stay
untracked; do not commit them.

```bash
python3 scripts/test_xpaths.py
```

## Trust model

The browser flow uses Primus' extension-backed zkTLS SDK. The server's only
role is signing the request with `PRIMUS_APP_SECRET`; it does not receive
Amazon cookies or fetch Amazon pages directly.

## Files

- `app/api/primus/sign/route.ts` — server-side `appSecret` signer for the
  attestation request, with template/request-shape validation.
- `components/AttestPurchaseBrowser.tsx` — orchestrates the
  `@primuslabs/zktls-js-sdk` flow: build request, sign on the server,
  hand off to the extension, verify, capture per-field outer-HTML.
- `components/AttestDeliveryCode.tsx` — runs the package-tracking flow and
  recovers the exact plaintexts Primus hashed for delivery status, locker code,
  and order id.
- `components/ProveAttestation.tsx` / `components/ProveDeliveryCode.tsx` — run
  the compiled Noir circuits in-browser and render/download proof outputs.
- `lib/primus-extraction.ts` — shared DOM/XPath/plaintext-hash recovery used by
  both attestation flows.
- `next.config.ts` — COEP/COOP headers needed for fast browser proving.

## Out of scope

- The Noir circuit itself lives under `packages/circuit`. See the
  `README.md` there for the verifier shape, the address-commitment
  spec, and the public-input layout.
