# amazon-zktls

Trustless escrow for "buy-this-Amazon-item-for-me" bounties on Aztec, settled by a Primus
zkTLS attestation that the item was actually delivered to the order creator's address.

## How it works

1. **Order creator** posts a private bounty on Aztec: _"pay AMOUNT in USDC to whoever
   delivers ASIN X to address H."_ Address is committed (poseidon2 over packed shipping
   lines) so it stays private.
2. **Filler** buys the item on Amazon, has it shipped to the creator's real address, and
   visits the [frontend](packages/frontend/) to attest the order summary page via
   Primus zkTLS. The browser runs the Noir circuit in-process and produces a proof whose
   public outputs are `(asin, grand_total, address_commitment, nullifier)`.
3. **Filler claims** by calling `settle_order` on the escrow with a `>Delivered `
   attestation, or first calls `enter_settlement_in_progress` with an `>Arriving `
   attestation to flag mid-flight progress and start a 10-day clawback timer. The
   contract re-runs the verifier inline (same Noir lib the browser used), asserts
   `asin` and `address_commitment` match the order, gates on an admin-curated
   attestor pubkey registry, pushes the per-stage nullifiers, and pays the filler.
4. **Order creator** can call `void_order` to claw back funds — immediately if no
   buyer has entered SIP, or after a 10-day window if SIP fired but never settled.

The chain stores nothing about the buyer's identity, the shipping address, or the order
contents — only commitments. Replay across orders is blocked by the proof nullifier;
state-machine progression is enforced by per-stage nullifiers
(`Poseidon2(serialize(config) || [stage])`) plus a kernel-checked
`assert_nullifier_exists` for prior-stage gating.

## Layout

```
packages/
├── circuit/    Noir circuit + TS prover. Verifies a Primus attestation and
│               extracts (asin, grand_total, address_commitment, nullifier).
│
├── contracts/  Aztec contracts: AmazonEscrow (per-order private escrow that
│               re-runs the circuit lib inline) + AttestorKeyOracle (admin-
│               curated PublicImmutable map of allowed pubkey hashes).
│
└── frontend/   Next.js app. Drives the browser-side flow: attest via
                Primus, prove with bb.js, render the public outputs ready
                for an on-chain fill.
```

Each package has its own README with build/test specifics.

## Versions

- Aztec **`v4.2.0-aztecnr-rc.2`** for both `aztec-nr` and `aztec-standards`. Compile
  scripts PATH-prefix `$HOME/.aztec/current/bin` so aztec's bundled nargo (beta.18)
  wins over a system nargo (beta.20) — `aztec-nr` v4.2.0 doesn't compile under beta.20.
- Noir **`1.0.0-beta.18`** (via aztec).
- bb.js **`3.0.0-nightly.20260102`** for browser proving.

## Quick start

```sh
git clone --recurse-submodules <repo>
cd amazon-zktls
pnpm install

# Build everything (Noir + TS).
pnpm -r build

# Frontend dev server.
pnpm dev

# Contracts test (in another terminal: aztec start --local-network).
pnpm test:contracts
```

## Primus Template Creation

The Primus templates are created in the Primus Developer Hub and published through the
developer-template MCP endpoint from:

```txt
https://dev.primuslabs.xyz/myDevelopment/myTemplates/newByAI
```

That page gives a posting endpoint that includes the account-specific MCP key. Treat that
URL like a secret and do not commit it. The current browser flows use these template env
vars:

```env
NEXT_PUBLIC_PRIMUS_INVOICE_TEMPLATE_ID=a76464be-c145-4ec2-852c-9ce286674aa7
NEXT_PUBLIC_PRIMUS_DELIVERY_CODE_TEMPLATE_ID=c08ac1d3-851e-472a-8591-00dfacf3c2d7
```

For delivery-code template changes, create a new template instead of mutating the old
one, and name it with an explicit suffix such as `amazon_delivery_code-v10`. After
publishing, update `packages/frontend/.env.local.example`, local `.env.local`, and the
fallback template id in `packages/frontend/components/AttestDeliveryCode.tsx` if needed.

The final delivery-code template is HTML-backed. Primus still expects
`resolver.type = "JSON_PATH"` for these HTML XPaths, and `ignoreResponse = true` tells it
to evaluate against the document body:

```json
{
  "name": "amazon_delivery_code-v10",
  "category": "OTHER",
  "status": "DRAFT",
  "dataSource": "amazon",
  "dataPageTemplate": {
    "baseUrl": "https://www.amazon.com/gp/your-account/ship-track"
  },
  "dataSourceTemplate": [
    {
      "requestTemplate": {
        "targetUrlExpression": "https://www\\.amazon\\.com/gp/your-account/ship-track(?:\\?.*)?",
        "targetUrlType": "REGX",
        "method": "GET",
        "ext": {},
        "dynamicParamters": [],
        "ignoreResponse": true
      },
      "responseTemplate": [
        {
          "resolver": {
            "type": "JSON_PATH",
            "expression": "//*[@id=\"topContent-container\"]/section[@class=\"pt-card promise-card\"]/h1[1]"
          },
          "valueType": "FIXED_VALUE",
          "fieldType": "FIELD_REVEAL",
          "feilds": [
            {
              "key": "deliveryStatus",
              "DataType": "string"
            }
          ]
        },
        {
          "resolver": {
            "type": "JSON_PATH",
            "expression": "//*[@id=\"pickupInformation-container\"]/h1[1]"
          },
          "valueType": "FIXED_VALUE",
          "fieldType": "FIELD_REVEAL",
          "feilds": [
            {
              "key": "pickupCode",
              "DataType": "string"
            }
          ]
        },
        {
          "resolver": {
            "type": "JSON_PATH",
            "expression": "//*[@id=\"ordersInPackage-container\"]/div[1]/div[1]/a[1]/@href"
          },
          "valueType": "FIXED_VALUE",
          "fieldType": "FIELD_REVEAL",
          "feilds": [
            {
              "key": "orderId",
              "DataType": "string"
            }
          ]
        }
      ]
    }
  ]
}
```

The frontend launches the Primus extension with Amazon tracking URL params from the
tracking link. Keep all five params because Amazon's tracking page may require
`itemId`, `ref`, `packageIndex`, `orderId`, and `shipmentId` for a stable page load:

```ts
const request = primus.generateRequestParams(templateId, RECIPIENT, {
  timeout: 2 * 60 * 1000,
});

request.setAdditionParams(JSON.stringify({ launch_page }));
request.setAttConditions([
  [
    { field: "deliveryStatus", op: "SHA256_EX" },
    { field: "pickupCode", op: "SHA256_EX" },
    { field: "orderId", op: "SHA256_EX" }
  ]
]);
request.setAllJsonResponseFlag("true");
```

Hash matching is the important validation step. The signed hashes are in
`JSON.parse(attestation.data)[field]`, while the plaintext candidates come from
`primus.getAllJsonResponse(attestation.requestid)`. Do not assume the signed plaintext is
always `outerHTML`: for the current template Primus signs direct text for
`deliveryStatus` (`Delivered`) and `pickupCode` (`Your pickup code is 123456`), and the
raw `href` attribute for `orderId`. The raw attribute can contain HTML entities such as
`&amp;`, so the UI hashes the raw value first, then parses out the display order id.

After a successful attestation, download the JSON from the UI. The downloaded file keeps
the original Primus attestation intact and adds sidecar data used by tests and Noir
proving:

```json
{
  "_plaintexts": {
    "deliveryStatus": "Delivered",
    "pickupCode": "Your pickup code is 123456",
    "orderId": "/gp/your-account/order-details?orderID=123-1234567-1234567&amp;ref=ppx_pt2_dt_b_view_detail"
  },
  "_values": {
    "deliveryStatus": "Delivered",
    "pickupCode": "123456",
    "orderId": "123-1234567-1234567"
  }
}
```

## Technical deficiencies

If we move forward with this, here's the open backlog:

- Need to handle multiple countries (specifically India to start) since that is the
  narrative / use case.
- Need to optimize — most important: switch Primus mode from sha hashes to Pedersen
  commitments.
- Order discovery off-chain and handle order-fill failure paths on-chain.
- ASIN constraining — we need to make sure you can't post an Amazon item where the
  name of the product shown on amazon.com isn't actually the product number.
- Attestation pub keys are public immutable and should be delayed-public mutable.
- Forked the Primus SDK since they have a number of incompatibilities with Noir beta.20.
- Actually had to downgrade to .18 which still isn't compatible with Primus; need to
  get on the latest testnet version.
- Per-field `MAX_*` bounds in `amazon_zktls_lib` share one ceiling per axis — tighten
  them to save sha256 constraints.
- Soundness gap in the circuit: public inputs (`recipient`, `timestamp`, `hashes`,
  attestor pubkey) aren't bound to `hash` in-circuit. We are tracking the canonical
  Primus discussion in
  [primus-labs/zktls-verification-noir#9](https://github.com/primus-labs/zktls-verification-noir/issues/9)
  and are not fixing this locally yet.
- I used Claude, there's slop, don't @ me.
