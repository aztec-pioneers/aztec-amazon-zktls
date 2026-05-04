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
  attestor pubkey) aren't bound to `hash` in-circuit. v2 should reconstruct the
  canonical Primus message and assert `keccak256(canonical) == hash`.
- I used Claude, there's slop, don't @ me.
