# `@amazon-zktls/contracts`

Aztec contracts that consume the `@amazon-zktls/circuit` zkTLS verifier:

- **`AmazonEscrow`** - per-order private escrow. Four-stage state machine:
  - **OPEN** (`open_order`): creator deposits a USDC bounty bound to a specific
    `(asin, address_commitment)`.
  - **SETTLEMENT_IN_PROGRESS** (`enter_settlement_in_progress`): buyer submits
    a Primus zkTLS attestation showing `>Arriving `; records SIP timestamp,
    starts the 10-day clawback timer.
  - **SETTLED** (`settle_order`): buyer submits a `>Delivered ` attestation
    and is paid out. Reachable from OPEN (shortcut) or SIP.
  - **VOID** (`void_order(after_sip)`): only `config.owner` can call.
    `after_sip=false` claws back immediately if SIP never fired;
    `after_sip=true` claws back >=10 days after SIP.
  Stage gating uses per-stage nullifiers (`Poseidon2(serialize(config) || [stage])`)
  with the kernel's `assert_nullifier_exists` for prior-stage existence and an
  emit-as-mutex pattern for terminal-state exclusivity.
- **`AttestorKeyOracle`** - admin-curated registry of allowed attestor pubkey hashes.
  Read privately from the escrow's verify-bearing entrypoints; reading an
  unregistered key reverts.

Pinned to Aztec **v4.2.0-aztecnr-rc.2** (matching aztec-standards tag).

## Layout

```
packages/contracts/
├── nr/
│   ├── Nargo.toml                # workspace
│   ├── escrow/                   # AmazonEscrow
│   └── attestor_key_oracle/      # AttestorKeyOracle
├── deps/aztec-standards/         # git submodule, tag v4.2.0-aztecnr-rc.2
├── scripts/add_artifacts.ts      # post-codegen: copy JSON, fix imports
├── src/
│   ├── artifacts/{escrow,oracle,token}/   # generated, gitignored
│   ├── contract.ts               # deploy/open/settle/SIP/void TS helpers
│   └── constants.ts              # TOKEN_METADATA, EscrowConfig, EscrowStage
└── test/escrow.test.ts           # vitest happy-path against localnet
```

## Build

```sh
git submodule update --init --recursive
pnpm install
pnpm --filter @amazon-zktls/contracts build
```

The build chains: `aztec compile` (workspace + token) -> `aztec codegen` -> `tsx scripts/add_artifacts.ts` (post-process imports). All `aztec` calls run with `PATH=$HOME/.aztec/current/bin:$PATH` so they pick up aztec's bundled nargo (beta.18). The repo's system nargo is beta.20 and aztec-nr v4.2.0 doesn't compile under it.

## Test

The test runs the **real** verifier path - secp256k1 sigverify + four sha256s + URL prefix
check inside one private function, then a private->private USDC transfer. Expect minutes
per tx.

```sh
# Terminal 1
aztec start --local-network

# Terminal 2 (wait for :8080 to respond)
pnpm --filter @amazon-zktls/contracts test
```

Test setup:

1. Loads `packages/circuit/test/fixtures/attestation-amazon.json`.
2. Derives the order's `asin` (10 ASCII bytes packed LE), `address_commitment`
   (poseidon2 over packed shipTo lines), and `attestor_pubkey_hash`
   (poseidon2(pack_bytes(public_key_x ‖ public_key_y))) so the order config
   matches what `verify(...)` will produce.
3. Spins up two `EmbeddedWallet`s. Account 1 = minter + order creator,
   account 2 = filler. Each wallet has its own PXE - the OTC pubkey-pattern
   requires `registerContract(instance, artifact, secretKey)` on every
   wallet that reads the escrow's notes.
4. Deploys USDC, mints to account 1.
5. Deploys the oracle, registers the fixture's pubkey hash.
6. Deploys a fresh escrow with the order params, registers it on wallet 2.
7. Account 1 calls `open_order(...)` to deposit the bounty.
8. Account 2 calls `settle_order(...)` with `expectedStatus = '>Delivered '`
   (the `OPEN -> SETTLED` shortcut).
9. Asserts account 2 received the bounty.

Other paths (`open_order` -> `void_order(false)` immediate clawback, mutex
failure cases, etc.) are exercised by additional `describe` blocks in
`test/escrow.test.ts`. The `OPEN -> SIP -> ...` paths require an
`>Arriving ` Primus fixture which we don't have in-repo yet, so those
tests are `describe.skip`'d pending a v2 fixture.

## Out of scope

- Switching the oracle from `PublicImmutable` to `DelayedPublicMutable` for
  key revocation.
- Per-field tightened `MAX_*` bounds in `amazon_zktls_lib`.
- Sponsored fee payment / testnet flow.
- Negative-path tests (double-fill rejection, asin mismatch, unregistered
  attestor, etc).
