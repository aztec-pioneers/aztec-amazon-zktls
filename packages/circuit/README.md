# `@amazon-zktls/circuit`

Noir circuit + TypeScript glue for verifying Primus zkTLS attestations of Amazon order pages and exposing the structured fields downstream consumers (escrow, registries) need.

## Layout

```
nr/
  lib/   amazon_zktls_lib  (per-field extractors + `verify` entrypoint)
  bin/   amazon_zktls_bin  (thin wrapper; only `main` lives here)
  delivery_code/ amazon_zktls_delivery_code (Locker pickup-code wrapper)
src/     TypeScript parser, prover, output decoders
test/    vitest end-to-end against an attestation fixture
```

All circuit logic lives in `lib`. The `bin` crate is a one-liner forwarder; downstream Aztec contracts will `use amazon_zktls_lib::*` and call `verify` (or individual extractors) directly inside their private functions.

## Public outputs

The order-summary circuit returns `PublicOutputs`:

| Field                | Type    | What it is                                                       |
|----------------------|---------|------------------------------------------------------------------|
| `asin`               | `Field` | Amazon ASIN, 10 ASCII bytes packed little-endian into one Field. |
| `grand_total`        | `Field` | Order total in USD cents (e.g. `$1,234.56` → `123456`).          |
| `address_commitment` | `Field` | poseidon2 commitment over the four shipping-address lines.       |
| `nullifier`          | `Field` | poseidon2 of the packed attestor signature bytes.                |
| `shipment_date`      | `Field` | Currently `0`; real date extraction is a follow-up.              |

The delivery-code circuit returns `DeliveryCodePublicOutputs`:

| Field         | Type       | What it is                                           |
|---------------|------------|------------------------------------------------------|
| `pickup_code` | `[u8; 6]`  | Locker pickup code bytes.                            |
| `order_id`    | `[u8; 19]` | Amazon order id bytes, e.g. `123-1234567-1234567`.   |

## Public-input layout

The proof `publicInputs` arrays follow Noir ABI order: public parameters first, then public return values. The index helpers in `src/encode_outputs.ts` (`PUBLIC_INPUTS_LENGTH`, `DELIVERY_CODE_PUBLIC_INPUTS_LENGTH`, `decodePublicOutputs`, `decodeDeliveryCodePublicOutputs`) are the source of truth — prefer those over hand-indexing.

Order-summary circuit:

| Range          | Field                  | Field count |
|----------------|------------------------|-------------|
| `[0..32)`      | `public_key_x` bytes   | 32          |
| `[32..64)`     | `public_key_y` bytes   | 32          |
| `[64..96)`     | `hash` bytes           | 32          |
| `[96..224)`    | `allowed_url.storage`  | 128 (`MAX_URL_LEN`) |
| `[224..225)`   | `allowed_url.len`      | 1           |
| `[225..245)`   | `recipient` bytes      | 20          |
| `[245..246)`   | `timestamp`            | 1 (`u64`)   |
| `[246..262)`   | `expected_status.storage` | 16 (`MAX_STATUS_NEEDLE_LEN`) |
| `[262..263)`   | `expected_status.len`     | 1           |
| `[263..295)`   | `hashes.shipment_status`  | 32          |
| `[295..327)`   | `hashes.product_title`    | 32          |
| `[327..359)`   | `hashes.ship_to`          | 32          |
| `[359..391)`   | `hashes.grand_total`      | 32          |
| `[391..392)`   | `asin`                    | 1 (output)  |
| `[392..393)`   | `grand_total`             | 1 (output)  |
| `[393..394)`   | `address_commitment`      | 1 (output)  |
| `[394..395)`   | `nullifier`               | 1 (output)  |
| `[395..396)`   | `shipment_date`           | 1 (output)  |

Total: **396 public inputs**. Each entry is a Field (BN254).

Delivery-code circuit:

| Range          | Field                     | Field count |
|----------------|---------------------------|-------------|
| `[0..32)`      | `public_key_x` bytes      | 32          |
| `[32..64)`     | `public_key_y` bytes      | 32          |
| `[64..96)`     | `hash` bytes              | 32          |
| `[96..352)`    | `allowed_url.storage`     | 256 (`MAX_DELIVERY_URL_LEN`) |
| `[352..353)`   | `allowed_url.len`         | 1           |
| `[353..609)`   | `request_url.storage`     | 256 (`MAX_DELIVERY_URL_LEN`) |
| `[609..610)`   | `request_url.len`         | 1           |
| `[610..630)`   | `recipient` bytes         | 20          |
| `[630..631)`   | `timestamp`               | 1 (`u64`)   |
| `[631..663)`   | `hashes.delivery_status`  | 32          |
| `[663..695)`   | `hashes.pickup_code`      | 32          |
| `[695..727)`   | `hashes.order_id`         | 32          |
| `[727..733)`   | `pickup_code`             | 6 (output)  |
| `[733..752)`   | `order_id`                | 19 (output) |

Total: **752 public inputs**.

## Address commitment

The shipping address comes from the `shipTo` field of the attestation, which is the outer-HTML of Amazon's `<ul>` block:

```html
<ul class="a-unordered-list a-nostyle a-vertical">
  <li><span class="a-list-item">${NAME}</span></li>
  <li><span class="a-list-item">${STREET}<br>${CITY_STATE_ZIP}</span></li>
  <li><span class="a-list-item">${COUNTRY}</span></li>
</ul>
```

The TS parser splits this into **four logical lines** — `name`, `street`, `city_state_zip`, `country` — and hints `(offset, length)` for each into `ship_to.storage()`. The circuit:

1. **Anchors each line.** For lines wrapped in `<li>`: assert the `\<li>\<span class="a-list-item">\n + 16 spaces` open anchor and the `\n + 12 spaces + \</span>\</li>` close anchor at the hinted boundaries. For the `street`/`city_state_zip` split: assert the literal `<br>` between them. This binds each line's bytes to a fixed structural slot in the plaintext — a malicious witness can't lift a name out of the country slot or splice arbitrary bytes.
2. **Reads each line's bytes** into a fixed-width `[u8; MAX_LINE]`, zero-padded past the actual line length. Caps:
   - `MAX_NAME_LEN = 64`
   - `MAX_STREET_LEN = 96`
   - `MAX_CITY_STATE_ZIP_LEN = 96`
   - `MAX_COUNTRY_LEN = 32`
3. **Packs each line** with `nodash::pack_bytes`. This walks the byte array in 31-byte chunks (the BN254 safe ceiling), little-endian within each chunk (`bytes[0]` is the lowest), and emits one Field per chunk. Lengths after packing:
   - `name`           → 3 Fields (64 / 31 + 1)
   - `street`         → 4 Fields (96 / 31 + 1)
   - `city_state_zip` → 4 Fields
   - `country`        → 2 Fields
   - **13 Fields total**
4. **Concatenates** the four packed arrays in line order (`name ‖ street ‖ city_state_zip ‖ country`) into a `[Field; 13]`.
5. **Hashes** with `nodash::poseidon2` — the result is the public `address_commitment`.

Recomputation off-chain (escrow, registry) follows the same recipe: pad each line to its `MAX_*` cap, run the same `pack_bytes`, concatenate in the same order, run poseidon2. As long as both sides agree on the per-line caps and the line-ordering, the commitment is deterministic and matchable without revealing the address bytes.

**Caveats**

- The packing is sensitive to trailing zeros: `"John"` and `"John\0"` pack the same in a 64-byte cap, but bumping `MAX_NAME_LEN` from 64 to 96 changes the commitment for the same name. The caps are part of the protocol; raise them only with version bumps.
- Address content is the trimmed `<li>` body, not Amazon's surrounding indentation. The parser strips Amazon's HTML indent before computing offsets/lengths. The anchor checks above bind *the trimming*, not just the content.
- `<br>` only appears once and only inside the second `<li>` (in the current Amazon template). If a future template change moves it, the hint logic and anchor checks both need to be updated together.

## Nullifier

Per-attestation uniqueness comes from secp256k1's nondeterministic `k`: every attestation Primus signs has a fresh `(r, s)` pair, so reusing the same attestation against a registry produces the same nullifier and is rejected. Two separate attestations over identical content still yield different nullifiers, so a user who re-attests the same order gets a fresh nullifier each time.

`nullifier = poseidon2(pack_bytes::<64>(signature))` — 64 bytes → 3 Fields → poseidon2.

## Soundness gap (TODO v2)

The verifier (escrow, registry) is currently trusted to set the public inputs `public_key_x/y`, `hash`, `recipient`, `timestamp`, and `hashes` to the values from the attestation JSON. Nothing inside the circuit ties them to each other. We are tracking the canonical Primus discussion in [primus-labs/zktls-verification-noir#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) and are not fixing this locally yet.
