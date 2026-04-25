// End-to-end: load the attestation fixture (with `_plaintexts` sidecar
// attached by AttestPurchaseBrowser's download), parse it into circuit
// inputs, execute (witness generation catches constraint failures before
// paying bb.js prove time), prove, verify, then decode the public
// outputs (ASIN, grand_total, address_commitment, nullifier) and check
// they match what we expect from the fixture.

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {
  AttestationProver,
  CIRCUIT_DIMS,
  centsToCurrency,
  computeAddressCommitment,
  computeNullifier,
  fieldToAsciiString,
  loadCircuit,
  parseAttestation,
  type PrimusAttestation,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(HERE, "fixtures");
const ATT_PATH = resolve(FIXTURES, "attestation-amazon.json");

const FIXTURE_HAS_PLAINTEXTS = (() => {
  try {
    const parsed = JSON.parse(readFileSync(ATT_PATH, "utf-8")) as PrimusAttestation;
    return parsed._plaintexts !== undefined;
  } catch {
    return false;
  }
})();

if (!FIXTURE_HAS_PLAINTEXTS) {
  console.warn(
    `[verify.test] fixture ${ATT_PATH} has no \`_plaintexts\` sidecar - ` +
      `skipping prove/verify. Regenerate by running the frontend ` +
      `(\`pnpm --filter @amazon-zktls/frontend dev\`), completing an attestation, ` +
      `and clicking "Download attestation.json"; the new file ` +
      `includes the plaintexts the Noir circuit needs as private inputs.`,
  );
}

// Public-input layout of `bin/main.nr`. The returned `PublicOutputs` is
// appended after the parameter-side public inputs.
//
//   [0..32)    public_key_x          32
//   [32..64)   public_key_y          32
//   [64..96)   hash                  32
//   [96..224)  allowed_url.storage   MAX_URL_LEN
//   [224..225) allowed_url.len        1
//   [225..245) recipient             20
//   [245..246) timestamp              1
//   [246..278) hashes.shipment_status 32
//   [278..310) hashes.product_title   32
//   [310..342) hashes.ship_to         32
//   [342..374) hashes.grand_total     32
//   [374..375) asin                    (output)
//   [375..376) grand_total             (output)
//   [376..377) address_commitment     (output)
//   [377..378) nullifier              (output)
const URL_FIELDS = CIRCUIT_DIMS.MAX_URL_LEN + 1; // BoundedVec storage + len
const IDX_ASIN = 32 + 32 + 32 + URL_FIELDS + 20 + 1 + 4 * 32;
const IDX_GRAND_TOTAL = IDX_ASIN + 1;
const IDX_ADDRESS_COMMITMENT = IDX_GRAND_TOTAL + 1;
const IDX_NULLIFIER = IDX_ADDRESS_COMMITMENT + 1;

async function loadInputs() {
  const att = JSON.parse(await readFile(ATT_PATH, "utf-8")) as PrimusAttestation;
  return parseAttestation(att, att._plaintexts!);
}

describe("amazon-zktls verify", () => {
  let prover: AttestationProver;

  beforeAll(async () => {
    const circuit = await loadCircuit();
    prover = new AttestationProver({ circuit });
    await prover.init();
  });

  afterAll(async () => {
    await prover?.destroy();
  });

  it.skipIf(!FIXTURE_HAS_PLAINTEXTS)(
    "parses the attestation into circuit inputs",
    async () => {
      const att = JSON.parse(await readFile(ATT_PATH, "utf-8")) as PrimusAttestation;
      const inputs = parseAttestation(att, att._plaintexts!);
      expect(inputs.public_key_x).toHaveLength(32);
      expect(inputs.public_key_y).toHaveLength(32);
      expect(inputs.signature).toHaveLength(64);
      expect(inputs.hash).toHaveLength(32);
      expect(inputs.recipient).toHaveLength(20);
      expect(inputs.request_url.len).toBe(att.request.url.length);
      expect(inputs.ship_to_hints.offsets).toHaveLength(4);
      expect(inputs.ship_to_hints.lens).toHaveLength(4);
      expect(inputs.grand_total_len).toBeGreaterThan(0);
    },
  );

  it.skipIf(!FIXTURE_HAS_PLAINTEXTS)(
    "executes the circuit (witness generation) without failing a constraint",
    async () => {
      const inputs = await loadInputs();
      await expect(prover.execute(inputs)).resolves.toBeDefined();
    },
  );

  it.skipIf(!FIXTURE_HAS_PLAINTEXTS)(
    "proves and verifies end-to-end + public outputs match the fixture",
    async () => {
      const inputs = await loadInputs();
      const proof = await prover.prove(inputs);
      expect(proof.proof).toBeInstanceOf(Uint8Array);
      expect(proof.publicInputs.length).toBe(IDX_NULLIFIER + 1);
      const ok = await prover.verify(proof);
      expect(ok).toBe(true);

      // ASIN: known fixture has /dp/B0FF98TQNP in the productTitle.
      const asin = fieldToAsciiString(proof.publicInputs[IDX_ASIN], 10);
      expect(asin).toBe("B0FF98TQNP");

      // grand_total: fixture is $0.28 = 28 cents.
      const cents = BigInt(proof.publicInputs[IDX_GRAND_TOTAL]);
      expect(cents).toBe(28n);
      expect(centsToCurrency(cents)).toBe("$0.28");

      // Address commitment: recompute from the known plaintext lines and
      // assert equality with the public output.
      const expectedCommitment = await computeAddressCommitment({
        name: "John Gilcrest",
        street: "385 S CHEROKEE ST APT 339",
        city_state_zip: "DENVER, CO 80223-2126",
        country: "United States",
      });
      const gotCommitment = BigInt(proof.publicInputs[IDX_ADDRESS_COMMITMENT]);
      expect(gotCommitment).toBe(expectedCommitment);

      // Nullifier: recompute from the signature bytes (r||s, 64 B).
      const sigBytes = new Uint8Array(inputs.signature);
      const expectedNullifier = await computeNullifier(sigBytes);
      const gotNullifier = BigInt(proof.publicInputs[IDX_NULLIFIER]);
      expect(gotNullifier).toBe(expectedNullifier);
    },
  );
});
