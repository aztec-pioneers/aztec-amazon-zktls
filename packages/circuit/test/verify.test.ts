// End-to-end: load the attestation fixture (with `_plaintexts` sidecar
// attached by AttestPurchaseBrowser's download), parse it into circuit
// inputs, execute (witness generation catches constraint failures before
// paying bb.js prove time), prove, verify, then decode the public
// outputs (ASIN, grand_total, address_commitment, nullifier) and check
// they match what we expect from the fixture.

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { Barretenberg, BackendType } from "@aztec/bb.js";
import {
  AttestationProver,
  CIRCUIT_DIMS,
  PUBLIC_INPUTS_LENGTH,
  DELIVERY_CODE_PUBLIC_INPUTS_LENGTH,
  EXPECTED_STATUS,
  centsToCurrency,
  computeAddressCommitment,
  computeNullifier,
  decodePublicOutputs,
  decodeDeliveryCodePublicOutputs,
  expectedStatusBytes,
  parseAttestation,
  parseDeliveryCodeAttestation,
  type AmazonDeliveryCodeAttestation,
  type AmazonOrderSummaryAttestation,
} from "../src/index.js";
import { loadCircuit, loadDeliveryCodeCircuit } from "../src/load.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(HERE, "fixtures");
const ORDER_SUMMARY_ATT_PATH = resolve(
  FIXTURES,
  "attestation-amazon-order-summary.json",
);
const DELIVERY_CODE_ATT_PATH = resolve(
  FIXTURES,
  "attestation-amazon-delivery-code.json",
);

function sha256Hex(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex");
}

const FIXTURE_HAS_PLAINTEXTS = (() => {
  try {
    const parsed = JSON.parse(
      readFileSync(ORDER_SUMMARY_ATT_PATH, "utf-8"),
    ) as AmazonOrderSummaryAttestation;
    return parsed._plaintexts !== undefined;
  } catch {
    return false;
  }
})();
const DELIVERY_FIXTURE_HAS_PLAINTEXTS = (() => {
  try {
    const parsed = JSON.parse(
      readFileSync(DELIVERY_CODE_ATT_PATH, "utf-8"),
    ) as AmazonDeliveryCodeAttestation;
    const hashes = JSON.parse(parsed.data) as Record<string, string>;
    return (
      parsed._plaintexts?.deliveryStatus !== undefined &&
      parsed._plaintexts?.pickupCode !== undefined &&
      parsed._plaintexts?.orderId !== undefined &&
      typeof hashes.deliveryStatus === "string" &&
      typeof hashes.pickupCode === "string" &&
      typeof hashes.orderId === "string"
    );
  } catch {
    return false;
  }
})();

async function loadInputs() {
  const att = JSON.parse(
    await readFile(ORDER_SUMMARY_ATT_PATH, "utf-8"),
  ) as AmazonOrderSummaryAttestation;
  return parseAttestation(att, att._plaintexts);
}

async function loadDeliveryCodeInputs() {
  const att = JSON.parse(
    await readFile(DELIVERY_CODE_ATT_PATH, "utf-8"),
  ) as AmazonDeliveryCodeAttestation;
  return parseDeliveryCodeAttestation(att, att._plaintexts);
}

describe("amazon-zktls verify", () => {
  let bb: Barretenberg;
  let prover: AttestationProver;
  let deliveryProver: AttestationProver;

  beforeAll(async () => {
    const circuit = await loadCircuit();
    const deliveryCircuit = await loadDeliveryCodeCircuit();
    // Force the WASM backend in vitest; the default (NativeUnixSocket)
    // races with vitest's worker pool.
    bb = await Barretenberg.new({ backend: BackendType.Wasm });
    prover = new AttestationProver({ circuit, bb });
    deliveryProver = new AttestationProver({ circuit: deliveryCircuit, bb });
    await prover.init();
    await deliveryProver.init();
  });

  afterAll(async () => {
    await prover?.destroy();
    await deliveryProver?.destroy();
    await bb?.destroy();
  });

  it.skipIf(!FIXTURE_HAS_PLAINTEXTS)(
    "parses the attestation into circuit inputs",
    async () => {
      const att = JSON.parse(
        await readFile(ORDER_SUMMARY_ATT_PATH, "utf-8"),
      ) as AmazonOrderSummaryAttestation;
      const inputs = parseAttestation(att, att._plaintexts);
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
      expect(proof.publicInputs.length).toBe(PUBLIC_INPUTS_LENGTH);
      const ok = await prover.verify(proof);
      expect(ok).toBe(true);

      const outputs = decodePublicOutputs(proof.publicInputs);

      // ASIN: known fixture has /dp/B0FF98TQNP in the productTitle.
      expect(outputs.asin).toBe("B0FF98TQNP");

      // grand_total: fixture is $0.28 = 28 cents.
      expect(outputs.grandTotalCents).toBe(28n);
      expect(centsToCurrency(outputs.grandTotalCents)).toBe("$0.28");

      // Address commitment: recompute from the known plaintext lines and
      // assert equality with the public output.
      const expectedCommitment = await computeAddressCommitment({
        name: "John Gilcrest",
        street: "385 S CHEROKEE ST APT 339",
        city_state_zip: "DENVER, CO 80223-2126",
        country: "United States",
      });
      expect(outputs.addressCommitment).toBe(expectedCommitment);

      // Nullifier: recompute from the signature bytes (r||s, 64 B).
      const sigBytes = new Uint8Array(inputs.signature);
      const expectedNullifier = await computeNullifier(sigBytes);
      expect(outputs.nullifier).toBe(expectedNullifier);

      // shipment_date: hardcoded to 0 in the circuit (real extraction TBD).
      expect(outputs.shipmentDate).toBe(0n);
    },
  );

  // Pure-TS coverage of the new arriving needle. We don't run a fresh
  // prove for arriving (the only fixture we have is a delivered
  // attestation), but we DO verify that `expectedStatusBytes('arriving')`
  // produces the byte sequence the Noir matcher will look for and that
  // it threads through `parseAttestation` cleanly when the substring is
  // actually present in the plaintext. A v2 follow-up should add a real
  // arriving-status fixture and run prove() on it.
  it("expectedStatusBytes('arriving') yields '>Arriving '", () => {
    const got = expectedStatusBytes("arriving");
    expect(got.len).toBe(EXPECTED_STATUS.arriving.length);
    const literal = new TextDecoder().decode(
      new Uint8Array(got.storage.slice(0, got.len)),
    );
    expect(literal).toBe(">Arriving ");
    expect(got.storage).toHaveLength(CIRCUIT_DIMS.MAX_STATUS_NEEDLE_LEN);
  });

  it("expectedStatusBytes('delivered') yields '>Delivered '", () => {
    const got = expectedStatusBytes("delivered");
    expect(got.len).toBe(EXPECTED_STATUS.delivered.length);
    const literal = new TextDecoder().decode(
      new Uint8Array(got.storage.slice(0, got.len)),
    );
    expect(literal).toBe(">Delivered ");
  });

  it.skipIf(!DELIVERY_FIXTURE_HAS_PLAINTEXTS)(
    "keeps the delivery-code attestation fixture ready for the delivery circuit",
    async () => {
      const att = JSON.parse(
        await readFile(DELIVERY_CODE_ATT_PATH, "utf-8"),
      ) as AmazonDeliveryCodeAttestation;
      const hashes = JSON.parse(att.data) as Record<string, string>;

      expect(att.request.url).toContain("/gp/your-account/ship-track");
      expect(Object.keys(att._plaintexts ?? {}).sort()).toEqual([
        "deliveryStatus",
        "orderId",
        "pickupCode",
      ]);
      expect(att._values).toMatchObject({
        deliveryStatus: "Delivered",
        orderId: "111-6245352-8673825",
        pickupCode: "039391",
      });
      expect(sha256Hex(att._plaintexts.deliveryStatus)).toBe(
        hashes.deliveryStatus,
      );
      expect(sha256Hex(att._plaintexts.pickupCode)).toBe(hashes.pickupCode);
      expect(sha256Hex(att._plaintexts.orderId)).toBe(hashes.orderId);
    },
  );

  it.skipIf(!DELIVERY_FIXTURE_HAS_PLAINTEXTS)(
    "parses the delivery-code attestation into circuit inputs",
    async () => {
      const att = JSON.parse(
        await readFile(DELIVERY_CODE_ATT_PATH, "utf-8"),
      ) as AmazonDeliveryCodeAttestation;
      const inputs = parseDeliveryCodeAttestation(att, att._plaintexts);
      expect(inputs.public_key_x).toHaveLength(32);
      expect(inputs.public_key_y).toHaveLength(32);
      expect(inputs.signature).toHaveLength(64);
      expect(inputs.hash).toHaveLength(32);
      expect(inputs.recipient).toHaveLength(20);
      expect(inputs.request_url.len).toBe(att.request.url.length);
      expect(inputs.hashes.delivery_status).toHaveLength(32);
      expect(inputs.hashes.pickup_code).toHaveLength(32);
      expect(inputs.hashes.order_id).toHaveLength(32);
    },
  );

  it.skipIf(!DELIVERY_FIXTURE_HAS_PLAINTEXTS)(
    "executes the delivery-code circuit without failing a constraint",
    async () => {
      const inputs = await loadDeliveryCodeInputs();
      await expect(deliveryProver.execute(inputs)).resolves.toBeDefined();
    },
  );

  it.skipIf(!DELIVERY_FIXTURE_HAS_PLAINTEXTS)(
    "proves and verifies delivery-code end-to-end + public outputs match",
    async () => {
      const att = JSON.parse(
        await readFile(DELIVERY_CODE_ATT_PATH, "utf-8"),
      ) as AmazonDeliveryCodeAttestation;
      const inputs = await loadDeliveryCodeInputs();
      const proof = await deliveryProver.prove(inputs);
      expect(proof.proof).toBeInstanceOf(Uint8Array);
      expect(proof.publicInputs.length).toBe(DELIVERY_CODE_PUBLIC_INPUTS_LENGTH);

      const ok = await deliveryProver.verify(proof);
      expect(ok).toBe(true);

      const outputs = decodeDeliveryCodePublicOutputs(proof.publicInputs);
      expect(outputs.allowedUrl).toBe(
        "https://www.amazon.com/gp/your-account/ship-track",
      );
      expect(outputs.requestUrl).toBe(att.request.url);
      expect(outputs.pickupCode).toBe("039391");
      expect(outputs.orderId).toBe("111-6245352-8673825");
    },
  );
});
