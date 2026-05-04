import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { createAztecNodeClient, type AztecNode } from "@aztec/aztec.js/node";
import { Fr } from "@aztec/aztec.js/fields";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AztecAddress } from "@aztec/aztec.js/addresses";

import {
  CIRCUIT_DIMS,
  computeAddressCommitment,
  expectedStatusBytes,
  packBytesNodash,
  parseAttestation,
  poseidon2Hash,
  type CircuitInputs,
  type PrimusAttestation,
} from "@amazon-zktls/circuit";

import {
  TOKEN_METADATA,
  addOracleKey,
  balanceOfPrivate,
  deployEscrowContract,
  deployOracleContract,
  deployTokenContract,
  enterSettlementInProgress,
  getEscrowContract,
  getOracleContract,
  getTokenContract,
  openOrder,
  settleOrder,
  voidOrder,
  wad,
  type VerifyOrderArgs,
} from "../src/index.js";

const L2_NODE_URL = process.env.L2_NODE_URL ?? "http://localhost:8080";

// Bounty in USDC (6 decimals).
const ORDER_AMOUNT = wad(100n, 6n); // 100 USDC

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  HERE,
  "../../circuit/test/fixtures/attestation-amazon.json",
);

// Recompute the (asin, address_commitment, attestor_pubkey_hash) Field
// values that `verify(...)` will produce on this fixture, so the order's
// stored config matches what the proof asserts on settle.
async function deriveOrderFields(att: PrimusAttestation) {
  const plaintexts = att._plaintexts;
  if (!plaintexts) {
    throw new Error(
      "fixture missing _plaintexts sidecar - regenerate via the frontend",
    );
  }

  const productTitle = plaintexts.productTitle;
  const dpIdx = productTitle.indexOf("/dp/");
  if (dpIdx === -1) throw new Error("/dp/ not found in productTitle");
  const asinStr = productTitle.slice(dpIdx + 4, dpIdx + 14);
  if (asinStr.length !== 10) throw new Error("ASIN window too short");
  const asinBytes = new TextEncoder().encode(asinStr);
  const asin = packBytesNodash(asinBytes, 10)[0];

  const shipTo = plaintexts.shipTo;
  const LI_OPEN = 'class="a-list-item">\n                ';
  const LI_CLOSE = "\n            </span></li>";
  const BR = "<br>";

  const opens: number[] = [];
  for (let i = 0; ; ) {
    const f = shipTo.indexOf(LI_OPEN, i);
    if (f === -1) break;
    opens.push(f + LI_OPEN.length);
    i = f + 1;
  }
  const closes: number[] = [];
  for (let i = 0; ; ) {
    const f = shipTo.indexOf(LI_CLOSE, i);
    if (f === -1) break;
    closes.push(f);
    i = f + 1;
  }
  if (opens.length !== 3 || closes.length !== 3) {
    throw new Error(
      `shipTo template mismatch: ${opens.length} opens, ${closes.length} closes`,
    );
  }
  let br = -1;
  for (let i = opens[1]; i < closes[1]; ) {
    const f = shipTo.indexOf(BR, i);
    if (f === -1 || f >= closes[1]) break;
    br = f;
    i = f + 1;
  }
  if (br === -1) throw new Error("<br> not found inside second <li>");

  const name = shipTo.slice(opens[0], closes[0]);
  const street = shipTo.slice(opens[1], br);
  const city_state_zip = shipTo.slice(br + BR.length, closes[1]);
  const country = shipTo.slice(opens[2], closes[2]);

  const addressCommitment = await computeAddressCommitment({
    name,
    street,
    city_state_zip,
    country,
  });

  const inputs = parseAttestation(att, plaintexts);
  const pubkeyBytes = new Uint8Array(64);
  pubkeyBytes.set(inputs.public_key_x, 0);
  pubkeyBytes.set(inputs.public_key_y, 32);
  const pubkeyHash = await poseidon2Hash(packBytesNodash(pubkeyBytes, 64));

  return { asin, addressCommitment, pubkeyHash, inputs };
}

// Build VerifyOrderArgs for the contract from parsed CircuitInputs +
// the chosen status needle. Both settle_order and
// enter_settlement_in_progress consume this exact shape.
function buildVerifyArgs(
  inputs: CircuitInputs,
  kind: "delivered" | "arriving",
): VerifyOrderArgs {
  return {
    publicKeyX: inputs.public_key_x,
    publicKeyY: inputs.public_key_y,
    hash: inputs.hash,
    signature: inputs.signature,
    allowedUrl: inputs.allowed_url,
    requestUrl: inputs.request_url,
    recipient: inputs.recipient,
    timestamp: BigInt(inputs.timestamp),
    expectedStatus: expectedStatusBytes(kind),
    hashes: inputs.hashes,
    contents: inputs.contents,
    shipToHints: inputs.ship_to_hints,
    grandTotalLen: inputs.grand_total_len,
  };
}

interface Setup {
  node: AztecNode;
  wallet1: EmbeddedWallet;
  wallet2: EmbeddedWallet;
  account1Address: AztecAddress;
  account2Address: AztecAddress;
  usdcAddress: AztecAddress;
  oracleAddress: AztecAddress;
  escrow: Awaited<ReturnType<typeof deployEscrowContract>>;
  circuitInputs: CircuitInputs;
}

// Spin up two wallets, fresh USDC + oracle + escrow contracts, mint
// the bounty into wallet1, and register the escrow on both wallets.
// Each describe block calls this once in beforeAll so its tests share
// the same escrow instance (which is terminal-once anyway).
async function setupFixture(label: string): Promise<Setup> {
  const fixture = JSON.parse(
    readFileSync(FIXTURE_PATH, "utf-8"),
  ) as PrimusAttestation;
  const derived = await deriveOrderFields(fixture);

  const node = createAztecNodeClient(L2_NODE_URL);
  const wallet1 = await EmbeddedWallet.create(node, { ephemeral: true });
  const wallet2 = await EmbeddedWallet.create(node, { ephemeral: true });

  const initial = await getInitialTestAccountsData();
  if (!initial[0] || !initial[1]) {
    throw new Error("need at least 2 prefunded accounts on the localnet");
  }
  const a1 = await wallet1.createSchnorrAccount(
    initial[0].secret,
    initial[0].salt,
    initial[0].signingKey,
  );
  const a2 = await wallet2.createSchnorrAccount(
    initial[1].secret,
    initial[1].salt,
    initial[1].signingKey,
  );
  const account1Address = a1.address;
  const account2Address = a2.address;
  await wallet1.registerSender(account2Address, `${label}-filler`);
  await wallet2.registerSender(account1Address, `${label}-creator`);

  const usdc = await deployTokenContract(
    wallet1,
    account1Address,
    TOKEN_METADATA.usdc,
  );
  const usdcAddress = usdc.contract.address;
  await usdc.contract
    .withWallet(wallet1)
    .methods.mint_to_private(account1Address, ORDER_AMOUNT)
    .send({ from: account1Address });
  await getTokenContract(wallet2, node, usdcAddress);

  const oracle = await deployOracleContract(
    wallet1,
    account1Address,
    account1Address,
  );
  const oracleAddress = oracle.contract.address;
  await addOracleKey(wallet1, account1Address, oracle.contract, derived.pubkeyHash);
  await getOracleContract(wallet2, node, oracleAddress);

  const escrow = await deployEscrowContract(
    wallet1,
    account1Address,
    usdcAddress,
    ORDER_AMOUNT,
    derived.asin,
    derived.addressCommitment,
    oracleAddress,
  );
  await getEscrowContract(
    wallet2,
    escrow.contract.address,
    escrow.instance,
    escrow.secretKey,
  );
  await wallet1.registerSender(escrow.contract.address, `${label}-escrow`);
  await wallet2.registerSender(escrow.contract.address, `${label}-escrow`);

  return {
    node,
    wallet1,
    wallet2,
    account1Address,
    account2Address,
    usdcAddress,
    oracleAddress,
    escrow,
    circuitInputs: derived.inputs,
  };
}

describe("AmazonEscrow: OPEN -> SETTLED shortcut (delivered proof, no SIP)", () => {
  let s: Setup;

  beforeAll(async () => {
    s = await setupFixture("settle-shortcut");
  }, 10 * 60 * 1000);

  it("creator opens, filler proves delivered and claims the bounty", async () => {
    const usdcOnW1 = await getTokenContract(s.wallet1, s.node, s.usdcAddress);
    const usdcOnW2 = await getTokenContract(s.wallet2, s.node, s.usdcAddress);

    expect(await balanceOfPrivate(s.wallet1, s.account1Address, usdcOnW1)).toBe(
      ORDER_AMOUNT,
    );
    expect(await balanceOfPrivate(s.wallet2, s.account2Address, usdcOnW2)).toBe(0n);

    await openOrder(
      s.wallet1,
      s.account1Address,
      s.escrow.contract,
      usdcOnW1,
      ORDER_AMOUNT,
    );
    expect(await balanceOfPrivate(s.wallet1, s.account1Address, usdcOnW1)).toBe(0n);

    await settleOrder(
      s.wallet2,
      s.account2Address,
      s.escrow.contract,
      buildVerifyArgs(s.circuitInputs, "delivered"),
    );

    expect(await balanceOfPrivate(s.wallet2, s.account2Address, usdcOnW2)).toBe(
      ORDER_AMOUNT,
    );
  });

  it("a second settle on the same escrow fails (push nullifier mutex)", async () => {
    await expect(
      settleOrder(
        s.wallet2,
        s.account2Address,
        s.escrow.contract,
        buildVerifyArgs(s.circuitInputs, "delivered"),
      ),
    ).rejects.toThrow();
  });

  it("voiding a settled escrow fails (push nullifier mutex)", async () => {
    await expect(
      voidOrder(s.wallet1, s.account1Address, s.escrow.contract, false),
    ).rejects.toThrow();
  });
});

describe("AmazonEscrow: OPEN -> VOID immediate (no SIP)", () => {
  let s: Setup;

  beforeAll(async () => {
    s = await setupFixture("void-immediate");
  }, 10 * 60 * 1000);

  it("non-owner cannot void", async () => {
    const usdcOnW1 = await getTokenContract(s.wallet1, s.node, s.usdcAddress);
    await openOrder(
      s.wallet1,
      s.account1Address,
      s.escrow.contract,
      usdcOnW1,
      ORDER_AMOUNT,
    );
    await expect(
      voidOrder(s.wallet2, s.account2Address, s.escrow.contract, false),
    ).rejects.toThrow();
  });

  it("owner voids (immediate path) and recovers the bounty", async () => {
    const usdcOnW1 = await getTokenContract(s.wallet1, s.node, s.usdcAddress);
    expect(await balanceOfPrivate(s.wallet1, s.account1Address, usdcOnW1)).toBe(0n);

    await voidOrder(s.wallet1, s.account1Address, s.escrow.contract, false);

    expect(await balanceOfPrivate(s.wallet1, s.account1Address, usdcOnW1)).toBe(
      ORDER_AMOUNT,
    );
  });

  it("settling a voided escrow fails (push nullifier mutex)", async () => {
    await expect(
      settleOrder(
        s.wallet2,
        s.account2Address,
        s.escrow.contract,
        buildVerifyArgs(s.circuitInputs, "delivered"),
      ),
    ).rejects.toThrow();
  });
});

describe("AmazonEscrow: failure - settle without open", () => {
  let s: Setup;

  beforeAll(async () => {
    s = await setupFixture("no-open-settle");
  }, 10 * 60 * 1000);

  it("settling a never-opened escrow fails (OPEN nullifier check)", async () => {
    await expect(
      settleOrder(
        s.wallet2,
        s.account2Address,
        s.escrow.contract,
        buildVerifyArgs(s.circuitInputs, "delivered"),
      ),
    ).rejects.toThrow();
  });
});

// SIP-requiring paths need an "Arriving …" attestation signed by the
// Primus attestor. We don't have an arriving fixture in-repo today
// (only the delivered one). When one lands, drop `.skip` and the
// `enterSettlementInProgress` calls will exercise the full state
// machine including the timer-void path. The contract-side state
// machine logic is otherwise identical for the delivered-proof
// branches that we DO test above (same nullifier-mutex pattern).
describe.skip("AmazonEscrow: SIP-required paths (need arriving fixture)", () => {
  let s: Setup;
  beforeAll(async () => {
    s = await setupFixture("sip-paths");
  }, 10 * 60 * 1000);

  it("OPEN -> SIP -> SETTLED happy path", async () => {
    const usdcOnW1 = await getTokenContract(s.wallet1, s.node, s.usdcAddress);
    await openOrder(
      s.wallet1,
      s.account1Address,
      s.escrow.contract,
      usdcOnW1,
      ORDER_AMOUNT,
    );
    await enterSettlementInProgress(
      s.wallet2,
      s.account2Address,
      s.escrow.contract,
      buildVerifyArgs(s.circuitInputs, "arriving"),
    );
    await settleOrder(
      s.wallet2,
      s.account2Address,
      s.escrow.contract,
      buildVerifyArgs(s.circuitInputs, "delivered"),
    );
  });

  it("OPEN -> SIP -> VOID(immediate) fails (SIP nullifier mutex)", async () => {
    // After SIP fires, voiding via the immediate path must fail
    // because void(after_sip=false) tries to push the SIP-stage
    // nullifier as its lockout, which collides with SIP's own emission.
    await expect(
      voidOrder(s.wallet1, s.account1Address, s.escrow.contract, false),
    ).rejects.toThrow();
  });

  it("OPEN -> SIP -> VOID(timer) fails before 10 days elapsed", async () => {
    // Needs Aztec test-env time advancement; localnet doesn't expose
    // a cheat by default. v2: use the TestEnvironment time-skip API.
  });
});
