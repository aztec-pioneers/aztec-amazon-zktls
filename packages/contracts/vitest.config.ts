import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The settle_order / enter_settlement_in_progress txs run the full
    // attestation verifier inside one private function (secp256k1 sigverify
    // + 4 sha256s + URL prefix check), then a private->private transfer.
    // Be generous.
    testTimeout: 10 * 60 * 1000,
    hookTimeout: 10 * 60 * 1000,
  },
});
