import { AztecAddress } from "@aztec/aztec.js/addresses";

export const TOKEN_METADATA = {
  usdc: { name: "USD Coin", symbol: "USDC", decimals: 6 },
} as const;

export type EscrowConfig = {
  owner: AztecAddress;
  payment_token: AztecAddress;
  amount: bigint;
  asin: bigint;
  address_commitment: bigint;
  oracle_address: AztecAddress;
  randomness: bigint;
};

// Stage codes mirror packages/contracts/nr/escrow/src/types/stages.nr.
// The contract-side per-stage nullifier is Poseidon2(serialize(config) ‖ [stage]).
export const EscrowStage = {
  OPEN: 0,
  SETTLEMENT_IN_PROGRESS: 1,
  SETTLED: 2,
  VOID: 3,
} as const;
export type EscrowStageCode = typeof EscrowStage[keyof typeof EscrowStage];

// 10 days in seconds, mirrors VOID_TIMER_SECONDS in main.nr.
export const VOID_TIMER_SECONDS = 10 * 24 * 3600;
