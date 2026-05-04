// Stage codes for the multi-stage escrow state machine. The
// `ConfigNote` nullifier is keyed on (config_serialization, stage),
// so each stage gets its own unique nullifier. Pushing a stage's
// nullifier is the "I have entered this stage" event; reading it
// (via `assert_nullifier_exists`) is the "this stage already
// fired" gate. Terminal states (SETTLED, VOID) push BOTH terminal
// nullifiers as a mutex so the other terminal can never fire.

pub mod ESCROW_STAGE {
    pub global OPEN: u8 = 0;
    pub global SETTLEMENT_IN_PROGRESS: u8 = 1;
    pub global SETTLED: u8 = 2;
    pub global VOID: u8 = 3;
}
