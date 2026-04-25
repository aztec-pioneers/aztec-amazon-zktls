// Nullifier = poseidon2(pack_bytes(signature)).
//
// Per-attestation nondeterministic uniqueness comes from secp256k1's `k`:
// each attestation Primus signs has a fresh signature, so even two
// attestations over identical content produce different nullifiers.
// Replay of the same attestation maps to the same nullifier and is
// rejected by the consuming registry.

use nodash::{pack_bytes, poseidon2};

pub fn compute(signature: [u8; 64]) -> Field {
    // 64 bytes -> 64/31 + 1 = 3 Fields.
    let packed = pack_bytes(signature);
    poseidon2(packed)
}
