use aztec::{
    macros::notes::note,
    oracle::random::random,
    protocol::{
        address::AztecAddress,
        traits::{Deserialize, Packable, Serialize},
    },
};
use poseidon::poseidon2::Poseidon2;

#[derive(Eq, Serialize, Deserialize, Packable)]
#[note]
pub struct ConfigNote {
    pub owner: AztecAddress,
    pub payment_token: AztecAddress,
    pub amount: u128,
    pub asin: Field,
    pub address_commitment: Field,
    pub oracle_address: AztecAddress,
    pub randomness: Field,
}

impl ConfigNote {
    pub fn new(
        owner: AztecAddress,
        payment_token: AztecAddress,
        amount: u128,
        asin: Field,
        address_commitment: Field,
        oracle_address: AztecAddress,
    ) -> Self {
        Self {
            owner,
            payment_token,
            amount,
            asin,
            address_commitment,
            oracle_address,
            // Safety: random() is an oracle call for note randomness
            randomness: unsafe { random() },
        }
    }

    // Returns the per-stage nullifier for this config. Each stage
    // (OPEN, SETTLEMENT_IN_PROGRESS, SETTLED, VOID) gets its own unique
    // nullifier, derived by binding the stage code to the serialized
    // config. The contract pushes these to mark stage transitions and
    // checks `assert_nullifier_exists` to gate prior stages.
    pub fn get_nullifier(self, stage: u8) -> Field {
        let serialized = self.serialize();
        let preimage = serialized.concat([stage as Field]);
        Poseidon2::hash(preimage, 8)
    }
}
