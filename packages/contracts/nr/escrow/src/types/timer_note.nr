use aztec::{
    macros::notes::note,
    oracle::random::random,
    protocol::traits::{Deserialize, Packable, Serialize},
};

// Captures the moment SETTLEMENT_IN_PROGRESS was entered. Read by
// `void_order(after_sip=true)` to enforce the 10-day clawback
// window. Late-initialized: the SinglePrivateImmutable slot is left
// empty until SIP fires.
#[derive(Eq, Serialize, Deserialize, Packable)]
#[note]
pub struct TimerNote {
    pub sip_timestamp: u64,
    pub randomness: Field,
}

impl TimerNote {
    pub fn new(sip_timestamp: u64) -> Self {
        Self {
            sip_timestamp,
            // Safety: random() is an oracle call for note randomness
            randomness: unsafe { random() },
        }
    }
}
