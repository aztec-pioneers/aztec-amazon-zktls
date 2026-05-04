use aztec::macros::aztec;

pub mod types;

#[aztec]
pub contract AmazonEscrow {
    use aztec::{
        macros::{
            functions::{external, initializer},
            storage::storage,
        },
        messages::message_delivery::MessageDelivery,
        nullifier::utils::compute_nullifier_existence_request,
        protocol::address::AztecAddress,
        state_vars::SinglePrivateImmutable,
    };
    use token_contract::Token;
    use attestor_key_oracle::AttestorKeyOracle;
    use amazon_zktls_lib::{MAX_STATUS_NEEDLE_LEN, MAX_URL_LEN, PublicOutputs, verify};
    use amazon_zktls_lib::internal::{pack_bytes, poseidon2};
    use crate::types::config_note::ConfigNote;
    use crate::types::circuit_args::{ContractContents, ContractHashes, ContractShipToHints};
    use crate::types::stages::ESCROW_STAGE;
    use crate::types::timer_note::TimerNote;

    // 10-day clawback window for void_order(after_sip=true).
    global VOID_TIMER_SECONDS: u64 = 10 * 24 * 3600;

    #[storage]
    struct Storage<Context> {
        config: SinglePrivateImmutable<ConfigNote, Context>,
        // Late-initialized inside `enter_settlement_in_progress` to
        // record when the SIP timer started. `void_order(after_sip=true)`
        // reads this; reading fails if SIP never fired, which is the
        // built-in gate against voiding-with-timer before SIP.
        timer: SinglePrivateImmutable<TimerNote, Context>,
    }

    #[external("private")]
    #[initializer]
    fn constructor(
        payment_token: AztecAddress,
        amount: u128,
        asin: Field,
        address_commitment: Field,
        oracle_address: AztecAddress,
    ) {
        // The deployer is the order creator. void_order checks
        // msg_sender == config.owner so the clawback path is locked
        // to whoever opened the escrow.
        let config = ConfigNote::new(
            self.msg_sender(),
            payment_token,
            amount,
            asin,
            address_commitment,
            oracle_address,
        );
        self.storage.config.initialize(config).deliver(MessageDelivery.ONCHAIN_CONSTRAINED);
    }

    /**
     * Stage transition: OPEN.
     *
     * Order creator deposits the bounty amount in the payment token
     * and marks the order OPEN. Pushing the OPEN-stage nullifier
     * gates every later transition.
     */
    #[external("private")]
    fn open_order(_nonce: Field) {
        let config = self.storage.config.get_note();
        let caller = self.msg_sender();

        self.call(Token::at(config.payment_token).transfer_private_to_private(
            caller,
            self.address,
            config.amount,
            _nonce,
        ));

        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::OPEN));
    }

    /**
     * Stage transition: OPEN -> SETTLEMENT_IN_PROGRESS.
     *
     * Buyer submits a Primus zkTLS attestation showing the order is
     * in flight ("Arriving ..."). Records the SIP entry timestamp in a
     * TimerNote so void_order(after_sip=true) can enforce the 10-day
     * clawback window. No funds move at this stage.
     */
    #[external("private")]
    fn enter_settlement_in_progress(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        allowed_url: BoundedVec<u8, MAX_URL_LEN>,
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        recipient: [u8; 20],
        timestamp: u64,
        expected_status: BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>,
        hashes: ContractHashes,
        contents: ContractContents,
        ship_to_hints: ContractShipToHints,
        grand_total_len: u32,
    ) {
        let config = self.storage.config.get_note();

        // Gate on prior stage: order must be OPEN.
        self.context.assert_nullifier_exists(compute_nullifier_existence_request(
            config.get_nullifier(ESCROW_STAGE::OPEN),
            self.context.this_address(),
        ));

        // Run the attestation verifier inline with the "arriving" needle.
        // The contract caller passes the literal `>Arriving ` bytes (the
        // TS wrapper builds them via `expectedStatusBytes('arriving')`),
        // so the prover can't sneak in a different needle without also
        // failing the attestor signature check on a different `hash`.
        let outputs: PublicOutputs = verify(
            public_key_x,
            public_key_y,
            hash,
            signature,
            allowed_url,
            request_url,
            recipient,
            timestamp,
            expected_status,
            hashes.to_lib(),
            contents.to_lib(),
            ship_to_hints.to_lib(),
            grand_total_len,
        );

        // Bind the proof to this order.
        assert(outputs.asin == config.asin, "asin mismatch");
        assert(
            outputs.address_commitment == config.address_commitment,
            "address commitment mismatch",
        );

        // Attestor pubkey gate (same recipe as settle).
        let mut pubkey_bytes: [u8; 64] = [0; 64];
        for i in 0..32 {
            pubkey_bytes[i] = public_key_x[i];
        }
        for i in 0..32 {
            pubkey_bytes[32 + i] = public_key_y[i];
        }
        let pubkey_hash = poseidon2(pack_bytes(pubkey_bytes));
        let is_valid = self.call(
            AttestorKeyOracle::at(config.oracle_address).is_allowed(pubkey_hash),
        );
        assert(is_valid, "attestor not allowed");

        // Cross-order proof replay protection.
        self.context.push_nullifier(outputs.nullifier);

        // Record SIP entry timestamp. Anchor block timestamp can drift
        // up to ~24h vs wall clock; acceptable for a 10-day window.
        let sip_timestamp = self.context.get_anchor_block_header().timestamp();
        let timer = TimerNote::new(sip_timestamp);
        self.storage.timer.initialize(timer).deliver(MessageDelivery.ONCHAIN_CONSTRAINED);

        // Mutex on this stage. Also locks out void_order(after_sip=false).
        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::SETTLEMENT_IN_PROGRESS));
    }

    /**
     * Stage transition: OPEN -> SETTLED, or SIP -> SETTLED.
     *
     * Buyer submits a Primus zkTLS attestation showing the order was
     * delivered. Pays out the bounty to the caller and locks out any
     * future void.
     */
    #[external("private")]
    fn settle_order(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        allowed_url: BoundedVec<u8, MAX_URL_LEN>,
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        recipient: [u8; 20],
        timestamp: u64,
        expected_status: BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>,
        hashes: ContractHashes,
        contents: ContractContents,
        ship_to_hints: ContractShipToHints,
        grand_total_len: u32,
    ) {
        let config = self.storage.config.get_note();
        let caller = self.msg_sender();

        // Gate on prior stage: order must be OPEN. (SIP is allowed but
        // not required - the OPEN -> SETTLED shortcut is valid.)
        self.context.assert_nullifier_exists(compute_nullifier_existence_request(
            config.get_nullifier(ESCROW_STAGE::OPEN),
            self.context.this_address(),
        ));

        // Run the attestation verifier inline with the "delivered" needle.
        let outputs: PublicOutputs = verify(
            public_key_x,
            public_key_y,
            hash,
            signature,
            allowed_url,
            request_url,
            recipient,
            timestamp,
            expected_status,
            hashes.to_lib(),
            contents.to_lib(),
            ship_to_hints.to_lib(),
            grand_total_len,
        );

        assert(outputs.asin == config.asin, "asin mismatch");
        assert(
            outputs.address_commitment == config.address_commitment,
            "address commitment mismatch",
        );

        // Attestor pubkey gate.
        let mut pubkey_bytes: [u8; 64] = [0; 64];
        for i in 0..32 {
            pubkey_bytes[i] = public_key_x[i];
        }
        for i in 0..32 {
            pubkey_bytes[32 + i] = public_key_y[i];
        }
        let pubkey_hash = poseidon2(pack_bytes(pubkey_bytes));
        let is_valid = self.call(
            AttestorKeyOracle::at(config.oracle_address).is_allowed(pubkey_hash),
        );
        assert(is_valid, "attestor not allowed");

        // Cross-order proof replay protection.
        self.context.push_nullifier(outputs.nullifier);

        // Pay the filler.
        self.call(Token::at(config.payment_token).transfer_private_to_private(
            self.address,
            caller,
            config.amount,
            0,
        ));

        // Mutex against the other terminal (VOID): pushing both
        // SETTLED and VOID stage nullifiers means a future void_order
        // (in either path) will fail by duplicate-nullifier.
        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::SETTLED));
        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::VOID));
    }

    /**
     * Stage transition: OPEN -> VOID, or SIP -> VOID (after timer).
     *
     * Order creator claws back the bounty.
     *   - `after_sip = false`: immediate path. Only valid if SIP has
     *     NOT fired (we push the SIP nullifier as a mutex - it fails
     *     by duplicate if SIP already happened).
     *   - `after_sip = true`: timer path. Reads the TimerNote (which
     *     fails if SIP never initialized it) and asserts at least
     *     VOID_TIMER_SECONDS have elapsed.
     */
    #[external("private")]
    fn void_order(after_sip: bool) {
        let config = self.storage.config.get_note();
        let caller = self.msg_sender();

        assert(caller == config.owner, "only owner can void");

        // Gate on prior stage: order must be OPEN.
        self.context.assert_nullifier_exists(compute_nullifier_existence_request(
            config.get_nullifier(ESCROW_STAGE::OPEN),
            self.context.this_address(),
        ));

        if after_sip {
            // Reading the timer note fails if SIP never initialized it,
            // which is exactly the gate we want.
            let timer = self.storage.timer.get_note();
            let now = self.context.get_anchor_block_header().timestamp();
            assert(now >= timer.sip_timestamp, "anchor before SIP");
            let elapsed = now - timer.sip_timestamp;
            assert(elapsed >= VOID_TIMER_SECONDS, "void timer not elapsed");
        } else {
            // Immediate path: locks out future SIP. Fails by duplicate
            // if SIP already happened, which is exactly the gate we want.
            self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::SETTLEMENT_IN_PROGRESS));
        }

        // Pay the owner back.
        self.call(Token::at(config.payment_token).transfer_private_to_private(
            self.address,
            config.owner,
            config.amount,
            0,
        ));

        // Mutex against the other terminal (SETTLED): pushing both
        // VOID and SETTLED stage nullifiers means a future settle_order
        // will fail by duplicate-nullifier.
        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::VOID));
        self.context.push_nullifier(config.get_nullifier(ESCROW_STAGE::SETTLED));
    }

    #[external("utility")]
    unconstrained fn get_config() -> ConfigNote {
        self.storage.config.view_note()
    }
}
