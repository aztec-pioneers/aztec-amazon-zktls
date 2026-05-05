// amazon_zktls_lib - Primus zkTLS attestation verifier for Amazon orders.
//
// All circuit logic lives in this crate (extractors + the high-level
// `verify` entrypoint) so a downstream Aztec contract can `use` the same
// pieces. `bin/main.nr` is a thin wrapper that just forwards into
// `verify` and returns its `PublicOutputs`.
//
// Steps:
//   1. ECDSA secp256k1 signature over the canonical message hash.
//   2. URL prefix check (request_url starts with allowed_url).
//   3. Per-field sha256: sha256(plaintext_i) == hashes.i, binding the
//      private plaintexts back to what the attestor signed.
//   4. ASIN extraction from productTitle.
//   5. Grand total parsing from grandTotal (USD cents).
//   6. shipTo split into 4 logical lines + poseidon2 commitment.
//   7. shipmentStatus contains the caller-supplied needle
//      (e.g. ">Delivered " for SETTLED, ">Arriving " for SIP).
//   8. Nullifier = poseidon2(pack(signature)).
//   9. Shipment date is exposed as a public output, currently
//      hardcoded to 0 (real extraction is a follow-up).
//
// TODO(soundness): public inputs (recipient, timestamp, hashes, attestor
// pubkey) are not bound to `hash` inside the circuit. Verifier must set
// them correctly. v2 should reconstruct the canonical attestation message
// in-circuit and assert keccak256(canonical) == hash.

use sha256::sha256_var;

pub mod asin;
pub mod delivery_code;
pub mod grand_total;
pub mod internal;
pub mod nullifier;
pub mod ship_to;
pub mod status;
pub mod url;

pub global MAX_URL_LEN: u32 = 128;
pub global MAX_DELIVERY_URL_LEN: u32 = 256;

// Per-field outer-HTML byte ceilings. Picked generously above what the
// Amazon order template currently emits. Shrink when bounded by real
// fixtures; grow with the matching TS parser constants if a longer field
// shows up.
pub global MAX_SHIPMENT_STATUS_LEN: u32 = 256;
pub global MAX_PRODUCT_TITLE_LEN: u32 = 1024;
pub global MAX_SHIP_TO_LEN: u32 = 1024;
// grandTotal is ~89 bytes ($0.28 wrapped in <span>); 128 leaves room for
// longer dollar values up to $999,999.99.
pub global MAX_GRAND_TOTAL_LEN: u32 = 128;
// Delivery-code fields from the ship-track page. The current fixture is
// pickupCode=72 bytes and orderId anchor=146 bytes; keep slack for Amazon
// attribute churn while preserving bounded SHA/search costs.
pub global MAX_DELIVERY_STATUS_LEN: u32 = 128;
pub global MAX_PICKUP_CODE_HTML_LEN: u32 = 128;
pub global MAX_DELIVERY_ORDER_ID_HTML_LEN: u32 = 256;
pub global PICKUP_CODE_BYTES: u32 = 6;
pub global ORDER_ID_BYTES: u32 = 19;

// shipTo line bounds (trimmed content; whitespace inside the <li>
// wrapper is verified separately via anchor checks).
pub global MAX_NAME_LEN: u32 = 64;
pub global MAX_STREET_LEN: u32 = 96;
pub global MAX_CITY_STATE_ZIP_LEN: u32 = 96;
pub global MAX_COUNTRY_LEN: u32 = 32;

// Max ASCII characters in the dollar value between `>$` and `<` in
// grandTotal. Covers `$X,XXX,XXX.XX` (10 digits + 2 commas + `.`); we
// cap at 999,999.99 in v1 so 9 chars is enough but the bound is the
// hint's ceiling, not a constraint.
pub global MAX_GRAND_TOTAL_DIGITS: u32 = 13;

// Re-export for convenience so downstream callers can import the
// needle ceiling alongside the rest of the size constants.
pub use status::MAX_STATUS_NEEDLE_LEN;

pub struct Contents {
    pub shipment_status: BoundedVec<u8, MAX_SHIPMENT_STATUS_LEN>,
    pub product_title: BoundedVec<u8, MAX_PRODUCT_TITLE_LEN>,
    pub ship_to: BoundedVec<u8, MAX_SHIP_TO_LEN>,
    pub grand_total: BoundedVec<u8, MAX_GRAND_TOTAL_LEN>,
}

pub struct Hashes {
    pub shipment_status: [u8; 32],
    pub product_title: [u8; 32],
    pub ship_to: [u8; 32],
    pub grand_total: [u8; 32],
}

// shipTo hint set: byte offsets into ship_to.storage() where each
// trimmed logical line begins, and how long that line is. The TS parser
// computes these by walking the HTML; the circuit verifies the
// surrounding anchor bytes match expectations and reads the slice.
// Order: [name, street, city_state_zip, country].
pub struct ShipToHints {
    pub offsets: [u32; 4],
    pub lens: [u32; 4],
}

pub struct PublicOutputs {
    pub asin: Field,                // ASCII bytes packed into one Field
    pub grand_total: Field,         // cents, e.g. $1,234.56 -> 123456
    pub address_commitment: Field,  // poseidon2 over packed name|street|csz|country
    pub nullifier: Field,           // poseidon2(pack(signature))
    pub shipment_date: Field,       // mocked to 0; real extraction is a v2 follow-up
}

pub struct DeliveryCodeContents {
    pub delivery_status: BoundedVec<u8, MAX_DELIVERY_STATUS_LEN>,
    pub pickup_code: BoundedVec<u8, MAX_PICKUP_CODE_HTML_LEN>,
    pub order_id: BoundedVec<u8, MAX_DELIVERY_ORDER_ID_HTML_LEN>,
}

pub struct DeliveryCodeHashes {
    pub delivery_status: [u8; 32],
    pub pickup_code: [u8; 32],
    pub order_id: [u8; 32],
}

pub struct DeliveryCodePublicOutputs {
    pub pickup_code: [u8; PICKUP_CODE_BYTES],
    pub order_id: [u8; ORDER_ID_BYTES],
}

// Single high-level entrypoint. `bin/main.nr::main` and downstream Aztec
// contract functions both call this directly.
pub fn verify(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    allowed_url: BoundedVec<u8, MAX_URL_LEN>,
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    recipient: [u8; 20],
    timestamp: u64,
    expected_status: BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>,
    hashes: Hashes,
    contents: Contents,
    ship_to_hints: ShipToHints,
    grand_total_len: u32,
) -> PublicOutputs {
    // (1) Attestor signature.
    assert(
        std::ecdsa_secp256k1::verify_signature(
            public_key_x, public_key_y, signature, hash,
        ),
        "attestor signature invalid",
    );

    // (2) URL prefix.
    url::assert_prefix(allowed_url, request_url);

    // (3) Per-field sha256 binding plaintexts to attestor-signed hashes.
    assert(
        sha256_var(
            contents.shipment_status.storage(),
            contents.shipment_status.len() as u32,
        ) == hashes.shipment_status,
        "shipment_status sha256 mismatch",
    );
    assert(
        sha256_var(
            contents.product_title.storage(),
            contents.product_title.len() as u32,
        ) == hashes.product_title,
        "product_title sha256 mismatch",
    );
    assert(
        sha256_var(
            contents.ship_to.storage(),
            contents.ship_to.len() as u32,
        ) == hashes.ship_to,
        "ship_to sha256 mismatch",
    );
    assert(
        sha256_var(
            contents.grand_total.storage(),
            contents.grand_total.len() as u32,
        ) == hashes.grand_total,
        "grand_total sha256 mismatch",
    );

    // (4) ASIN.
    let asin = asin::extract(contents.product_title);

    // (5) Grand total in cents.
    let grand_total = grand_total::extract(contents.grand_total, grand_total_len);

    // (6) shipTo address commitment.
    let address_commitment = ship_to::extract_commitment(contents.ship_to, ship_to_hints);

    // (7) shipmentStatus contains the caller-supplied needle.
    status::assert_status_contains(expected_status, contents.shipment_status);

    // (8) Nullifier.
    let nullifier = nullifier::compute(signature);

    // recipient and timestamp are consumed only as public inputs (no
    // in-circuit use yet); referencing them here keeps Noir from warning
    // about unused params.
    let _ = recipient;
    let _ = timestamp;

    PublicOutputs {
        asin,
        grand_total,
        address_commitment,
        nullifier,
        shipment_date: 0,
    }
}

pub fn verify_delivery_code(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    allowed_url: BoundedVec<u8, MAX_DELIVERY_URL_LEN>,
    request_url: BoundedVec<u8, MAX_DELIVERY_URL_LEN>,
    recipient: [u8; 20],
    timestamp: u64,
    hashes: DeliveryCodeHashes,
    contents: DeliveryCodeContents,
) -> DeliveryCodePublicOutputs {
    assert(
        std::ecdsa_secp256k1::verify_signature(
            public_key_x, public_key_y, signature, hash,
        ),
        "attestor signature invalid",
    );

    url::assert_prefix(allowed_url, request_url);

    assert(
        sha256_var(
            contents.delivery_status.storage(),
            contents.delivery_status.len() as u32,
        ) == hashes.delivery_status,
        "delivery_status sha256 mismatch",
    );
    assert(
        sha256_var(
            contents.pickup_code.storage(),
            contents.pickup_code.len() as u32,
        ) == hashes.pickup_code,
        "pickup_code sha256 mismatch",
    );
    assert(
        sha256_var(
            contents.order_id.storage(),
            contents.order_id.len() as u32,
        ) == hashes.order_id,
        "order_id sha256 mismatch",
    );

    status::assert_delivery_status_delivered(contents.delivery_status);
    let pickup_code = delivery_code::extract_pickup_code(contents.pickup_code);
    let order_id = delivery_code::extract_order_id(contents.order_id);

    let _ = recipient;
    let _ = timestamp;

    DeliveryCodePublicOutputs { pickup_code, order_id }
}
