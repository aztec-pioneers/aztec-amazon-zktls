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
//   7. shipmentStatus contains "Delivered".
//   8. Nullifier = poseidon2(pack(signature)).
//
// TODO(soundness): public inputs (recipient, timestamp, hashes, attestor
// pubkey) are not bound to `hash` inside the circuit. Verifier must set
// them correctly. v2 should reconstruct the canonical attestation message
// in-circuit and assert keccak256(canonical) == hash.

use sha256::sha256_var;

pub mod asin;
pub mod grand_total;
pub mod nullifier;
pub mod ship_to;
pub mod status;
pub mod url;

pub global MAX_URL_LEN: u32 = 128;

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

    // (7) shipmentStatus contains "Delivered".
    status::assert_delivered(contents.shipment_status);

    // (8) Nullifier.
    let nullifier = nullifier::compute(signature);

    // recipient and timestamp are consumed only as public inputs (no
    // in-circuit use yet); referencing them here keeps Noir from warning
    // about unused params.
    let _ = recipient;
    let _ = timestamp;

    PublicOutputs { asin, grand_total, address_commitment, nullifier }
}
