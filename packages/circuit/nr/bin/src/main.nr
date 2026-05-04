// Standalone proving entrypoint. Same shape we'll lift into an Aztec
// private function later. All logic lives in `amazon_zktls_lib::verify`;
// this file just declares the public/private split and forwards.

use amazon_zktls_lib::{
    Contents, Hashes, PublicOutputs, ShipToHints, MAX_STATUS_NEEDLE_LEN, MAX_URL_LEN, verify,
};

fn main(
    public_key_x: pub [u8; 32],
    public_key_y: pub [u8; 32],
    hash: pub [u8; 32],
    signature: [u8; 64],
    allowed_url: pub BoundedVec<u8, MAX_URL_LEN>,
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    recipient: pub [u8; 20],
    timestamp: pub u64,
    expected_status: pub BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>,
    hashes: pub Hashes,
    contents: Contents,
    ship_to_hints: ShipToHints,
    grand_total_len: u32,
) -> pub PublicOutputs {
    verify(
        public_key_x,
        public_key_y,
        hash,
        signature,
        allowed_url,
        request_url,
        recipient,
        timestamp,
        expected_status,
        hashes,
        contents,
        ship_to_hints,
        grand_total_len,
    )
}
