// Standalone proving entrypoint for Amazon Locker delivery-code attestations.
// The full request_url is public for downstream checks; pickup code and
// order id are returned as fixed-size public byte arrays.

use amazon_zktls_lib::{
    DeliveryCodeContents, DeliveryCodeHashes, DeliveryCodePublicOutputs,
    MAX_DELIVERY_URL_LEN, verify_delivery_code,
};

fn main(
    public_key_x: pub [u8; 32],
    public_key_y: pub [u8; 32],
    hash: pub [u8; 32],
    signature: [u8; 64],
    allowed_url: pub BoundedVec<u8, MAX_DELIVERY_URL_LEN>,
    request_url: pub BoundedVec<u8, MAX_DELIVERY_URL_LEN>,
    recipient: pub [u8; 20],
    timestamp: pub u64,
    hashes: pub DeliveryCodeHashes,
    contents: DeliveryCodeContents,
) -> pub DeliveryCodePublicOutputs {
    verify_delivery_code(
        public_key_x,
        public_key_y,
        hash,
        signature,
        allowed_url,
        request_url,
        recipient,
        timestamp,
        hashes,
        contents,
    )
}
