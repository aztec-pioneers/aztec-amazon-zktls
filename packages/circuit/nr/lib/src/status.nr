// shipmentStatus check: assert the plaintext contains the substring
// `>Delivered ` (trailing space included).
//
// TODO: support additional terminal states like `>Picked up `. Either
// accept any of a known set (multiple substring_match calls OR'd
// together) or take the expected status as a public input from a small
// enum so the verifier can pick which terminal state they require.

use crate::MAX_SHIPMENT_STATUS_LEN;
use string_search::{StringBody, StringBody256, SubString, SubString32};

pub fn assert_delivered(
    shipment_status: BoundedVec<u8, MAX_SHIPMENT_STATUS_LEN>,
) {
    // `>Delivered ` is 11 bytes; SubString32 fits comfortably.
    let needle_bytes: [u8; 11] = comptime { ">Delivered ".as_bytes() };
    let needle: SubString32 = SubString::new(needle_bytes, 11);
    let haystack: StringBody256 =
        StringBody::new(shipment_status.storage(), shipment_status.len());
    let (found, _position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "shipmentStatus does not contain 'Delivered'");
}
