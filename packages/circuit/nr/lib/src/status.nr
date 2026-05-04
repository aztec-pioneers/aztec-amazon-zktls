// shipmentStatus check: assert the plaintext contains an
// arbitrary substring chosen by the verifier (passed in as a
// bounded byte sequence). The contract layer constrains
// `expected_status` to a known literal (e.g. ">Delivered " or
// ">Arriving ") so the prover cannot pick a needle that always
// matches.

use crate::MAX_SHIPMENT_STATUS_LEN;
use string_search::{StringBody, StringBody256, SubString, SubString32};

// Fits the longest currently-known terminal-state needle
// (">Delivered " is 11 bytes) plus slack for ">Arriving "
// (10 bytes) and future variants. Must stay <= 32 so SubString32
// can hold it.
pub global MAX_STATUS_NEEDLE_LEN: u32 = 16;

pub fn assert_status_contains(
    expected_status: BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>,
    shipment_status: BoundedVec<u8, MAX_SHIPMENT_STATUS_LEN>,
) {
    let needle: SubString32 =
        SubString::new(expected_status.storage(), expected_status.len() as u32);
    let haystack: StringBody256 =
        StringBody::new(shipment_status.storage(), shipment_status.len());
    let (found, _position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "shipmentStatus does not contain expected status");
}
