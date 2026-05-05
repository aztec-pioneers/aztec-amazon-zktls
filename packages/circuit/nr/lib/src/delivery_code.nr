// Amazon Locker delivery-code extractors.
//
// The Primus template hashes the exact plaintext returned by its XPath:
//   - pickupCode: `Your pickup code is 123456`
//   - orderId: an order-details href containing `orderID=...`
//
// This module searches the signed plaintexts for those stable anchors,
// copies fixed-size byte arrays, and range-checks their formats.

use crate::{
    MAX_PICKUP_CODE_HTML_LEN, MAX_DELIVERY_ORDER_ID_HTML_LEN, PICKUP_CODE_BYTES,
    ORDER_ID_BYTES,
};
use string_search::{StringBody, StringBody128, StringBody256, SubString, SubString32};

global PICKUP_CODE_ANCHOR_LEN: u32 = 20;
global ORDER_ID_ANCHOR_LEN: u32 = 8;

fn is_digit(b: u8) -> bool {
    (b >= 0x30) & (b <= 0x39)
}

pub fn extract_pickup_code(
    pickup_code_html: BoundedVec<u8, MAX_PICKUP_CODE_HTML_LEN>,
) -> [u8; PICKUP_CODE_BYTES] {
    let needle_bytes: [u8; PICKUP_CODE_ANCHOR_LEN] =
        comptime { "Your pickup code is ".as_bytes() };
    let needle: SubString32 = SubString::new(needle_bytes, PICKUP_CODE_ANCHOR_LEN);
    let haystack: StringBody128 =
        StringBody::new(pickup_code_html.storage(), pickup_code_html.len());
    let (found, position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "pickup-code anchor not found");

    let start = position + PICKUP_CODE_ANCHOR_LEN;
    assert(
        start + PICKUP_CODE_BYTES <= pickup_code_html.len(),
        "pickup-code value truncated",
    );

    let bytes = pickup_code_html.storage();
    let mut out: [u8; PICKUP_CODE_BYTES] = [0; PICKUP_CODE_BYTES];
    for i in 0..PICKUP_CODE_BYTES {
        let b = bytes[start + i];
        assert(is_digit(b), "pickup-code byte not digit");
        out[i] = b;
    }

    let next_index = start + PICKUP_CODE_BYTES;
    if next_index < pickup_code_html.len() {
        assert(!is_digit(bytes[next_index]), "pickup-code too long");
    }
    out
}

pub fn extract_order_id(
    order_id_html: BoundedVec<u8, MAX_DELIVERY_ORDER_ID_HTML_LEN>,
) -> [u8; ORDER_ID_BYTES] {
    let needle_bytes: [u8; ORDER_ID_ANCHOR_LEN] = comptime { "orderID=".as_bytes() };
    let needle: SubString32 = SubString::new(needle_bytes, ORDER_ID_ANCHOR_LEN);
    let haystack: StringBody256 =
        StringBody::new(order_id_html.storage(), order_id_html.len());
    let (found, position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "orderID anchor not found");

    let start = position + ORDER_ID_ANCHOR_LEN;
    assert(
        start + ORDER_ID_BYTES <= order_id_html.len(),
        "orderID value truncated",
    );

    let bytes = order_id_html.storage();
    let hyphen: u8 = comptime { "-".as_bytes()[0] };
    let mut out: [u8; ORDER_ID_BYTES] = [0; ORDER_ID_BYTES];
    for i in 0..ORDER_ID_BYTES {
        let b = bytes[start + i];
        if (i == 3) | (i == 11) {
            assert_eq(b, hyphen, "orderID hyphen mismatch");
        } else {
            assert(is_digit(b), "orderID byte not digit");
        }
        out[i] = b;
    }

    let next_index = start + ORDER_ID_BYTES;
    if next_index < order_id_html.len() {
        let next = bytes[next_index];
        assert(!(is_digit(next) | (next == hyphen)), "orderID too long");
    }
    out
}
