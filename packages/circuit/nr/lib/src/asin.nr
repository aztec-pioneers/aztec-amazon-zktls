// ASIN extractor.
//
// Amazon ASINs are exactly 10 ASCII chars from the alphabet [0-9 | A-Z]
// and appear in productTitle as the substring `/dp/<ASIN>`. We use
// noir_string_search to locate the `/dp/` anchor in-circuit, then read
// 10 bytes from `position + 4` and pack to a single Field with nodash.

use crate::MAX_PRODUCT_TITLE_LEN;
use string_search::{StringBody, StringBody1024, SubString, SubString32};
use nodash::pack_bytes;

pub global ASIN_BYTES: u32 = 10;

pub fn extract(product_title: BoundedVec<u8, MAX_PRODUCT_TITLE_LEN>) -> Field {
    // Locate `/dp/` inside productTitle.
    let needle_bytes: [u8; 4] = comptime { "/dp/".as_bytes() };
    let needle: SubString32 = SubString::new(needle_bytes, 4);
    let haystack: StringBody1024 =
        StringBody::new(product_title.storage(), product_title.len());
    let (found, position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "/dp/ anchor not found in productTitle");

    // Bound the ASIN window so the unconditional reads below are safe.
    assert(
        position + 4 + ASIN_BYTES <= MAX_PRODUCT_TITLE_LEN,
        "/dp/ anchor too late for full ASIN",
    );

    // Read 10 bytes after the anchor.
    let title_bytes = product_title.storage();
    let mut asin_bytes: [u8; ASIN_BYTES] = [0; ASIN_BYTES];
    for i in 0..ASIN_BYTES {
        asin_bytes[i] = title_bytes[position + 4 + i];
    }

    // Range-check the ASIN alphabet [0-9 | A-Z].
    for i in 0..ASIN_BYTES {
        let b = asin_bytes[i];
        let is_digit = (b >= 0x30) & (b <= 0x39);
        let is_upper = (b >= 0x41) & (b <= 0x5A);
        assert(is_digit | is_upper, "ASIN byte not [0-9|A-Z]");
    }

    // 10 bytes < 31, so pack_bytes returns [Field; 1].
    let packed = pack_bytes(asin_bytes);
    packed[0]
}
