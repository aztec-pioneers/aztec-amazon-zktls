// Grand total parser.
//
// grandTotal contains `$X,XXX.XX` somewhere inside the outer-HTML span
// (Amazon emits it surrounded by whitespace, so we can't use `>$` as a
// direct anchor). We use noir_string_search to find the `$` byte, then
// read `grand_total_len` bytes (hinted) starting just past `$` and parse
// them as a USD value into integer cents.
//
// The hint length is constrained: the byte at position+1+grand_total_len
// must be `<`, anchoring the closing `</span>`. Inside the digit window
// the parser asserts ASCII digits, an optional thousands-comma, and
// exactly one period followed by exactly two more digits.

use crate::{MAX_GRAND_TOTAL_LEN, MAX_GRAND_TOTAL_DIGITS};
use string_search::{StringBody, StringBody128, SubString, SubString32};

pub fn extract(
    grand_total: BoundedVec<u8, MAX_GRAND_TOTAL_LEN>,
    grand_total_len: u32,
) -> Field {
    let needle_bytes: [u8; 1] = comptime { "$".as_bytes() };
    let needle: SubString32 = SubString::new(needle_bytes, 1);
    let haystack: StringBody128 =
        StringBody::new(grand_total.storage(), grand_total.len());
    let (found, position): (bool, u32) = haystack.substring_match(needle);
    assert(found, "$ anchor not found in grandTotal");

    // Close anchor: the byte right after the digit window must NOT be a
    // numeric character (digit, '.', or ','). This forces grand_total_len
    // to cover the entire digit run rather than a prefix of it. (Amazon's
    // template trails whitespace before `</span>`, so a literal `<`
    // anchor doesn't fit.)
    let bytes = grand_total.storage();
    let close_idx = position + 1 + grand_total_len;
    let close_byte = bytes[close_idx];
    let close_is_period = close_byte == comptime { ".".as_bytes()[0] };
    let close_is_comma = close_byte == comptime { ",".as_bytes()[0] };
    let close_is_digit = (close_byte >= 0x30) & (close_byte <= 0x39);
    assert(
        !(close_is_period | close_is_comma | close_is_digit),
        "grand_total: close byte still numeric (hint too short)",
    );

    assert(grand_total_len <= MAX_GRAND_TOTAL_DIGITS, "grand_total hint too long");
    assert(grand_total_len >= 4, "grand_total hint too short for X.XX");
    // Allow unconditional reads of the full digit window without OOB:
    // position + 1 + (MAX_GRAND_TOTAL_DIGITS - 1) must be < storage size.
    assert(
        position + 1 + MAX_GRAND_TOTAL_DIGITS <= MAX_GRAND_TOTAL_LEN,
        "grand_total: anchor too late for full digit window",
    );

    // Walk the digit window. We require exactly one `.` with exactly two
    // digits after it; commas are accepted before the `.` and skipped.
    let mut cents: Field = 0;
    let mut seen_period = false;
    let mut digits_after_period: u32 = 0;

    let period_byte = comptime { ".".as_bytes()[0] };
    let comma_byte = comptime { ",".as_bytes()[0] };

    for i in 0..MAX_GRAND_TOTAL_DIGITS {
        // Hoist the read out of the gating conditional; the bound assert
        // above guarantees the index is in range.
        let b = bytes[position + 1 + i];
        let is_period = b == period_byte;
        let is_comma = b == comma_byte;
        let is_digit = (b >= 0x30) & (b <= 0x39);

        if i < grand_total_len {
            assert(is_period | is_comma | is_digit, "grand_total: non-decimal byte");

            if is_period {
                assert(!seen_period, "grand_total: multiple periods");
                seen_period = true;
            } else if is_digit {
                cents = cents * 10 + (b as Field) - 48;
                if seen_period {
                    digits_after_period += 1;
                }
            }
            // Comma case is a no-op.
        }
    }

    assert(seen_period, "grand_total: missing period");
    assert_eq(digits_after_period, 2, "grand_total: must have exactly two decimal digits");

    cents
}
