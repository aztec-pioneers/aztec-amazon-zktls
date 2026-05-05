// Constrained prefix check: request_url begins with allowed_url.
// Generic over the BoundedVec ceiling so order-summary and delivery-code
// circuits can use different URL bounds without duplicating the check.

pub fn assert_prefix<let MAX: u32>(
    allowed_url: BoundedVec<u8, MAX>,
    request_url: BoundedVec<u8, MAX>,
) {
    let allowed_len = allowed_url.len();
    assert(allowed_len > 0, "allowed_url empty");
    assert(request_url.len() >= allowed_len, "request_url shorter than prefix");
    let allowed_bytes = allowed_url.storage();
    let request_bytes = request_url.storage();
    for j in 0..MAX {
        // Hoist reads out of the conditional; both arrays are sized
        // MAX so j < MAX is always safe.
        let av = allowed_bytes[j];
        let rv = request_bytes[j];
        if j < allowed_len {
            assert_eq(rv, av, "URL prefix mismatch");
        }
    }

    if request_url.len() > allowed_len {
        let slash: u8 = comptime { "/".as_bytes()[0] };
        let question: u8 = comptime { "?".as_bytes()[0] };
        let fragment: u8 = comptime { "#".as_bytes()[0] };
        let last_allowed = allowed_bytes[allowed_len - 1];
        let next = request_bytes[allowed_len];
        let allowed_is_delimited =
            (last_allowed == slash) | (last_allowed == question) | (last_allowed == fragment);
        if !allowed_is_delimited {
            let next_is_delimiter = (next == slash) | (next == question) | (next == fragment);
            assert(next_is_delimiter, "URL prefix boundary mismatch");
        }
    }
}
