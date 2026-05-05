// Constrained prefix check: request_url begins with allowed_url.
// Generic over the BoundedVec ceiling so order-summary and delivery-code
// circuits can use different URL bounds without duplicating the check.

pub fn assert_prefix<let MAX: u32>(
    allowed_url: BoundedVec<u8, MAX>,
    request_url: BoundedVec<u8, MAX>,
) {
    let allowed_len = allowed_url.len();
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
}
