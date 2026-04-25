// Constrained prefix check: request_url begins with allowed_url.
// Bounded by MAX_URL_LEN; the conditional folds the tail past the
// prefix length.

use crate::MAX_URL_LEN;

pub fn assert_prefix(
    allowed_url: BoundedVec<u8, MAX_URL_LEN>,
    request_url: BoundedVec<u8, MAX_URL_LEN>,
) {
    let allowed_len = allowed_url.len();
    assert(request_url.len() >= allowed_len, "request_url shorter than prefix");
    let allowed_bytes = allowed_url.storage();
    let request_bytes = request_url.storage();
    for j in 0..MAX_URL_LEN {
        // Hoist reads out of the conditional; both arrays are sized
        // MAX_URL_LEN so j < MAX is always safe.
        let av = allowed_bytes[j];
        let rv = request_bytes[j];
        if j < allowed_len {
            assert_eq(rv, av, "URL prefix mismatch");
        }
    }
}
