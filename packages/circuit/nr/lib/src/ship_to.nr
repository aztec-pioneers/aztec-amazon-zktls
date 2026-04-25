// shipTo extractor + address commitment.
//
// Splits the shipTo HTML into 4 logical lines:
//   0. name              wrapped in `<li>` 1
//   1. street            wrapped in `<li>` 2 before `<br>`
//   2. city_state_zip    wrapped in `<li>` 2 after `<br>`
//   3. country           wrapped in `<li>` 3
//
// The TS parser hints (offset, len) for each trimmed line into
// ship_to.storage(); this module verifies the surrounding anchor bytes
// match Amazon's template, copies the line bytes into fixed-width
// arrays, packs each via nodash::pack_bytes, concatenates the packed
// Fields in line order, and poseidon2-hashes them into a single
// commitment.
//
// Anchor bytes (verified at run time, defined as comptime constants
// from string literals so the byte arithmetic is one place):
//   LI_OPEN  = `class="a-list-item">\n` + 16 spaces        (37 B)
//   LI_CLOSE = `\n` + 12 spaces + `</span></li>`           (25 B)
//   BR       = `<br>`                                      ( 4 B)

use crate::{
    MAX_SHIP_TO_LEN, MAX_NAME_LEN, MAX_STREET_LEN, MAX_CITY_STATE_ZIP_LEN,
    MAX_COUNTRY_LEN, ShipToHints,
};
use nodash::{pack_bytes, poseidon2};

global LI_OPEN_LEN: u32 = 37;
global LI_CLOSE_LEN: u32 = 25;
global BR_LEN: u32 = 4;

// Total packed-Field count in line order:
//   name (64/31+1=3) + street (96/31+1=4) + csz (4) + country (32/31+1=2)
global PACKED_TOTAL: u32 = 13;

// Verify the K-byte anchor sits at `start` in the shipTo plaintext.
// Reads are unconditional; caller must guarantee start + K <= storage size.
fn assert_anchor<let K: u32>(
    bytes: [u8; MAX_SHIP_TO_LEN],
    start: u32,
    anchor: [u8; K],
) {
    for k in 0..K {
        assert_eq(bytes[start + k], anchor[k], "shipTo anchor mismatch");
    }
}

// Read MAX_LINE bytes starting at offset; bytes past `len` are zeroed
// for deterministic packing.
fn read_line<let MAX_LINE: u32>(
    bytes: [u8; MAX_SHIP_TO_LEN],
    offset: u32,
    len: u32,
) -> [u8; MAX_LINE] {
    let mut out: [u8; MAX_LINE] = [0; MAX_LINE];
    for j in 0..MAX_LINE {
        // Hoist the read; offset + MAX_LINE is bounded by the caller's
        // assert against MAX_SHIP_TO_LEN.
        let v = bytes[offset + j];
        if j < len {
            out[j] = v;
        }
    }
    out
}

pub fn extract_commitment(
    ship_to: BoundedVec<u8, MAX_SHIP_TO_LEN>,
    hints: ShipToHints,
) -> Field {
    let bytes = ship_to.storage();

    let li_open: [u8; LI_OPEN_LEN] =
        comptime { "class=\"a-list-item\">\n                ".as_bytes() };
    let li_close: [u8; LI_CLOSE_LEN] =
        comptime { "\n            </span></li>".as_bytes() };
    let br: [u8; BR_LEN] = comptime { "<br>".as_bytes() };

    let off = hints.offsets;
    let len = hints.lens;

    // Per-line max bytes. Caps must satisfy off[i] + MAX_LINE <= MAX_SHIP_TO_LEN
    // for the unconditional reads in `read_line` to stay in-bounds.
    assert(len[0] <= MAX_NAME_LEN, "name too long");
    assert(len[1] <= MAX_STREET_LEN, "street too long");
    assert(len[2] <= MAX_CITY_STATE_ZIP_LEN, "city_state_zip too long");
    assert(len[3] <= MAX_COUNTRY_LEN, "country too long");
    assert(off[0] + MAX_NAME_LEN <= MAX_SHIP_TO_LEN, "name window OOB");
    assert(off[1] + MAX_STREET_LEN <= MAX_SHIP_TO_LEN, "street window OOB");
    assert(off[2] + MAX_CITY_STATE_ZIP_LEN <= MAX_SHIP_TO_LEN, "csz window OOB");
    assert(off[3] + MAX_COUNTRY_LEN <= MAX_SHIP_TO_LEN, "country window OOB");

    // Open-anchor offsets (preceding bytes). Use `<li>` open for lines
    // 0/1/3 and `<br>` for line 2.
    assert(off[0] >= LI_OPEN_LEN, "name offset too small");
    assert(off[1] >= LI_OPEN_LEN, "street offset too small");
    assert(off[2] >= BR_LEN, "csz offset too small");
    assert(off[3] >= LI_OPEN_LEN, "country offset too small");

    assert_anchor(bytes, off[0] - LI_OPEN_LEN, li_open);
    assert_anchor(bytes, off[1] - LI_OPEN_LEN, li_open);
    assert_anchor(bytes, off[2] - BR_LEN, br);
    assert_anchor(bytes, off[3] - LI_OPEN_LEN, li_open);

    // Close-anchor offsets. `<li>` close for lines 0/2/3 and `<br>` for
    // line 1 (before city_state_zip).
    assert(off[0] + len[0] + LI_CLOSE_LEN <= MAX_SHIP_TO_LEN, "name close OOB");
    assert(off[1] + len[1] + BR_LEN <= MAX_SHIP_TO_LEN, "street close OOB");
    assert(off[2] + len[2] + LI_CLOSE_LEN <= MAX_SHIP_TO_LEN, "csz close OOB");
    assert(off[3] + len[3] + LI_CLOSE_LEN <= MAX_SHIP_TO_LEN, "country close OOB");

    assert_anchor(bytes, off[0] + len[0], li_close);
    assert_anchor(bytes, off[1] + len[1], br);
    assert_anchor(bytes, off[2] + len[2], li_close);
    assert_anchor(bytes, off[3] + len[3], li_close);

    // Read trimmed lines into fixed-width windows.
    let name_bytes: [u8; MAX_NAME_LEN] = read_line(bytes, off[0], len[0]);
    let street_bytes: [u8; MAX_STREET_LEN] = read_line(bytes, off[1], len[1]);
    let csz_bytes: [u8; MAX_CITY_STATE_ZIP_LEN] = read_line(bytes, off[2], len[2]);
    let country_bytes: [u8; MAX_COUNTRY_LEN] = read_line(bytes, off[3], len[3]);

    // Pack to BN254 Fields (31-byte chunks).
    let name_packed = pack_bytes(name_bytes);       // [Field; 3]
    let street_packed = pack_bytes(street_bytes);   // [Field; 4]
    let csz_packed = pack_bytes(csz_bytes);         // [Field; 4]
    let country_packed = pack_bytes(country_bytes); // [Field; 2]

    // Concatenate in line order.
    let mut all_packed: [Field; PACKED_TOTAL] = [0; PACKED_TOTAL];
    for i in 0..3 {
        all_packed[i] = name_packed[i];
    }
    for i in 0..4 {
        all_packed[3 + i] = street_packed[i];
    }
    for i in 0..4 {
        all_packed[7 + i] = csz_packed[i];
    }
    for i in 0..2 {
        all_packed[11 + i] = country_packed[i];
    }

    poseidon2(all_packed)
}
