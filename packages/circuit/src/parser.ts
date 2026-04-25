// Turn a Primus attestation JSON (+ plaintexts) into the CircuitInputs the
// bin circuit consumes. Performs two safety checks that the circuit itself
// doesn't do:
//   - recovered ECDSA pubkey hashes to the declared attestor address
//   - sha256(plaintext_i) matches the hash claimed in `attestation.data`
// Both would cause circuit prove() to fail anyway, but catching them here
// gives a clearer error (and lets the test harness fast-fail before hitting
// bb.js).

import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  CIRCUIT_DIMS,
  FIELD_MAP,
  type CircuitInputs,
  type FieldKey,
  type PrimusAttestation,
} from "./types.js";
import { encodeAttestation } from "./encode.js";

const AMAZON_ALLOWED_URL = "https://www.amazon.com";

// Anchor literals — must stay byte-identical to the comptime constants in
// nr/lib/src/{ship_to,grand_total}.nr.
const LI_OPEN = 'class="a-list-item">\n                '; // 37 B
const LI_CLOSE = "\n            </span></li>"; // 25 B
const BR = "<br>";

function locateAll(haystack: string, needle: string): number[] {
  const out: number[] = [];
  let i = 0;
  while (i <= haystack.length - needle.length) {
    const found = haystack.indexOf(needle, i);
    if (found === -1) break;
    out.push(found);
    i = found + 1;
  }
  return out;
}

function locateShipToHints(shipTo: string): {
  offsets: number[];
  lens: number[];
} {
  const opens = locateAll(shipTo, LI_OPEN);
  const closes = locateAll(shipTo, LI_CLOSE);
  if (opens.length !== 3 || closes.length !== 3) {
    throw new Error(
      `shipTo template mismatch: expected 3 <li> open/close pairs, got ${opens.length}/${closes.length}`,
    );
  }
  // Content of <li>_i is [opens[i] + LI_OPEN.length, closes[i]).
  const o = opens.map((p) => p + LI_OPEN.length);

  // The second <li> contains a single <br> separating street and
  // city_state_zip; assert exactly one and that it sits inside that range.
  const brAll = locateAll(shipTo, BR).filter((p) => p > o[1] && p < closes[1]);
  if (brAll.length !== 1) {
    throw new Error(
      `expected exactly one <br> inside the second <li>, found ${brAll.length}`,
    );
  }
  const br = brAll[0];

  // Lines: name, street, city_state_zip, country.
  const offsets = [o[0], o[1], br + BR.length, o[2]];
  const lens = [
    closes[0] - o[0],
    br - o[1],
    closes[1] - (br + BR.length),
    closes[2] - o[2],
  ];
  return { offsets, lens };
}

function locateGrandTotalLen(grandTotal: string): number {
  const dollar = grandTotal.indexOf("$");
  if (dollar === -1) throw new Error("$ not found in grandTotal");
  // Walk past the digit run (digits + thousands-comma + decimal period).
  // Stop at the first non-numeric byte (space, '<', whatever).
  let end = dollar + 1;
  while (end < grandTotal.length) {
    const c = grandTotal.charCodeAt(end);
    const isDigit = c >= 0x30 && c <= 0x39;
    const isComma = c === 0x2c; // ','
    const isPeriod = c === 0x2e; // '.'
    if (!(isDigit || isComma || isPeriod)) break;
    end++;
  }
  return end - (dollar + 1);
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// Ethereum "address of pubkey" = last 20 bytes of keccak256(pubkey[1..]).
function pubkeyToAddress(pub65: Uint8Array): string {
  if (pub65.length !== 65 || pub65[0] !== 0x04) {
    throw new Error("expected uncompressed 65-byte pubkey");
  }
  const hash = keccak_256(pub65.slice(1));
  return "0x" + bytesToHex(hash.slice(-20));
}

// Parse the 65-byte (r|s|v) hex signature into its components plus the
// "compact" 64-byte (r|s) form the Noir circuit wants.
function splitSignature(sigHex: string) {
  const sig = hexToBytes(sigHex);
  if (sig.length !== 65) throw new Error(`signature must be 65 bytes, got ${sig.length}`);
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  let v = sig[64];
  if (v === 27 || v === 28) v -= 27;
  if (v !== 0 && v !== 1) throw new Error(`unsupported v=${v}`);
  return { r, s, v, compact: sig.slice(0, 64) };
}

// Pad a utf-8 string into a fixed-length byte storage, recording the true
// length for BoundedVec. Throws if the content is longer than the max.
function toBoundedVec(value: string | Uint8Array, max: number, label: string) {
  const bytes =
    value instanceof Uint8Array ? value : new TextEncoder().encode(value);
  if (bytes.length > max) {
    throw new Error(`${label} is ${bytes.length} bytes, exceeds MAX=${max}`);
  }
  const storage = new Array<number>(max).fill(0);
  for (let i = 0; i < bytes.length; i++) storage[i] = bytes[i];
  return { storage, len: bytes.length };
}

export interface ParseOptions {
  // Optional override: skip sha256 self-check (useful if you want the
  // circuit itself to be the integrity oracle).
  skipSha256Check?: boolean;
}

export function parseAttestation(
  att: PrimusAttestation,
  plaintexts: Record<string, string>,
  opts: ParseOptions = {},
): CircuitInputs {
  // 1. Canonical message hash the attestor signed.
  const hash = encodeAttestation(att);

  // 2. Recover pubkey from signature + hash. noble's recoverPublicKey returns
  //    an affine point; uncompressed serialization is `0x04 || X || Y`.
  const { r, s, v, compact } = splitSignature(att.signatures[0]);
  const signature = new secp256k1.Signature(
    BigInt("0x" + bytesToHex(r)),
    BigInt("0x" + bytesToHex(s)),
  ).addRecoveryBit(v);
  const pubkey = signature.recoverPublicKey(hash);
  const pub65 = pubkey.toRawBytes(false); // 65 bytes
  const pubX = pub65.slice(1, 33);
  const pubY = pub65.slice(33, 65);

  // 3. Cross-check: recovered address matches the declared attestor. If not,
  //    the attestation was malformed or tampered with.
  const recoveredAddr = pubkeyToAddress(pub65).toLowerCase();
  const declaredAddr = att.attestors[0].attestorAddr.toLowerCase();
  if (recoveredAddr !== declaredAddr) {
    throw new Error(
      `attestor mismatch: signature recovered to ${recoveredAddr}, expected ${declaredAddr}`,
    );
  }

  // 4. Data hashes: attestation.data is JSON like
  //    `{"shipmentStatus":"<sha256>", ...}`. Map to Noir snake_case fields.
  const dataObj = JSON.parse(att.data) as Record<string, string>;
  const hashesByField = {} as CircuitInputs["hashes"];
  const expectedHashes = {} as Record<FieldKey, Uint8Array>;
  for (const snake of Object.keys(FIELD_MAP) as FieldKey[]) {
    const camel = FIELD_MAP[snake];
    const hex = dataObj[camel];
    if (typeof hex !== "string" || !/^[0-9a-f]{64}$/i.test(hex)) {
      throw new Error(`missing/invalid hash for field '${camel}' in attestation.data`);
    }
    const bytes = hexToBytes(hex);
    expectedHashes[snake] = bytes;
    hashesByField[snake] = Array.from(bytes);
  }

  // 5. Contents: pad each plaintext into its own BoundedVec. Verify the
  //    local sha256 matches the signed hash as a sanity check.
  const contentsByField = {} as CircuitInputs["contents"];
  const maxByField: Record<FieldKey, number> = {
    shipment_status: CIRCUIT_DIMS.MAX_SHIPMENT_STATUS_LEN,
    product_title: CIRCUIT_DIMS.MAX_PRODUCT_TITLE_LEN,
    ship_to: CIRCUIT_DIMS.MAX_SHIP_TO_LEN,
    grand_total: CIRCUIT_DIMS.MAX_GRAND_TOTAL_LEN,
  };
  for (const snake of Object.keys(FIELD_MAP) as FieldKey[]) {
    const camel = FIELD_MAP[snake];
    const plain = plaintexts[camel];
    if (typeof plain !== "string") {
      throw new Error(`plaintexts['${camel}'] missing`);
    }
    contentsByField[snake] = toBoundedVec(plain, maxByField[snake], camel);
    if (!opts.skipSha256Check) {
      const local: Uint8Array = sha256(new TextEncoder().encode(plain));
      const expected = expectedHashes[snake];
      let match = local.length === expected.length;
      if (match) {
        for (let i = 0; i < local.length; i++) {
          if (local[i] !== expected[i]) {
            match = false;
            break;
          }
        }
      }
      if (!match) {
        throw new Error(
          `sha256(plaintexts['${camel}']) does not match attestation.data['${camel}']` +
            ` - got ${bytesToHex(local)}, expected ${bytesToHex(expected)}`,
        );
      }
    }
  }

  // 6. Allowed URL + request URL as BoundedVec<u8, MAX_URL_LEN>.
  const allowed_url = toBoundedVec(
    AMAZON_ALLOWED_URL,
    CIRCUIT_DIMS.MAX_URL_LEN,
    "allowed_url",
  );
  const request_url = toBoundedVec(
    att.request.url,
    CIRCUIT_DIMS.MAX_URL_LEN,
    "request_url",
  );

  // 7. Recipient (20-byte address) and timestamp (u64 as decimal string).
  const recipientBytes = hexToBytes(att.recipient);
  if (recipientBytes.length !== 20) {
    throw new Error(`recipient must be 20 bytes, got ${recipientBytes.length}`);
  }

  // 8. Hints for the in-circuit extractors.
  const ship_to_hints = locateShipToHints(plaintexts[FIELD_MAP.ship_to]);
  const grand_total_len = locateGrandTotalLen(plaintexts[FIELD_MAP.grand_total]);
  if (grand_total_len > CIRCUIT_DIMS.MAX_GRAND_TOTAL_DIGITS) {
    throw new Error(
      `grand_total digit window is ${grand_total_len} bytes, exceeds MAX=${CIRCUIT_DIMS.MAX_GRAND_TOTAL_DIGITS}`,
    );
  }

  return {
    public_key_x: Array.from(pubX),
    public_key_y: Array.from(pubY),
    hash: Array.from(hash),
    signature: Array.from(compact),
    allowed_url,
    request_url,
    recipient: Array.from(recipientBytes),
    timestamp: String(att.timestamp),
    hashes: hashesByField,
    contents: contentsByField,
    ship_to_hints,
    grand_total_len,
  };
}
