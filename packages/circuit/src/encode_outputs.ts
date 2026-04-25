// Off-chain decoders / re-computers for the circuit's public outputs.
// Mirrors nodash's pack_bytes layout and uses bb.js's poseidon2 so a
// downstream consumer (escrow, registry, test harness) can recompute
// address_commitment / nullifier from raw inputs and match against the
// proof's public outputs.

import { BarretenbergSync } from "@aztec/bb.js";
import { CIRCUIT_DIMS } from "./types.js";

// ===== ASCII / decimal helpers =====

// Inverse of nodash::pack_bytes for a single Field that holds up to
// `len` ASCII bytes (e.g. the 10-byte ASIN). The Field's bytes are
// little-endian: lowest byte = bytes[0].
export function fieldToAsciiString(fieldHex: string, len: number): string {
  const x = BigInt(fieldHex.startsWith("0x") ? fieldHex : "0x" + fieldHex);
  const out = new Uint8Array(len);
  let v = x;
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return new TextDecoder().decode(out);
}

// Render integer cents as `$X,XXX.XX` for human display.
export function centsToCurrency(cents: bigint): string {
  const negative = cents < 0n;
  const abs = negative ? -cents : cents;
  const dollars = abs / 100n;
  const remainder = abs % 100n;
  const dollarsStr = dollars.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const remStr = remainder.toString().padStart(2, "0");
  return `${negative ? "-" : ""}$${dollarsStr}.${remStr}`;
}

// ===== nodash::pack_bytes mirror =====

// pack_bytes::<N>(arr) returns [Field; N/31 + 1]. Input is zero-padded
// (right side) to (N/31 + 1) * 31 bytes; each 31-byte chunk is encoded
// little-endian into one Field (chunk[0] is the lowest power of 256).
export function packBytesNodash(input: Uint8Array, max: number): bigint[] {
  if (input.length > max) {
    throw new Error(`packBytesNodash: input ${input.length} > max ${max}`);
  }
  const chunks = Math.floor(max / 31) + 1;
  const padded = new Uint8Array(chunks * 31);
  padded.set(input);
  const out: bigint[] = [];
  for (let c = 0; c < chunks; c++) {
    let f = 0n;
    let mul = 1n;
    for (let i = 0; i < 31; i++) {
      f += BigInt(padded[c * 31 + i]) * mul;
      mul <<= 8n;
    }
    out.push(f);
  }
  return out;
}

// ===== poseidon2 via bb.js =====

let bbsPromise: Promise<BarretenbergSync> | null = null;
async function getBbs(): Promise<BarretenbergSync> {
  if (!bbsPromise) {
    bbsPromise = BarretenbergSync.initSingleton();
  }
  return bbsPromise;
}

function bigintToFieldBytes(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  // Big-endian: highest byte at index 0.
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function fieldBytesToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) {
    v = (v << 8n) | BigInt(b[i]);
  }
  return v;
}

export async function poseidon2Hash(fields: bigint[]): Promise<bigint> {
  const bbs = await getBbs();
  const inputs = fields.map(bigintToFieldBytes);
  const { hash } = bbs.poseidon2Hash({ inputs });
  return fieldBytesToBigint(hash);
}

// ===== High-level: address commitment + nullifier =====

// Recompute the public `address_commitment` from raw line strings.
// Caller provides the trimmed line content (no Amazon HTML padding).
export async function computeAddressCommitment(lines: {
  name: string;
  street: string;
  city_state_zip: string;
  country: string;
}): Promise<bigint> {
  const enc = new TextEncoder();
  const namePacked = packBytesNodash(enc.encode(lines.name), CIRCUIT_DIMS.MAX_NAME_LEN);
  const streetPacked = packBytesNodash(
    enc.encode(lines.street),
    CIRCUIT_DIMS.MAX_STREET_LEN,
  );
  const cszPacked = packBytesNodash(
    enc.encode(lines.city_state_zip),
    CIRCUIT_DIMS.MAX_CITY_STATE_ZIP_LEN,
  );
  const countryPacked = packBytesNodash(
    enc.encode(lines.country),
    CIRCUIT_DIMS.MAX_COUNTRY_LEN,
  );
  const all = [...namePacked, ...streetPacked, ...cszPacked, ...countryPacked];
  return poseidon2Hash(all);
}

// Recompute nullifier = poseidon2(pack_bytes(signature)).
export async function computeNullifier(signature: Uint8Array): Promise<bigint> {
  if (signature.length !== 64) {
    throw new Error(`signature must be 64 bytes, got ${signature.length}`);
  }
  const packed = packBytesNodash(signature, 64);
  return poseidon2Hash(packed);
}
