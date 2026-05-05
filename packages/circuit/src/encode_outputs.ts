// Off-chain decoders / re-computers for the circuit's public outputs.
// Mirrors nodash's pack_bytes layout and uses bb.js's poseidon2 so a
// downstream consumer (escrow, registry, test harness) can recompute
// address_commitment / nullifier from raw inputs and match against the
// proof's public outputs.

import { BarretenbergSync } from "@aztec/bb.js";
import { CIRCUIT_DIMS, DELIVERY_CODE_DIMS } from "./types.js";

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

function fieldToByte(fieldHex: string): number {
  const value = BigInt(fieldHex);
  if (value < 0n || value > 255n) {
    throw new Error(`public input byte out of range: ${fieldHex}`);
  }
  return Number(value);
}

function publicByteArrayToString(
  publicInputs: readonly string[],
  start: number,
  len: number,
): string {
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = fieldToByte(publicInputs[start + i]);
  }
  return new TextDecoder().decode(bytes);
}

function publicBoundedVecToString(
  publicInputs: readonly string[],
  start: number,
  max: number,
): string {
  const len = Number(BigInt(publicInputs[start + max]));
  if (len < 0 || len > max) {
    throw new Error(`public BoundedVec len ${len} exceeds max ${max}`);
  }
  return publicByteArrayToString(publicInputs, start, len);
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

// ===== Public-input layout =====
//
// `bin/main.nr` lays its public inputs out in the order shown below;
// the four return-value Fields (PublicOutputs) sit at the tail. This
// mapping lets downstream consumers (frontend prover UI, escrow
// verifier, etc.) decode the structured outputs without duplicating
// the offset arithmetic.

const URL_FIELDS = 1 + CIRCUIT_DIMS.MAX_URL_LEN; // BoundedVec.len + storage
const PARAM_PUBLIC_FIELDS =
  32 + 32 + 32 + URL_FIELDS + 20 + 1 + 4 * 32;
const IDX_ASIN = PARAM_PUBLIC_FIELDS;
const IDX_GRAND_TOTAL = IDX_ASIN + 1;
const IDX_ADDRESS_COMMITMENT = IDX_GRAND_TOTAL + 1;
const IDX_NULLIFIER = IDX_ADDRESS_COMMITMENT + 1;
export const PUBLIC_INPUTS_LENGTH = IDX_NULLIFIER + 1;

export interface DecodedOutputs {
  asin: string;          // 10-byte ASCII, decoded
  grandTotalCents: bigint;
  addressCommitment: bigint;
  nullifier: bigint;
}

// Decode the four public outputs out of a `ProofData.publicInputs`
// array (hex-string Fields). `len` is the ASCII length of the ASIN
// (always 10 for Amazon).
export function decodePublicOutputs(
  publicInputs: readonly string[],
): DecodedOutputs {
  if (publicInputs.length !== PUBLIC_INPUTS_LENGTH) {
    throw new Error(
      `publicInputs length ${publicInputs.length} != expected ${PUBLIC_INPUTS_LENGTH}`,
    );
  }
  return {
    asin: fieldToAsciiString(publicInputs[IDX_ASIN], 10),
    grandTotalCents: BigInt(publicInputs[IDX_GRAND_TOTAL]),
    addressCommitment: BigInt(publicInputs[IDX_ADDRESS_COMMITMENT]),
    nullifier: BigInt(publicInputs[IDX_NULLIFIER]),
  };
}

const DELIVERY_URL_FIELDS = 1 + DELIVERY_CODE_DIMS.MAX_DELIVERY_URL_LEN;
const IDX_DELIVERY_ALLOWED_URL = 32 + 32 + 32;
const IDX_DELIVERY_REQUEST_URL = IDX_DELIVERY_ALLOWED_URL + DELIVERY_URL_FIELDS;
const IDX_DELIVERY_RECIPIENT = IDX_DELIVERY_REQUEST_URL + DELIVERY_URL_FIELDS;
const IDX_DELIVERY_TIMESTAMP = IDX_DELIVERY_RECIPIENT + 20;
const IDX_DELIVERY_HASHES = IDX_DELIVERY_TIMESTAMP + 1;
const IDX_DELIVERY_PICKUP_CODE = IDX_DELIVERY_HASHES + 3 * 32;
const IDX_DELIVERY_ORDER_ID =
  IDX_DELIVERY_PICKUP_CODE + DELIVERY_CODE_DIMS.PICKUP_CODE_BYTES;
export const DELIVERY_CODE_PUBLIC_INPUTS_LENGTH =
  IDX_DELIVERY_ORDER_ID + DELIVERY_CODE_DIMS.ORDER_ID_BYTES;

export interface DecodedDeliveryCodeOutputs {
  allowedUrl: string;
  requestUrl: string;
  pickupCode: string;
  orderId: string;
}

export function decodeDeliveryCodePublicOutputs(
  publicInputs: readonly string[],
): DecodedDeliveryCodeOutputs {
  if (publicInputs.length !== DELIVERY_CODE_PUBLIC_INPUTS_LENGTH) {
    throw new Error(
      `publicInputs length ${publicInputs.length} != expected ${DELIVERY_CODE_PUBLIC_INPUTS_LENGTH}`,
    );
  }
  return {
    allowedUrl: publicBoundedVecToString(
      publicInputs,
      IDX_DELIVERY_ALLOWED_URL,
      DELIVERY_CODE_DIMS.MAX_DELIVERY_URL_LEN,
    ),
    requestUrl: publicBoundedVecToString(
      publicInputs,
      IDX_DELIVERY_REQUEST_URL,
      DELIVERY_CODE_DIMS.MAX_DELIVERY_URL_LEN,
    ),
    pickupCode: publicByteArrayToString(
      publicInputs,
      IDX_DELIVERY_PICKUP_CODE,
      DELIVERY_CODE_DIMS.PICKUP_CODE_BYTES,
    ),
    orderId: publicByteArrayToString(
      publicInputs,
      IDX_DELIVERY_ORDER_ID,
      DELIVERY_CODE_DIMS.ORDER_ID_BYTES,
    ),
  };
}
