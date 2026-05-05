// Attestation JSON shape as produced by @primuslabs/zktls-js-sdk's
// `verifyAttestation` callback. Note `reponseResolve` (typo is in the SDK).
// Downloaded frontend fixtures add sidecars through flow-specific types below.

export interface PrimusRequest {
  url: string;
  header: string;
  method: string;
  body: string;
}

export interface PrimusResponseResolve {
  keyName: string;
  parseType: string;
  parsePath: string;
}

export interface PrimusAttestor {
  attestorAddr: string;
  url: string;
}

export interface PrimusAttestationBase {
  recipient: string;
  request: PrimusRequest;
  // typo preserved: this is the key the SDK emits
  reponseResolve: PrimusResponseResolve[];
  data: string; // JSON string: { [keyName]: sha256HexDigest }
  attConditions: string; // JSON string (REVEAL_HEX_STRING entries)
  timestamp: number;
  additionParams: string; // JSON string
  attestors: PrimusAttestor[];
  signatures: string[]; // 0x-prefixed 65-byte hex (r|s|v)
  requestid: string;
}

export interface AmazonOrderSummaryAttestation extends PrimusAttestationBase {
  _plaintexts: {
    shipmentStatus: string;
    productTitle: string;
    shipTo: string;
    grandTotal: string;
  };
}

export interface AmazonDeliveryCodeAttestation extends PrimusAttestationBase {
  _plaintexts: {
    deliveryStatus: string;
    pickupCode: string;
    orderId: string;
  };
  _values: {
    deliveryStatus: string;
    pickupCode: string;
    orderId: string;
  };
}

// What the circuit expects. Fields map 1:1 to `main.nr`'s params.
// Byte-array fields use number[] instead of Uint8Array for cleaner JSON
// snapshots and noir_js InputMap compatibility.
export interface CircuitInputs {
  public_key_x: number[]; // 32
  public_key_y: number[]; // 32
  hash: number[]; // 32
  signature: number[]; // 64 (r|s, no v)
  allowed_url: { storage: number[]; len: number };
  request_url: { storage: number[]; len: number };
  recipient: number[]; // 20
  // Noir u64; noir_js accepts decimal strings here.
  timestamp: string;
  // BoundedVec<u8, MAX_STATUS_NEEDLE_LEN>: literal needle the circuit
  // must find inside shipmentStatus (e.g. ">Delivered " or ">Arriving ").
  expected_status: { storage: number[]; len: number };
  hashes: {
    shipment_status: number[]; // 32
    product_title: number[]; // 32
    ship_to: number[]; // 32
    grand_total: number[]; // 32
  };
  contents: {
    shipment_status: { storage: number[]; len: number };
    product_title: { storage: number[]; len: number };
    ship_to: { storage: number[]; len: number };
    grand_total: { storage: number[]; len: number };
  };
  // Hint: byte offsets and lengths into ship_to.storage for the four
  // trimmed logical lines, in order [name, street, city_state_zip, country].
  ship_to_hints: {
    offsets: number[]; // 4
    lens: number[]; // 4
  };
  // Hint: number of bytes between `>$` and `<` in grandTotal.
  grand_total_len: number;
}

export interface DeliveryCodeCircuitInputs {
  public_key_x: number[]; // 32
  public_key_y: number[]; // 32
  hash: number[]; // 32
  signature: number[]; // 64 (r|s, no v)
  allowed_url: { storage: number[]; len: number };
  // Public full ship-track URL.
  request_url: { storage: number[]; len: number };
  recipient: number[]; // 20
  timestamp: string;
  hashes: {
    delivery_status: number[]; // 32
    pickup_code: number[]; // 32
    order_id: number[]; // 32
  };
  contents: {
    delivery_status: { storage: number[]; len: number };
    pickup_code: { storage: number[]; len: number };
    order_id: { storage: number[]; len: number };
  };
}

export type AnyCircuitInputs = CircuitInputs | DeliveryCodeCircuitInputs;

// Circuit parameters that must stay in sync with `lib/src/lib.nr`.
export const CIRCUIT_DIMS = {
  MAX_URL_LEN: 128,
  MAX_SHIPMENT_STATUS_LEN: 256,
  MAX_PRODUCT_TITLE_LEN: 1024,
  MAX_SHIP_TO_LEN: 1024,
  MAX_GRAND_TOTAL_LEN: 128,
  MAX_NAME_LEN: 64,
  MAX_STREET_LEN: 96,
  MAX_CITY_STATE_ZIP_LEN: 96,
  MAX_COUNTRY_LEN: 32,
  // Cap on the number of bytes between `>$` and `<` in grandTotal
  // (digits + thousands-commas + decimal period).
  MAX_GRAND_TOTAL_DIGITS: 13,
  // Max bytes in the shipment-status needle (">Delivered ",
  // ">Arriving ", future variants). Must stay <= 32 to fit SubString32.
  MAX_STATUS_NEEDLE_LEN: 16,
} as const;

export const DELIVERY_CODE_DIMS = {
  MAX_DELIVERY_URL_LEN: 256,
  MAX_DELIVERY_STATUS_LEN: 128,
  MAX_PICKUP_CODE_HTML_LEN: 128,
  MAX_DELIVERY_ORDER_ID_HTML_LEN: 256,
  PICKUP_CODE_BYTES: 6,
  ORDER_ID_BYTES: 19,
} as const;

// Canonical status needles: byte-identical to the strings the Noir
// circuit substring-matches against. Pass via `expectedStatusBytes`.
export const EXPECTED_STATUS = {
  delivered: ">Delivered ",
  arriving: ">Arriving ",
} as const;
export type ExpectedStatusKind = keyof typeof EXPECTED_STATUS;

export function expectedStatusBytes(
  kind: ExpectedStatusKind,
): { storage: number[]; len: number } {
  const literal = EXPECTED_STATUS[kind];
  const bytes = new TextEncoder().encode(literal);
  if (bytes.length > CIRCUIT_DIMS.MAX_STATUS_NEEDLE_LEN) {
    throw new Error(
      `expected_status '${literal}' is ${bytes.length} bytes, exceeds MAX=${CIRCUIT_DIMS.MAX_STATUS_NEEDLE_LEN}`,
    );
  }
  const storage = new Array<number>(CIRCUIT_DIMS.MAX_STATUS_NEEDLE_LEN).fill(0);
  for (let i = 0; i < bytes.length; i++) storage[i] = bytes[i];
  return { storage, len: bytes.length };
}

// Field names (Noir snake_case) mapped to the Primus SDK's camelCase keyName
// from the template. Handy when walking `attestation.data` / `_plaintexts`.
export const FIELD_MAP = {
  shipment_status: "shipmentStatus",
  product_title: "productTitle",
  ship_to: "shipTo",
  grand_total: "grandTotal",
} as const;

export type FieldKey = keyof typeof FIELD_MAP;

export const DELIVERY_CODE_FIELD_MAP = {
  delivery_status: "deliveryStatus",
  pickup_code: "pickupCode",
  order_id: "orderId",
} as const;

export type DeliveryCodeFieldKey = keyof typeof DELIVERY_CODE_FIELD_MAP;
