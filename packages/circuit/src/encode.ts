// Reproduces `@primuslabs/zktls-js-sdk`'s `encodeAttestation` using
// noble hashes (no ethers dep). The SDK does:
//
//   keccak256(solidityPack(
//     ["address","bytes32","bytes32","string","string","uint64","string"],
//     [recipient, keccak256(solidityPack(["string","string","string","string"],
//                                        [url, header, method, body])),
//                keccak256(iterate reponseResolve:
//                            solidityPack(["bytes","string","string","string"],
//                                         [acc, keyName, parseType, parsePath])),
//                data, attConditions, timestamp, additionParams]))
//
// `solidityPack` is `abi.encodePacked` semantics: no length prefixes, no
// padding between items. Types we need:
//   - address: 20 bytes
//   - bytes32: 32 bytes
//   - string:  raw utf-8 bytes
//   - uint64:  8 bytes big-endian
//   - bytes:   raw bytes

// noble-hashes v2 ships ESM subpath exports as `./sha3.js` etc.
import { keccak_256 } from "@noble/hashes/sha3.js";
import type { PrimusAttestationBase } from "./types.js";

// Byte arrays returned by browser `TextEncoder().encode()` and noble hashes
// are declared `Uint8Array<ArrayBufferLike>` (the type TS 5 widens to so
// SharedArrayBuffer is covered). Keep the wider generic throughout so we
// don't have to .slice() copies just to narrow the buffer type.
type Bytes = Uint8Array<ArrayBufferLike>;

function hexToBytes(hex: string): Bytes {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2) throw new Error(`odd-length hex: ${hex}`);
  if (!/^[0-9a-f]*$/i.test(s)) throw new Error(`invalid hex: ${hex}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

function concat(...parts: Bytes[]): Bytes {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function u64BE(n: number | bigint): Bytes {
  const ab = new ArrayBuffer(8);
  const view = new DataView(ab);
  view.setBigUint64(0, BigInt(n), false);
  return new Uint8Array(ab);
}

function addressBytes(addr: string): Bytes {
  const b = hexToBytes(addr);
  if (b.length !== 20) throw new Error(`address must be 20 bytes, got ${b.length}`);
  return b;
}

function encodeRequest(req: PrimusAttestationBase["request"]): Bytes {
  const packed = concat(
    new TextEncoder().encode(req.url),
    new TextEncoder().encode(req.header),
    new TextEncoder().encode(req.method),
    new TextEncoder().encode(req.body),
  );
  return keccak_256(packed);
}

function encodeResponse(rr: PrimusAttestationBase["reponseResolve"]): Bytes {
  // The SDK does rolling keccak: acc starts as "0x" (empty bytes), and each
  // iteration wraps the previous `acc` (as `bytes`) with the next triple.
  // Because "bytes" is packed raw, folding left-to-right is equivalent to
  // concatenating all fields in sequence ahead of the final keccak256.
  let acc: Bytes = new Uint8Array(0);
  for (const r of rr) {
    acc = concat(
      acc,
      new TextEncoder().encode(r.keyName),
      new TextEncoder().encode(r.parseType),
      new TextEncoder().encode(r.parsePath),
    );
  }
  return keccak_256(acc);
}

// Returns the 32-byte keccak256 digest that Primus' attestor signs.
export function encodeAttestation(att: PrimusAttestationBase): Bytes {
  const packed = concat(
    addressBytes(att.recipient),
    encodeRequest(att.request),
    encodeResponse(att.reponseResolve),
    new TextEncoder().encode(att.data),
    new TextEncoder().encode(att.attConditions),
    u64BE(att.timestamp),
    new TextEncoder().encode(att.additionParams),
  );
  return keccak_256(packed);
}
