// Concat KDF unit tests.
//
// The high-confidence vector is the RFC 7518 Appendix C "Example
// ECDH-ES Key Agreement Computation" — same KDF construction we
// implement (JOSE OtherInfo + SHA-256), 128-bit output, well-known
// inputs:
//
//   Z   = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131,
//          191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72,
//          246, 218, 167, 121, 140, 254, 144, 196]
//   alg = "A128GCM"
//   apu = base64url("Alice")  → bytes
//   apv = base64url("Bob")    → bytes
//   keyDataLen = 128 bits
//
//   Expected key = [86, 170, 141, 234, 248, 35, 109, 32,
//                   92, 34, 40, 205, 113, 167, 16, 26]
//   Base64url    = "VqqN6vgjbSBcIijNcacQGg"
//
// If this vector passes, our Concat KDF matches the JOSE spec
// byte-for-byte and we know the JWE pack path will too.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as b64u from "../src/base64url.js";
import {
  concatenate,
  deriveKey,
  lengthPrefix,
  uint32be,
} from "../src/concat-kdf.js";

test("RFC 7518 Appendix C ECDH-ES Concat KDF vector", async () => {
  const z = new Uint8Array([
    158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
    251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144,
    196,
  ]);
  const expected = new Uint8Array([
    86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
  ]);

  const apu = new TextEncoder().encode("Alice");
  const apv = new TextEncoder().encode("Bob");

  const derived = await deriveKey(
    z,
    { alg: "A128GCM", apu, apv },
    128,
  );
  assert.deepEqual(derived, expected);
  assert.equal(b64u.encode(derived), "VqqN6vgjbSBcIijNcacQGg");
});

test("deriveKey produces requested length for multi-block output", async () => {
  // Exercises the counter increment path (reps > 1).
  //
  // JOSE Concat KDF binds keyDataLen into the OtherInfo
  // (SuppPubInfo), so deriving 256 vs 512 bits produces
  // UNRELATED outputs — that's deliberate, it prevents
  // key-length-substitution attacks where a 32-byte CEK might
  // be reused as the first half of a 64-byte one.
  const z = new Uint8Array(32).fill(0xab);
  const apu = new Uint8Array();
  const apv = new Uint8Array();

  const out256 = await deriveKey(z, { alg: "ECDH-1PU+A256KW", apu, apv }, 256);
  assert.equal(out256.length, 32);

  const out512 = await deriveKey(z, { alg: "ECDH-1PU+A256KW", apu, apv }, 512);
  assert.equal(out512.length, 64);
  assert.notDeepEqual(
    out512.subarray(0, 32),
    out256,
    "different keyDataLen → different OtherInfo → different K_1",
  );
  // And block 2 ≠ block 1 within the same derive (counter differs).
  assert.notDeepEqual(out512.subarray(0, 32), out512.subarray(32, 64));
});

test("deriveKey is deterministic across calls", async () => {
  const z = new Uint8Array(32).fill(1);
  const apu = new TextEncoder().encode("Alice");
  const apv = new TextEncoder().encode("Bob");
  const a = await deriveKey(z, { alg: "ECDH-1PU+A256KW", apu, apv }, 256);
  const b = await deriveKey(z, { alg: "ECDH-1PU+A256KW", apu, apv }, 256);
  assert.deepEqual(a, b);
});

test("deriveKey distinguishes apu vs apv (no symmetry bug)", async () => {
  const z = new Uint8Array(32).fill(1);
  const x = new TextEncoder().encode("X");
  const y = new TextEncoder().encode("Y");
  const k1 = await deriveKey(z, { alg: "A", apu: x, apv: y }, 256);
  const k2 = await deriveKey(z, { alg: "A", apu: y, apv: x }, 256);
  assert.notDeepEqual(k1, k2, "swap of apu/apv must change output");
});

test("deriveKey distinguishes alg strings", async () => {
  const z = new Uint8Array(32).fill(1);
  const apu = new Uint8Array();
  const apv = new Uint8Array();
  const a = await deriveKey(z, { alg: "A128GCM", apu, apv }, 256);
  const b = await deriveKey(z, { alg: "A256GCM", apu, apv }, 256);
  assert.notDeepEqual(a, b, "different alg must change output");
});

test("deriveKey rejects non-byte keyDataLenBits", async () => {
  const z = new Uint8Array(32);
  const apu = new Uint8Array();
  const apv = new Uint8Array();
  await assert.rejects(
    deriveKey(z, { alg: "A", apu, apv }, 7),
    /multiple of 8/,
  );
});

test("deriveKey rejects unreasonable keyDataLenBits", async () => {
  const z = new Uint8Array(32);
  const apu = new Uint8Array();
  const apv = new Uint8Array();
  await assert.rejects(deriveKey(z, { alg: "A", apu, apv }, 0), /positive/);
  await assert.rejects(deriveKey(z, { alg: "A", apu, apv }, 1 << 16), /≤ 4096/);
});

test("deriveKey rejects non-Uint8Array inputs", async () => {
  await assert.rejects(
    deriveKey([1, 2, 3], { alg: "A", apu: new Uint8Array(), apv: new Uint8Array() }, 256),
    /Z must be Uint8Array/,
  );
});

// ── Helper tests ───────────────────────────────────────────────────

test("uint32be encodes correctly", () => {
  assert.deepEqual(uint32be(0), new Uint8Array([0, 0, 0, 0]));
  assert.deepEqual(uint32be(1), new Uint8Array([0, 0, 0, 1]));
  assert.deepEqual(uint32be(256), new Uint8Array([0, 0, 1, 0]));
  assert.deepEqual(uint32be(0xdeadbeef), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
});

test("uint32be rejects out-of-range", () => {
  assert.throws(() => uint32be(-1), RangeError);
  assert.throws(() => uint32be(0x100000000), RangeError);
  assert.throws(() => uint32be(1.5), RangeError);
});

test("lengthPrefix prepends 4-byte BE length", () => {
  const data = new TextEncoder().encode("Alice");
  assert.deepEqual(lengthPrefix(data), new Uint8Array([0, 0, 0, 5, 65, 108, 105, 99, 101]));
  assert.deepEqual(lengthPrefix(new Uint8Array()), new Uint8Array([0, 0, 0, 0]));
});

test("concatenate joins multiple Uint8Arrays", () => {
  assert.deepEqual(
    concatenate(new Uint8Array([1]), new Uint8Array([2, 3]), new Uint8Array([4])),
    new Uint8Array([1, 2, 3, 4]),
  );
});
