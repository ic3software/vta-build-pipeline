// Multibase + multikey round-trip tests.
//
// Pins the wire shapes against:
//   - Multibase spec test vectors (https://github.com/multiformats/multibase)
//   - A real did:key Ed25519 from the workspace (so we know the
//     full pipeline — varint prefix + base58btc — matches what
//     `did:key:z…` resolvers produce).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MULTICODEC,
  base58btcDecode,
  base58btcEncode,
  decodeMultikey,
  encodeMultikey,
} from "../src/multibase.js";

const enc = (s) => new TextEncoder().encode(s);

// Multibase project's base58btc test vectors (from `tests/base58btc.csv`).
const B58_VECTORS = [
  ["yes mani !", "7paNL19xttacUY"],
  ["hello world", "StV1DL6CwTryKyV"],
  // "\x00yes mani !" — leading null bytes preserved as '1'
  [null, "17paNL19xttacUY", new Uint8Array([0, ...enc("yes mani !")])],
];

for (const [text, encoded, expectedBytes] of B58_VECTORS) {
  const input = expectedBytes ?? enc(text);
  test(`base58btc encode (${JSON.stringify(text ?? "<bytes>")})`, () => {
    assert.equal(base58btcEncode(input), encoded);
  });
  test(`base58btc decode (${JSON.stringify(encoded)})`, () => {
    assert.deepEqual(base58btcDecode(encoded), input);
  });
}

test("base58btc encode handles empty input", () => {
  assert.equal(base58btcEncode(new Uint8Array()), "");
});

test("base58btc round-trip across many random byte sequences", () => {
  for (let len = 1; len <= 64; len++) {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = (i * 17 + len) & 0xff;
    const encoded = base58btcEncode(bytes);
    const decoded = base58btcDecode(encoded);
    assert.deepEqual(decoded, bytes, `round-trip failed at len=${len}`);
  }
});

test("base58btc decode rejects invalid character", () => {
  // '0', 'O', 'I', 'l' are intentionally not in the base58btc alphabet.
  assert.throws(() => base58btcDecode("0OIl"), /invalid char/);
});

// ── Multikey wrapping (multicodec varint + base58btc + 'z' prefix) ──

test("Ed25519 multikey round-trip preserves bytes", () => {
  const pk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) pk[i] = i;
  const s = encodeMultikey(MULTICODEC.ED25519_PUB, pk);
  assert.ok(s.startsWith("z"));
  const { codec, key } = decodeMultikey(s);
  assert.deepEqual(codec, MULTICODEC.ED25519_PUB);
  assert.deepEqual(key, pk);
});

test("X25519 multikey round-trip preserves bytes", () => {
  const pk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) pk[i] = 31 - i;
  const s = encodeMultikey(MULTICODEC.X25519_PUB, pk);
  const { codec, key } = decodeMultikey(s);
  assert.deepEqual(codec, MULTICODEC.X25519_PUB);
  assert.deepEqual(key, pk);
});

test("P-256 multikey round-trip preserves bytes", () => {
  // 33-byte compressed point — multicodec p256-pub is 0x80 0x24.
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  for (let i = 1; i < 33; i++) compressed[i] = i * 7;
  const s = encodeMultikey(MULTICODEC.P256_PUB, compressed);
  const { codec, key } = decodeMultikey(s);
  assert.deepEqual(codec, MULTICODEC.P256_PUB);
  assert.deepEqual(key, compressed);
});

test("decodeMultikey rejects strings without 'z' prefix", () => {
  assert.throws(() => decodeMultikey("notamultibase"), /must be base58btc multibase/);
});

test("real did:key Ed25519 strings decode + re-encode losslessly", () => {
  // Pin byte-equivalence of decode → encode for a handful of
  // known `did:key:z…` Ed25519 examples. We don't assert specific
  // decoded bytes here (the spec examples are easy to mis-transcribe);
  // the codec-identification + round-trip together pin the wire shape.
  const samples = [
    "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "z6MkpTHR8VNsBxYAAWHut2Geadd9jSruqfoeAvUUkfWGZpaP",
    "z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T",
  ];
  for (const did of samples) {
    const { codec, key } = decodeMultikey(did);
    assert.deepEqual(codec, MULTICODEC.ED25519_PUB);
    assert.equal(key.length, 32, `${did}: Ed25519 public key must be 32 bytes`);
    assert.equal(
      encodeMultikey(MULTICODEC.ED25519_PUB, key),
      did,
      `round-trip failed for ${did}`,
    );
  }
});
