// RFC 4648 §10 test vectors, adapted for base64url-no-padding.
//
// The RFC's vectors are standard base64 with `=` padding; convert
// `+` → `-`, `/` → `_`, strip trailing `=` to get the base64url form
// our implementation produces.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as b64u from "../src/base64url.js";

const enc = (s) => new TextEncoder().encode(s);

const VECTORS = [
  // [input, expected base64url-no-padding]
  ["", ""],
  ["f", "Zg"],
  ["fo", "Zm8"],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg"],
  ["fooba", "Zm9vYmE"],
  ["foobar", "Zm9vYmFy"],
];

for (const [input, expected] of VECTORS) {
  test(`RFC 4648 vector encode(${JSON.stringify(input)})`, () => {
    assert.equal(b64u.encode(enc(input)), expected);
  });

  test(`RFC 4648 vector decode(${JSON.stringify(expected)})`, () => {
    const decoded = b64u.decode(expected);
    assert.equal(new TextDecoder().decode(decoded), input);
  });
}

test("round-trip random bytes", () => {
  const random = new Uint8Array(127);
  for (let i = 0; i < random.length; i++) random[i] = (i * 31) & 0xff;
  const encoded = b64u.encode(random);
  // base64url shouldn't ever contain +, /, or = trailing.
  assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  const decoded = b64u.decode(encoded);
  assert.deepEqual(decoded, random);
});

test("decode tolerates standard-base64 + padding", () => {
  // standard base64 of "foob" is "Zm9vYg==". Our decoder must
  // accept both `+/=` and `-_`.
  assert.deepEqual(b64u.decode("Zm9vYg=="), enc("foob"));
  assert.deepEqual(b64u.decode("Zm9vYg"), enc("foob"));
});

test("decode rejects invalid characters", () => {
  assert.throws(() => b64u.decode("not!base64"), /invalid character/);
});

test("decode rejects non-string", () => {
  assert.throws(() => b64u.decode(null), /expects a string/);
});

test("encode tolerates ArrayBuffer + Array inputs", () => {
  const bytes = enc("foobar");
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  assert.equal(b64u.encode(buf), "Zm9vYmFy");
  assert.equal(b64u.encode([102, 111, 111, 98, 97, 114]), "Zm9vYmFy");
});
