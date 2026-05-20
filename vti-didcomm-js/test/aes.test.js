import { test } from "node:test";
import assert from "node:assert/strict";

import * as aes from "../src/aes.js";

test("AES-256-KW wrap/unwrap round-trip (32-byte CEK)", async () => {
  // Legacy size — A128GCM, A256GCM, or A256DIRECT all land here.
  // We don't use these algorithms today, but the wrap/unwrap path
  // must not be silently broken if a caller later supplies a
  // shorter CEK.
  const kek = new Uint8Array(32);
  crypto.getRandomValues(kek);
  const cek = new Uint8Array(32);
  crypto.getRandomValues(cek);

  const wrapped = await aes.wrapKey(kek, cek);
  // RFC 3394: wrapped output is input + 8 bytes.
  assert.equal(wrapped.length, 40);
  assert.notDeepEqual(wrapped.subarray(0, 32), cek, "wrapped must not equal input");

  const unwrapped = await aes.unwrapKey(kek, wrapped);
  assert.deepEqual(unwrapped, cek);
});

test("AES-256-KW wrap/unwrap round-trip (64-byte CEK — A256CBC-HS512)", async () => {
  // This is the operational size: A256CBC-HS512 splits a 64-byte
  // CEK into mac-key || enc-key. The wrap helper has to import the
  // CEK as a CryptoKey that accepts arbitrary lengths (HMAC, not
  // AES-GCM) — this test catches a regression of that.
  const kek = new Uint8Array(32);
  crypto.getRandomValues(kek);
  const cek = new Uint8Array(64);
  crypto.getRandomValues(cek);

  const wrapped = await aes.wrapKey(kek, cek);
  assert.equal(wrapped.length, 72);

  const unwrapped = await aes.unwrapKey(kek, wrapped);
  assert.deepEqual(unwrapped, cek);
});

test("AES-256-KW unwrap with wrong KEK throws", async () => {
  const kek = new Uint8Array(32).fill(0x11);
  const wrongKek = new Uint8Array(32).fill(0x22);
  const cek = new Uint8Array(64).fill(0x33);
  const wrapped = await aes.wrapKey(kek, cek);
  await assert.rejects(aes.unwrapKey(wrongKek, wrapped));
});

test("wrapKey rejects wrong-length KEK", async () => {
  await assert.rejects(
    aes.wrapKey(new Uint8Array(31), new Uint8Array(64)),
    /must be 32 bytes/,
  );
});
