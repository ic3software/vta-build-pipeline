import { test } from "node:test";
import assert from "node:assert/strict";

import * as aes from "../src/aes.js";

test("AES-256-KW wrap/unwrap round-trip", async () => {
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

test("AES-256-KW unwrap with wrong KEK throws", async () => {
  const kek = new Uint8Array(32).fill(0x11);
  const wrongKek = new Uint8Array(32).fill(0x22);
  const cek = new Uint8Array(32).fill(0x33);
  const wrapped = await aes.wrapKey(kek, cek);
  await assert.rejects(aes.unwrapKey(wrongKek, wrapped));
});

test("AES-256-GCM encrypt/decrypt round-trip with AAD", async () => {
  const { key, iv } = aes.generateAes256GcmKeyAndIv();
  const aad = new TextEncoder().encode("protected-header-bytes");
  const plaintext = new TextEncoder().encode("hello, didcomm");

  const { ciphertext, tag } = await aes.aesGcmEncrypt({ key, iv, aad, plaintext });
  assert.equal(tag.length, 16);
  assert.equal(ciphertext.length, plaintext.length);

  const decrypted = await aes.aesGcmDecrypt({ key, iv, aad, ciphertext, tag });
  assert.deepEqual(decrypted, plaintext);
});

test("AES-256-GCM decrypt with tampered AAD throws", async () => {
  const { key, iv } = aes.generateAes256GcmKeyAndIv();
  const aad = new TextEncoder().encode("original");
  const plaintext = new TextEncoder().encode("secret payload");
  const { ciphertext, tag } = await aes.aesGcmEncrypt({ key, iv, aad, plaintext });
  await assert.rejects(
    aes.aesGcmDecrypt({
      key,
      iv,
      aad: new TextEncoder().encode("tampered"),
      ciphertext,
      tag,
    }),
  );
});

test("AES-256-GCM decrypt with tampered tag throws", async () => {
  const { key, iv } = aes.generateAes256GcmKeyAndIv();
  const aad = new Uint8Array();
  const plaintext = new TextEncoder().encode("secret payload");
  const { ciphertext, tag } = await aes.aesGcmEncrypt({ key, iv, aad, plaintext });
  const tampered = new Uint8Array(tag);
  tampered[0] ^= 0x01;
  await assert.rejects(
    aes.aesGcmDecrypt({ key, iv, aad, ciphertext, tag: tampered }),
  );
});

test("generateAes256GcmKeyAndIv produces correct lengths", () => {
  const { key, iv } = aes.generateAes256GcmKeyAndIv();
  assert.equal(key.length, 32);
  assert.equal(iv.length, 12);
});

test("wrapKey rejects wrong-length KEK", async () => {
  await assert.rejects(
    aes.wrapKey(new Uint8Array(31), new Uint8Array(32)),
    /must be 32 bytes/,
  );
});
