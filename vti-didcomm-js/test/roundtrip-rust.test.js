// Round-trip JS pack → Rust unpack via `vti-didcomm-roundtrip-helper`.
//
// This is the load-bearing proof that our JS authcrypt
// implementation is byte-equivalent with `affinidi-messaging-didcomm`:
// every detail (Concat KDF inputs, APU/APV bytes, JWE protected
// header canonicalization, base64url encoding, AES-KW + AES-GCM
// wire bytes) must match the Rust crate for unpack to succeed.
//
// Skips itself with a clear message if the helper binary isn't
// built — `cargo build -p vti-didcomm-roundtrip-helper` from the
// workspace root.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import * as b64u from "../src/base64url.js";
import * as jwk from "../src/jwk.js";
import { pack } from "../src/pack.js";
import * as x25519 from "../src/x25519.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Resolve the helper binary path. Cargo target dir may be set via
 *  CARGO_TARGET_DIR env var, otherwise it's `target/` at the
 *  workspace root.
 */
function helperPath() {
  const targetDir =
    process.env.CARGO_TARGET_DIR ||
    resolve(HERE, "..", "..", "target");
  return resolve(targetDir, "debug", "didcomm-unpack");
}

/** Drive the Rust helper with a request, return the parsed response. */
function rustUnpack(req) {
  return new Promise((resolveResult, rejectResult) => {
    const child = spawn(helperPath(), [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString("utf8")));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString("utf8")));
    child.on("error", rejectResult);
    child.on("close", (code) => {
      if (code !== 0) {
        rejectResult(
          new Error(`didcomm-unpack exited ${code}; stderr: ${stderr.trim()}`),
        );
        return;
      }
      try {
        resolveResult(JSON.parse(stdout));
      } catch (e) {
        rejectResult(new Error(`bad helper stdout: ${e.message}\n${stdout}`));
      }
    });
    child.stdin.end(JSON.stringify(req));
  });
}

const HELPER_AVAILABLE = existsSync(helperPath());

if (!HELPER_AVAILABLE) {
  test("Rust round-trip helper not built — skipping", { skip: true }, () => {});
} else {
  test("JS pack → Rust unpack: simple message", async () => {
    const ephem = x25519.generateKeyPair(); // not used; just here for symmetry
    void ephem;
    const sender = x25519.generateKeyPair();
    const recipient = x25519.generateKeyPair();

    const senderKid = "did:key:zSenderAlice#x25519-1";
    const recipientKid = "did:key:zRecipientBob#x25519-1";

    const message = {
      id: "msg-rust-roundtrip-1",
      type: "https://example.com/test/1.0",
      from: senderKid.split("#")[0],
      to: [recipientKid.split("#")[0]],
      body: { hello: "didcomm-rust" },
      created_time: 1700000000,
    };

    const jwe = await pack({
      message,
      sender: {
        kid: senderKid,
        privateJwk: jwk.privateJwk(
          "X25519",
          sender.privateKey,
          sender.publicKey,
          senderKid,
        ),
      },
      recipient: {
        kid: recipientKid,
        publicJwk: jwk.publicJwk(
          "X25519",
          recipient.publicKey,
          recipientKid,
        ),
      },
    });

    const resp = await rustUnpack({
      jwe,
      recipient_kid: recipientKid,
      recipient_private_x_b64u: b64u.encode(recipient.privateKey),
      sender_public_x_b64u: b64u.encode(sender.publicKey),
    });

    assert.equal(resp.ok, true, `Rust unpack failed: ${JSON.stringify(resp)}`);
    assert.equal(resp.kind, "encrypted");
    assert.equal(resp.authenticated, true, "authcrypt → authenticated must be true");
    assert.equal(resp.recipient_kid, recipientKid);
    assert.equal(resp.sender_kid, senderKid);
    // The plaintext we packed should come back byte-for-byte.
    assert.deepEqual(resp.plaintext, message);
  });

  test("JS pack → Rust unpack: 4 KB body", async () => {
    const sender = x25519.generateKeyPair();
    const recipient = x25519.generateKeyPair();
    const senderKid = "did:key:zSender#x";
    const recipientKid = "did:key:zRecipient#x";

    const big = "x".repeat(4096);
    const message = {
      id: "msg-big",
      type: "test/1.0",
      from: senderKid.split("#")[0],
      to: [recipientKid.split("#")[0]],
      body: { data: big },
    };

    const jwe = await pack({
      message,
      sender: {
        kid: senderKid,
        privateJwk: jwk.privateJwk("X25519", sender.privateKey, sender.publicKey, senderKid),
      },
      recipient: {
        kid: recipientKid,
        publicJwk: jwk.publicJwk("X25519", recipient.publicKey, recipientKid),
      },
    });

    const resp = await rustUnpack({
      jwe,
      recipient_kid: recipientKid,
      recipient_private_x_b64u: b64u.encode(recipient.privateKey),
      sender_public_x_b64u: b64u.encode(sender.publicKey),
    });

    assert.equal(resp.ok, true, `Rust unpack failed: ${JSON.stringify(resp)}`);
    assert.equal(resp.plaintext.body.data, big);
  });

  test("Rust unpack rejects when sender_public is wrong (auth check)", async () => {
    // Pin that the Rust side's authcrypt verification actually
    // catches a sender-key mismatch — if THIS test passes, the
    // Rust side is doing real cryptographic sender attribution
    // (not just decrypting and trusting `skid`).
    const sender = x25519.generateKeyPair();
    const otherSender = x25519.generateKeyPair();
    const recipient = x25519.generateKeyPair();
    const senderKid = "did:key:zSender#x";
    const recipientKid = "did:key:zRecipient#x";

    const message = { id: "m", type: "t", body: {} };
    const jwe = await pack({
      message,
      sender: {
        kid: senderKid,
        privateJwk: jwk.privateJwk("X25519", sender.privateKey, sender.publicKey, senderKid),
      },
      recipient: {
        kid: recipientKid,
        publicJwk: jwk.publicJwk("X25519", recipient.publicKey, recipientKid),
      },
    });

    const resp = await rustUnpack({
      jwe,
      recipient_kid: recipientKid,
      recipient_private_x_b64u: b64u.encode(recipient.privateKey),
      // WRONG sender public key.
      sender_public_x_b64u: b64u.encode(otherSender.publicKey),
    });

    assert.equal(resp.ok, false, "Rust unpack must reject wrong sender_public");
  });

  test("Rust unpack rejects when recipient_private is wrong", async () => {
    const sender = x25519.generateKeyPair();
    const recipient = x25519.generateKeyPair();
    const eve = x25519.generateKeyPair();
    const senderKid = "did:key:zSender#x";
    const recipientKid = "did:key:zRecipient#x";

    const message = { id: "m", type: "t", body: { secret: "shh" } };
    const jwe = await pack({
      message,
      sender: {
        kid: senderKid,
        privateJwk: jwk.privateJwk("X25519", sender.privateKey, sender.publicKey, senderKid),
      },
      recipient: {
        kid: recipientKid,
        publicJwk: jwk.publicJwk("X25519", recipient.publicKey, recipientKid),
      },
    });

    const resp = await rustUnpack({
      jwe,
      recipient_kid: recipientKid,
      recipient_private_x_b64u: b64u.encode(eve.privateKey),
      sender_public_x_b64u: b64u.encode(sender.publicKey),
    });

    assert.equal(resp.ok, false, "Rust unpack must reject wrong recipient_private");
  });
}
