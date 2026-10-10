import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { EncryptedSecretStore } from "../encrypted-secret-store.js";

test("put/get round-trips and delete removes", async () =>
{
    const store = new EncryptedSecretStore(randomBytes(32));
    await store.Put("t1/k", "s3cret");
    assert.equal(await store.Get("t1/k"), "s3cret");
    await store.Delete("t1/k");
    assert.equal(await store.Get("t1/k"), null);
});

test("absent key returns null, never throws", async () =>
{
    const store = new EncryptedSecretStore(randomBytes(32));
    assert.equal(await store.Get("missing"), null);
});

test("same secret under two keys both round-trip (random nonce per put)", async () =>
{
    const entries = new Map<string, string>();
    const store = new EncryptedSecretStore(randomBytes(32), entries);
    await store.Put("a", "same");
    await store.Put("b", "same");
    assert.equal(await store.Get("a"), "same");
    assert.equal(await store.Get("b"), "same");
    assert.notEqual(entries.get("a"), entries.get("b"));
});

test("a non-32-byte master key is rejected", () =>
{
    assert.throws(() => new EncryptedSecretStore(randomBytes(16)));
});

test("FromBase64 builds a working store", async () =>
{
    const store = EncryptedSecretStore.FromBase64(randomBytes(32).toString("base64"));
    await store.Put("k", "v");
    assert.equal(await store.Get("k"), "v");
});

test("a tampered blob fails closed: Get returns null, never throws", async () =>
{
    const entries = new Map<string, string>();
    const store = new EncryptedSecretStore(randomBytes(32), entries);
    await store.Put("k", "v");
    const raw = Buffer.from(entries.get("k")!, "base64url");
    raw[raw.length - 1] ^= 0x01;
    entries.set("k", raw.toString("base64url"));
    assert.equal(await store.Get("k"), null);
});

test("a blob written under a different key reads as null", async () =>
{
    const entries = new Map<string, string>();
    await new EncryptedSecretStore(randomBytes(32), entries).Put("k", "v");
    assert.equal(await new EncryptedSecretStore(randomBytes(32), entries).Get("k"), null);
});

test("structurally truncated blobs read as null", async () =>
{
    const entries = new Map<string, string>();
    const store = new EncryptedSecretStore(randomBytes(32), entries);
    await store.Put("k", "v");
    entries.set("k", randomBytes(12).toString("base64url"));
    assert.equal(await store.Get("k"), null);
    entries.set("k", Buffer.concat([randomBytes(12), randomBytes(4)]).toString("base64url"));
    assert.equal(await store.Get("k"), null);
    entries.set("k", "");
    assert.equal(await store.Get("k"), null);
});
