import { test } from "node:test";
import assert from "node:assert/strict";
import { Argon2PasswordHasher } from "../argon2-password-hasher.js";

test("hash verifies the correct password and rejects a wrong one", async () =>
{
    const hasher = new Argon2PasswordHasher();
    const stored = await hasher.Hash("hunter2");
    assert.ok(stored.startsWith("$argon2id$"));
    assert.equal(await hasher.Verify("hunter2", stored), true);
    assert.equal(await hasher.Verify("wrong", stored), false);
});

test("verify returns false (never throws) on a malformed stored hash", async () =>
{
    const hasher = new Argon2PasswordHasher();
    assert.equal(await hasher.Verify("x", "not-a-phc-string"), false);
});
