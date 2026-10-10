import { test } from "node:test";
import assert from "node:assert/strict";

// Baseline resolution guard: the contracts package resolves from its root barrel
// (compiled dist) and the hash-wasm crypto dependency resolves. Pins the file:
// dependency on ../todl-identity and the hash-wasm registry dependency.
import { PresentedSecret, AuthMethod } from "@pragmatic-tech-ai/todl-identity";
import { argon2id } from "hash-wasm";

test("todl-identity root barrel resolves the authN contracts the pack needs", () =>
{
    const secret = new PresentedSecret("x");
    assert.equal(secret.Reveal(), "x");
    assert.equal(AuthMethod.Local, 1);
});

test("hash-wasm argon2id resolves", () =>
{
    assert.equal(typeof argon2id, "function");
});
