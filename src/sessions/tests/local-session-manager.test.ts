import { test } from "node:test";
import assert from "node:assert/strict";
import { Principal, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import { LocalSessionManager } from "../local-session-manager.js";

const principal = new Principal("p1", "t1", PrincipalKind.User, new Map(), []);

test("issue then validate round-trips", async () =>
{
    const sessions = new LocalSessionManager();
    const session = await sessions.Issue(principal);
    const validated = await sessions.Validate(session.Id);
    assert.equal(validated?.PrincipalId, "p1");
    assert.equal(validated?.TenantId, "t1");
});

test("validate after revoke returns null", async () =>
{
    const sessions = new LocalSessionManager();
    const session = await sessions.Issue(principal);
    await sessions.Revoke(session.Id);
    assert.equal(await sessions.Validate(session.Id), null);
});

test("validate after expiry returns null", async () =>
{
    let t = 1_000_000;
    const sessions = new LocalSessionManager(1000, () => new Date(t));
    const session = await sessions.Issue(principal);
    t += 2000;
    assert.equal(await sessions.Validate(session.Id), null);
});

test("validate of a never-issued token returns null", async () =>
{
    const sessions = new LocalSessionManager();
    assert.equal(await sessions.Validate("bogus-token"), null);
});

test("the raw token is not stored as a key", async () =>
{
    const sessions = new LocalSessionManager();
    const session = await sessions.Issue(principal);
    assert.ok(session.Id.length >= 40);
    assert.ok(await sessions.Validate(session.Id) !== null);
});

test("RevokeAllFor revokes every session of that principal and leaves others", async () =>
{
    const sessions = new LocalSessionManager();
    const other = new Principal("p2", "t1", PrincipalKind.User, new Map(), []);
    const a1 = await sessions.Issue(principal);
    const a2 = await sessions.Issue(principal);
    const b = await sessions.Issue(other);
    await sessions.RevokeAllFor("p1");
    assert.equal(await sessions.Validate(a1.Id), null);
    assert.equal(await sessions.Validate(a2.Id), null);
    assert.equal((await sessions.Validate(b.Id))?.PrincipalId, "p2");
});
