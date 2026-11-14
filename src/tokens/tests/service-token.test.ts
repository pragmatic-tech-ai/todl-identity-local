import { test } from "node:test";
import assert from "node:assert/strict";
import { Realm, RealmKind, Credential, PresentedSecret, AuthMethod, AuthenticatedResult, RejectedResult, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import { ServiceTokenStore } from "../service-token-store.js";
import { ServiceTokenAuthenticator } from "../service-token-authenticator.js";

const realm = new Realm("t1", RealmKind.Saas, "Acme");

test("issue then authenticate yields a Service principal whose Groups are the scopes", async () =>
{
    const store = new ServiceTokenStore();
    const { Grant, Token } = await store.Issue(realm, "svc1", ["read:models", "write:models"], null);
    assert.ok(Token.length >= 40);
    const auth = new ServiceTokenAuthenticator(store);
    const result = await auth.Authenticate(new Credential(AuthMethod.ServiceToken, Grant.TokenRef), new PresentedSecret(Token), realm);
    assert.ok(result instanceof AuthenticatedResult);
    assert.equal((result as AuthenticatedResult).Principal.Kind, PrincipalKind.Service);
    assert.deepEqual([...(result as AuthenticatedResult).Principal.Groups].sort(), ["read:models", "write:models"]);
});

test("resolve after revoke returns null (authenticate rejects)", async () =>
{
    const store = new ServiceTokenStore();
    const { Grant, Token } = await store.Issue(realm, "svc1", ["read:models"], null);
    await store.Revoke(realm, Grant.TokenRef);
    assert.equal(await store.Resolve(realm, new PresentedSecret(Token)), null);
    const auth = new ServiceTokenAuthenticator(store);
    assert.ok((await auth.Authenticate(new Credential(AuthMethod.ServiceToken, Grant.TokenRef), new PresentedSecret(Token), realm)) instanceof RejectedResult);
});

test("resolve of an expired token returns null", async () =>
{
    let t = 1_000_000;
    const store = new ServiceTokenStore(() => new Date(t));
    const { Token } = await store.Issue(realm, "svc1", ["read:models"], new Date(t + 1000));
    t += 2000;
    assert.equal(await store.Resolve(realm, new PresentedSecret(Token)), null);
});

test("resolve of a bogus token returns null", async () =>
{
    const store = new ServiceTokenStore();
    assert.equal(await store.Resolve(realm, new PresentedSecret("nope")), null);
});

test("resolve under the wrong realm returns null", async () =>
{
    const store = new ServiceTokenStore();
    const { Token } = await store.Issue(realm, "svc1", ["read:models"], null);
    const other = new Realm("t2", RealmKind.Saas, "Globex");
    assert.equal(await store.Resolve(other, new PresentedSecret(Token)), null);
});

test("token is expired at exactly its expiry instant but valid one ms before", async () =>
{
    const t0 = 1_000_000;
    let t = t0;
    const store = new ServiceTokenStore(() => new Date(t));
    const { Token } = await store.Issue(realm, "svc1", ["read:models"], new Date(t0 + 1000));
    t = t0 + 999;
    assert.notEqual(await store.Resolve(realm, new PresentedSecret(Token)), null);
    t = t0 + 1000;
    assert.equal(await store.Resolve(realm, new PresentedSecret(Token)), null);
});

test("a different realm cannot revoke another realm's token by ref", async () =>
{
    const store = new ServiceTokenStore();
    const { Grant, Token } = await store.Issue(realm, "svc1", ["read:models"], null);
    const other = new Realm("t2", RealmKind.Saas, "Globex");
    await store.Revoke(other, Grant.TokenRef);
    assert.notEqual(await store.Resolve(realm, new PresentedSecret(Token)), null);
});

test("List returns only the realm's tokens", async () =>
{
    const store = new ServiceTokenStore();
    const other = new Realm("t2", RealmKind.Saas, "Globex");
    const mine = await store.Issue(realm, "svc1", ["read:models"], null);
    await store.Issue(other, "svc2", ["x"], null);
    const list = await store.List(realm);
    assert.equal(list.length, 1);
    assert.equal(list[0].TokenRef, mine.Grant.TokenRef);
    assert.equal(list[0].PrincipalId, "svc1");
    assert.equal(list[0].Revoked, false);
    assert.equal((await store.List(other)).length, 1);
});

test("List surfaces Revoked=true after Revoke", async () =>
{
    const store = new ServiceTokenStore();
    const { Grant } = await store.Issue(realm, "svc1", ["read:models"], null);
    await store.Revoke(realm, Grant.TokenRef);
    assert.equal((await store.List(realm))[0].Revoked, true);
});

test("List never exposes the raw token", async () =>
{
    const store = new ServiceTokenStore();
    const { Token } = await store.Issue(realm, "svc1", ["read:models"], null);
    assert.ok(!JSON.stringify(await store.List(realm)).includes(Token));
});
