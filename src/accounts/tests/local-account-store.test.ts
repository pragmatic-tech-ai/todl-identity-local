import { test } from "node:test";
import assert from "node:assert/strict";
import { Tenant, TenantKind, LocalAccountNotFoundError } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../local-account-store.js";

const t1 = new Tenant("t1", TenantKind.Saas, "Acme");
const t2 = new Tenant("t2", TenantKind.Saas, "Globex");

test("create then find by email and principal id", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "t1/pwhash/p1");
    const byEmail = await store.FindByEmail(t1, "a@x.io");
    assert.equal(byEmail?.PrincipalId, "p1");
    assert.equal(byEmail?.SecretRef, "t1/pwhash/p1");
    const byId = await store.FindByPrincipalId(t1, "p1");
    assert.equal(byId?.Email, "a@x.io");
});

test("duplicate email in the same tenant throws", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await assert.rejects(() => store.CreateAccount(t1, "a@x.io", "p2", "r2"));
});

test("same email in a different tenant is allowed (tenant isolation)", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await store.CreateAccount(t2, "a@x.io", "p9", "r9");
    assert.equal((await store.FindByPrincipalId(t2, "p9"))?.Email, "a@x.io");
    assert.equal((await store.FindByPrincipalId(t1, "p1"))?.PrincipalId, "p1");
    assert.equal((await store.FindByEmail(t1, "a@x.io"))?.PrincipalId, "p1");
    assert.equal((await store.FindByEmail(t2, "a@x.io"))?.PrincipalId, "p9");
});

test("duplicate principal id in the same tenant throws and leaves maps untouched", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await assert.rejects(() => store.CreateAccount(t1, "b@x.io", "p1", "r2"));
    assert.equal(await store.FindByEmail(t1, "b@x.io"), null);
    assert.equal((await store.FindByPrincipalId(t1, "p1"))?.Email, "a@x.io");
});

test("separator in tenant id or principal id is rejected", async () =>
{
    const store = new LocalAccountStore();
    await assert.rejects(() => store.CreateAccount(new Tenant("a/b", TenantKind.Saas, "X"), "e@x.io", "c", "r"));
    await assert.rejects(() => store.CreateAccount(t1, "e@x.io", "b/c", "r"));
});

test("absent lookups return null", async () =>
{
    const store = new LocalAccountStore();
    assert.equal(await store.FindByEmail(t1, "nobody@x.io"), null);
    assert.equal(await store.Lookup("ghost", t1), null);
});

test("Lookup returns a User principal for an existing account", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    const principal = await store.Lookup("p1", t1);
    assert.equal(principal?.Id, "p1");
    assert.equal(principal?.TenantId, "t1");
});

test("Disable then Lookup returns null, but FindByPrincipalId still returns the record with Disabled=true", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await store.Disable(t1, "p1");
    await store.Disable(t1, "p1");
    assert.equal(await store.Lookup("p1", t1), null);
    assert.equal((await store.FindByPrincipalId(t1, "p1"))?.Disabled, true);
    assert.equal((await store.FindByEmail(t1, "a@x.io"))?.Disabled, true);
});

test("Disable an unknown principal throws LocalAccountNotFoundError", async () =>
{
    const store = new LocalAccountStore();
    await assert.rejects(() => store.Disable(t1, "ghost"), LocalAccountNotFoundError);
});

test("ListAccounts returns only the given tenant's accounts", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await store.CreateAccount(t1, "b@x.io", "p2", "r2");
    await store.CreateAccount(t2, "c@x.io", "p3", "r3");
    assert.deepEqual((await store.ListAccounts(t1)).map(a => a.PrincipalId).sort(), ["p1", "p2"]);
    assert.deepEqual((await store.ListAccounts(t2)).map(a => a.PrincipalId), ["p3"]);
});

test("ListAccounts includes a disabled account with Disabled=true", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await store.Disable(t1, "p1");
    const list = await store.ListAccounts(t1);
    assert.equal(list.length, 1);
    assert.equal(list[0].Disabled, true);
});

test("Enable re-enables a disabled account: Lookup works and Disabled=false", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(t1, "a@x.io", "p1", "r1");
    await store.Disable(t1, "p1");
    await store.Enable(t1, "p1");
    assert.equal((await store.Lookup("p1", t1))?.Id, "p1");
    assert.equal((await store.FindByPrincipalId(t1, "p1"))?.Disabled, false);
    assert.equal((await store.FindByEmail(t1, "a@x.io"))?.Disabled, false);
});

test("Enable an unknown principal throws LocalAccountNotFoundError", async () =>
{
    const store = new LocalAccountStore();
    await assert.rejects(() => store.Enable(t1, "ghost"), LocalAccountNotFoundError);
});
