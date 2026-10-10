import { test } from "node:test";
import assert from "node:assert/strict";
import { Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
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
