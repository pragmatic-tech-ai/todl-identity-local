import { test } from "node:test";
import assert from "node:assert/strict";
import { Tenant, TenantKind, LocalGroupNotFoundError } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../local-account-store.js";

const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
const other = new Tenant("t2", TenantKind.Saas, "Other");

test("groups: create, add, remove, list, and Lookup carries membership", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(tenant, "dana@x.io", "dana", "ref");
    await store.CreateGroup(tenant, "hr-staff", "HR staff");
    await store.AddMember(tenant, "hr-staff", "dana");
    assert.deepEqual((await store.Lookup("dana", tenant))?.Groups, ["hr-staff"]);
    await assert.rejects(store.AddMember(tenant, "missing", "dana"), LocalGroupNotFoundError);
    await assert.rejects(store.CreateGroup(tenant, "hr-staff", "again"));
    await store.CreateGroup(other, "other-group", "Other");
    assert.deepEqual((await store.ListGroups(tenant)).map(g => g.GroupId), ["hr-staff"]);
    await store.RemoveMember(tenant, "hr-staff", "dana");
    assert.deepEqual((await store.Lookup("dana", tenant))?.Groups, []);
});
