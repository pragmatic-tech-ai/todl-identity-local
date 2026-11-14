import { test } from "node:test";
import assert from "node:assert/strict";
import { Realm, RealmKind, LocalGroupNotFoundError } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../local-account-store.js";

const realm = new Realm("t1", RealmKind.Saas, "Acme");
const other = new Realm("t2", RealmKind.Saas, "Other");

test("groups: create, add, remove, list, and Lookup carries membership", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(realm, "dana@x.io", "dana", "ref");
    await store.CreateGroup(realm, "hr-staff", "HR staff");
    await store.AddMember(realm, "hr-staff", "dana");
    assert.deepEqual((await store.Lookup("dana", realm))?.Groups, ["hr-staff"]);
    await assert.rejects(store.AddMember(realm, "missing", "dana"), LocalGroupNotFoundError);
    await assert.rejects(store.CreateGroup(realm, "hr-staff", "again"));
    await store.CreateGroup(other, "other-group", "Other");
    assert.deepEqual((await store.ListGroups(realm)).map(g => g.GroupId), ["hr-staff"]);
    await store.RemoveMember(realm, "hr-staff", "dana");
    assert.deepEqual((await store.Lookup("dana", realm))?.Groups, []);
});
