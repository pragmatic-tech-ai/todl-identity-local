import { test } from "node:test";
import assert from "node:assert/strict";
import { Tenant, TenantKind, IdpDirectoryRequest, IdpUserState } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../../accounts/local-account-store.js";
import { LocalDirectorySource } from "../local-directory-source.js";

const tenant = new Tenant("t1", TenantKind.Saas, "Acme");

test("directory source reports enabled, disabled, deleted and group members", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(tenant, "alice@x.io", "alice", "r1");
    await store.CreateAccount(tenant, "dana@x.io", "dana", "r2");
    await store.Disable(tenant, "dana");
    await store.CreateGroup(tenant, "hr-staff", "HR");
    await store.AddMember(tenant, "hr-staff", "alice");
    const source = new LocalDirectorySource(store, store);
    const snapshot = await source.Snapshot(tenant, new IdpDirectoryRequest(["hr-staff", "none"], ["alice", "dana", "ghost"]));
    assert.equal(source.Authoritative, true);
    assert.equal(snapshot.Authoritative, true);
    assert.equal(snapshot.StateOf("alice"), IdpUserState.Enabled);
    assert.equal(snapshot.StateOf("dana"), IdpUserState.Disabled);
    assert.equal(snapshot.StateOf("ghost"), IdpUserState.Deleted);
    assert.deepEqual(snapshot.MembersOf("hr-staff"), ["alice"]);
    assert.deepEqual(snapshot.MembersOf("none"), []);
});
