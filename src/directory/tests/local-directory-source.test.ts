import { test } from "node:test";
import assert from "node:assert/strict";
import { Realm, RealmKind, IdpDirectoryRequest, IdpUserState } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../../accounts/local-account-store.js";
import { LocalDirectorySource } from "../local-directory-source.js";

const realm = new Realm("t1", RealmKind.Saas, "Acme");

test("directory source reports enabled, disabled, deleted and group members", async () =>
{
    const store = new LocalAccountStore();
    await store.CreateAccount(realm, "alice@x.io", "alice", "r1");
    await store.CreateAccount(realm, "dana@x.io", "dana", "r2");
    await store.Disable(realm, "dana");
    await store.CreateGroup(realm, "hr-staff", "HR");
    await store.AddMember(realm, "hr-staff", "alice");
    await store.CreateAccount(realm, "erin@x.io", "erin", "r3");
    await store.Disable(realm, "erin");
    await store.AddMember(realm, "hr-staff", "erin");
    const source = new LocalDirectorySource(store, store);
    const snapshot = await source.Snapshot(realm, new IdpDirectoryRequest(["hr-staff", "none"], ["alice", "dana", "ghost"]));
    assert.equal(source.Authoritative, true);
    assert.equal(snapshot.Authoritative, true);
    assert.equal(snapshot.StateOf("alice"), IdpUserState.Enabled);
    assert.equal(snapshot.StateOf("dana"), IdpUserState.Disabled);
    assert.equal(snapshot.StateOf("ghost"), IdpUserState.Deleted);
    assert.equal(snapshot.StateOf("erin"), IdpUserState.Disabled);
    assert.deepEqual(snapshot.MembersOf("hr-staff"), ["alice", "erin"]);
    assert.deepEqual(snapshot.MembersOf("none"), []);
});
