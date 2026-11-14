import { test } from "node:test";
import assert from "node:assert/strict";
import { Grant, ResourceRef, ResourceKind, Role, Realm, RealmKind } from "@pragmatic-tech-ai/todl-identity";
import { InMemoryRoleGrantStore } from "../in-memory-role-grant-store.js";

class Fixture
{
    public static readonly Realm = new Realm("t1", RealmKind.Saas, "Acme");

    public static Grant(subject: string, role: Role, path: string[]): Grant
    {
        return new Grant(subject, role, new ResourceRef(ResourceKind.Project, "t1", path));
    }
}

test("Revoke removes the matching grant", async () =>
{
    const store = new InMemoryRoleGrantStore();
    await store.Save(Fixture.Grant("u1", Role.Editor, ["a", "b"]));
    await store.Revoke(Fixture.Grant("u1", Role.Editor, ["a", "b"]));
    assert.equal((await store.GrantsFor("u1", Fixture.Realm)).length, 0);
});

test("Revoke leaves a different grant", async () =>
{
    const store = new InMemoryRoleGrantStore();
    await store.Save(Fixture.Grant("u1", Role.Editor, ["a", "b"]));
    await store.Save(Fixture.Grant("u1", Role.Viewer, ["a", "b"]));
    await store.Save(Fixture.Grant("u1", Role.Editor, ["a"]));
    await store.Revoke(Fixture.Grant("u1", Role.Editor, ["a", "b"]));
    const grants = await store.GrantsFor("u1", Fixture.Realm);
    assert.equal(grants.length, 2);
    assert.ok(grants.some(g => g.Role === Role.Viewer));
    assert.ok(grants.some(g => g.Resource.Path.length === 1));
});

test("Revoke is a no-op when nothing matches", async () =>
{
    const store = new InMemoryRoleGrantStore();
    await store.Save(Fixture.Grant("u1", Role.Editor, ["a"]));
    await store.Revoke(Fixture.Grant("u1", Role.Owner, ["a"]));
    await store.Revoke(Fixture.Grant("u2", Role.Editor, ["a"]));
    assert.equal((await store.GrantsFor("u1", Fixture.Realm)).length, 1);
});

test("GrantsOn returns only exact-resource grants for the queried realm", async () =>
{
    const store = new InMemoryRoleGrantStore();
    const root1 = new ResourceRef(ResourceKind.Realm, "t1", []);
    const root2 = new ResourceRef(ResourceKind.Realm, "t2", []);
    await store.Save(new Grant("u1", Role.Owner, root1));
    await store.Save(new Grant("u2", Role.Admin, root1));
    await store.Save(new Grant("u3", Role.Owner, root2));
    await store.Save(Fixture.Grant("u4", Role.Editor, ["a"]));
    const grants = await store.GrantsOn(root1);
    assert.deepEqual(grants.map(g => g.Subject).sort(), ["u1", "u2"]);
});
