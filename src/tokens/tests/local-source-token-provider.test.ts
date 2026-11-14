import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Realm, RealmKind, SourceTokenRequest, SourceTokenError, SourceTokenFailure, SystemPrincipal } from "@pragmatic-tech-ai/todl-identity";
import { LocalAccountStore } from "../../accounts/local-account-store.js";
import { EncryptedSecretStore } from "../../secrets/encrypted-secret-store.js";
import { LocalSourceTokenProvider } from "../local-source-token-provider.js";

const realm = new Realm("t1", RealmKind.Saas, "Acme");
const R = "resource-a";
const R2 = "resource-b";

class Fixture
{
    public Now = 1_000_000_000_000;
    public readonly Accounts = new LocalAccountStore();
    public readonly Provider = new LocalSourceTokenProvider(this.Accounts, new EncryptedSecretStore(randomBytes(32)), () => new Date(this.Now));

    public async Token(principalId: string, resource: string): Promise<string>
    {
        return (await this.Provider.Acquire(new SourceTokenRequest(realm.Id, principalId, resource))).Value.Reveal();
    }

    public async FailureOf(principalId: string): Promise<SourceTokenFailure | undefined>
    {
        try
        {
            await this.Token(principalId, R);
        }
        catch (e)
        {
            return e instanceof SourceTokenError ? e.Failure : undefined;
        }
        return undefined;
    }
}

test("local source token is per user and verifiable for its resource only", async () =>
{
    const f = new Fixture();
    await f.Accounts.CreateAccount(realm, "alice@x.io", "alice", "r1");
    await f.Accounts.CreateAccount(realm, "bob@x.io", "bob", "r2");
    const alice = await f.Token("alice", R);
    const bob = await f.Token("bob", R);
    assert.equal(await f.Provider.Verify(realm.Id, alice, R), "alice");
    assert.equal(await f.Provider.Verify(realm.Id, alice, R2), null);
    assert.notEqual(alice, bob);
    assert.equal(await f.Provider.Verify(realm.Id, bob, R), "bob");
    f.Now += 301_000;
    assert.equal(await f.Provider.Verify(realm.Id, alice, R), null);
});

test("disabled account cannot acquire a source token", async () =>
{
    const f = new Fixture();
    await f.Accounts.CreateAccount(realm, "dana@x.io", "dana", "r1");
    await f.Accounts.Disable(realm, "dana");
    assert.equal(await f.FailureOf("dana"), SourceTokenFailure.PrincipalInactive);
    assert.equal(await f.FailureOf("ghost"), SourceTokenFailure.PrincipalInactive);
    assert.equal(await f.FailureOf(SystemPrincipal.IdFor(realm.Id)), SourceTokenFailure.UnsupportedPrincipal);
});
