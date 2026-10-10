import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Tenant, TenantKind, Credential, PresentedSecret, AuthMethod, AuthenticatedResult, RejectedResult } from "@pragmatic-tech-ai/todl-identity";
import { Argon2PasswordHasher } from "../../hashing/argon2-password-hasher.js";
import { EncryptedSecretStore } from "../../secrets/encrypted-secret-store.js";
import { LocalAccountStore } from "../../accounts/local-account-store.js";
import { LocalPasswordAuthenticator } from "../local-password-authenticator.js";

const tenant = new Tenant("t1", TenantKind.Saas, "Acme");

async function register(accounts: LocalAccountStore, secrets: EncryptedSecretStore, hasher: Argon2PasswordHasher, email: string, principalId: string, password: string): Promise<void>
{
    const ref = "t1/pwhash/" + principalId;
    await secrets.Put(ref, await hasher.Hash(password));
    await accounts.CreateAccount(tenant, email, principalId, ref);
}

test("correct password authenticates to the right principal", async () =>
{
    const accounts = new LocalAccountStore(); const secrets = new EncryptedSecretStore(randomBytes(32)); const hasher = new Argon2PasswordHasher();
    await register(accounts, secrets, hasher, "a@x.io", "p1", "hunter2");
    const auth = new LocalPasswordAuthenticator(accounts, secrets, hasher);
    const result = await auth.Authenticate(new Credential(AuthMethod.Local, "a@x.io"), new PresentedSecret("hunter2"), tenant);
    assert.ok(result instanceof AuthenticatedResult);
    assert.equal((result as AuthenticatedResult).Principal.Id, "p1");
});

test("wrong password is rejected", async () =>
{
    const accounts = new LocalAccountStore(); const secrets = new EncryptedSecretStore(randomBytes(32)); const hasher = new Argon2PasswordHasher();
    await register(accounts, secrets, hasher, "a@x.io", "p1", "hunter2");
    const auth = new LocalPasswordAuthenticator(accounts, secrets, hasher);
    const result = await auth.Authenticate(new Credential(AuthMethod.Local, "a@x.io"), new PresentedSecret("wrong"), tenant);
    assert.ok(result instanceof RejectedResult);
});

test("unknown email is rejected with the SAME reason as a bad password (no account enumeration)", async () =>
{
    const accounts = new LocalAccountStore(); const secrets = new EncryptedSecretStore(randomBytes(32)); const hasher = new Argon2PasswordHasher();
    await register(accounts, secrets, hasher, "a@x.io", "p1", "hunter2");
    const auth = new LocalPasswordAuthenticator(accounts, secrets, hasher);
    const badPassword = await auth.Authenticate(new Credential(AuthMethod.Local, "a@x.io"), new PresentedSecret("wrong"), tenant);
    const unknownEmail = await auth.Authenticate(new Credential(AuthMethod.Local, "ghost@x.io"), new PresentedSecret("wrong"), tenant);
    assert.ok(badPassword instanceof RejectedResult && unknownEmail instanceof RejectedResult);
    assert.equal((badPassword as RejectedResult).Reason, (unknownEmail as RejectedResult).Reason);
});

test("the dummy hash is a valid PHC string (verify returns a boolean without throwing)", async () =>
{
    const dummy = (LocalPasswordAuthenticator as unknown as { DummyHash: string }).DummyHash;
    assert.match(dummy, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    const hasher = new Argon2PasswordHasher();
    assert.equal(typeof await hasher.Verify("x", dummy), "boolean");
});
