import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Tenant, TenantKind, PresentedSecret } from "@pragmatic-tech-ai/todl-identity";
import { Argon2PasswordHasher } from "../../hashing/argon2-password-hasher.js";
import { EncryptedSecretStore } from "../../secrets/encrypted-secret-store.js";
import { LocalAccountStore } from "../../accounts/local-account-store.js";
import { InMemoryAuditSink } from "../in-memory-audit-sink.js";
import { LocalAccountRegistrar } from "../local-account-registrar.js";

test("a failed registration leaves no orphaned secret and no audit event", async () =>
{
    const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
    const secrets = new EncryptedSecretStore(randomBytes(32));
    const audit = new InMemoryAuditSink();
    const registrar = new LocalAccountRegistrar(new LocalAccountStore(), secrets, new Argon2PasswordHasher(), audit);

    await registrar.Register(tenant, "a@x.io", "p1", new PresentedSecret("pw1"));
    await assert.rejects(registrar.Register(tenant, "a@x.io", "p2", new PresentedSecret("pw2")));

    assert.equal(await secrets.Get("t1/pwhash/p2"), null);
    assert.notEqual(await secrets.Get("t1/pwhash/p1"), null);
    assert.equal(audit.Events.length, 1);
});

test("re-registering an existing principalId rejects and leaves the victim credential intact", async () =>
{
    const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
    const secrets = new EncryptedSecretStore(randomBytes(32));
    const hasher = new Argon2PasswordHasher();
    const registrar = new LocalAccountRegistrar(new LocalAccountStore(), secrets, hasher, new InMemoryAuditSink());

    await registrar.Register(tenant, "a@x.io", "p1", new PresentedSecret("pw1"));
    const before = await secrets.Get("t1/pwhash/p1");
    assert.ok(before !== null && await hasher.Verify("pw1", before));

    await assert.rejects(registrar.Register(tenant, "attacker@x.io", "p1", new PresentedSecret("pw2")));

    const after = await secrets.Get("t1/pwhash/p1");
    assert.ok(after !== null);
    assert.ok(await hasher.Verify("pw1", after));
    assert.ok(!await hasher.Verify("pw2", after));
});

test("RotatePasswordIfChanged rewrites the hash when the password changed", async () =>
{
    const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
    const secrets = new EncryptedSecretStore(randomBytes(32));
    const hasher = new Argon2PasswordHasher();
    const audit = new InMemoryAuditSink();
    const registrar = new LocalAccountRegistrar(new LocalAccountStore(), secrets, hasher, audit);

    await registrar.Register(tenant, "a@x.io", "p1", new PresentedSecret("pw-old"));
    const rotated = await registrar.RotatePasswordIfChanged(tenant, "p1", new PresentedSecret("pw-new"));

    assert.equal(rotated, true);
    const stored = await secrets.Get("t1/pwhash/p1");
    assert.ok(stored !== null && await hasher.Verify("pw-new", stored));
    assert.ok(!await hasher.Verify("pw-old", stored));
    // one register + one rotate event, rotate detail carries only a non-secret action token
    assert.equal(audit.Events.length, 2);
    const rotate = audit.Events[1];
    assert.equal(rotate.Detail.get("action"), "rotate");
    for (const value of rotate.Detail.values())
    {
        assert.ok(!value.includes("pw-new") && !value.includes("pw-old"));
    }
});

test("RotatePasswordIfChanged is a no-op when the password is unchanged", async () =>
{
    const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
    const secrets = new EncryptedSecretStore(randomBytes(32));
    const hasher = new Argon2PasswordHasher();
    const audit = new InMemoryAuditSink();
    const registrar = new LocalAccountRegistrar(new LocalAccountStore(), secrets, hasher, audit);

    await registrar.Register(tenant, "a@x.io", "p1", new PresentedSecret("pw-same"));
    const before = await secrets.Get("t1/pwhash/p1");
    const rotated = await registrar.RotatePasswordIfChanged(tenant, "p1", new PresentedSecret("pw-same"));

    assert.equal(rotated, false);
    assert.equal(await secrets.Get("t1/pwhash/p1"), before); // byte-identical: no re-hash write
    assert.equal(audit.Events.length, 1); // register only, no rotate event
});

test("RotatePasswordIfChanged never mints a credential when none exists", async () =>
{
    const tenant = new Tenant("t1", TenantKind.Saas, "Acme");
    const secrets = new EncryptedSecretStore(randomBytes(32));
    const audit = new InMemoryAuditSink();
    const registrar = new LocalAccountRegistrar(new LocalAccountStore(), secrets, new Argon2PasswordHasher(), audit);

    const rotated = await registrar.RotatePasswordIfChanged(tenant, "ghost", new PresentedSecret("pw"));

    assert.equal(rotated, false);
    assert.equal(await secrets.Get("t1/pwhash/ghost"), null); // nothing written
    assert.equal(audit.Events.length, 0);
});
