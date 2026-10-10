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
