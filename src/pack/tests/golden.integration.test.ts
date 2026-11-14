import { test } from "node:test";
import assert from "node:assert/strict";
import { Realm, RealmKind, Credential, PresentedSecret, AuthMethod, AuthenticatedResult, RejectedResult, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import { LocalIdentityProviderPack } from "../local-identity-provider-pack.js";

test("golden: register, login, session, service token, and no secret in audit", async () =>
{
    const Password = "hunter2";
    const pack = LocalIdentityProviderPack.Create();
    const realm = new Realm("t1", RealmKind.Saas, "Acme");

    await pack.Registrar.Register(realm, "a@x.io", "p1", new PresentedSecret(Password));

    const login = await pack.AuthenticatorFor(AuthMethod.Local)!.Authenticate(new Credential(AuthMethod.Local, "a@x.io"), new PresentedSecret(Password), realm);
    assert.ok(login instanceof AuthenticatedResult);
    const principal = (login as AuthenticatedResult).Principal;
    assert.equal(principal.Id, "p1");

    const session = await pack.Sessions.Issue(principal);
    assert.notEqual(await pack.Sessions.Validate(session.Id), null);
    await pack.Sessions.Revoke(session.Id);
    assert.equal(await pack.Sessions.Validate(session.Id), null);

    const { Grant, Token } = await pack.Tokens.Issue(realm, "svc1", ["read:models"], null);
    const tokenAuth = pack.AuthenticatorFor(AuthMethod.ServiceToken)!;
    const viaToken = await tokenAuth.Authenticate(new Credential(AuthMethod.ServiceToken, Grant.TokenRef), new PresentedSecret(Token), realm);
    assert.ok(viaToken instanceof AuthenticatedResult);
    const servicePrincipal = (viaToken as AuthenticatedResult).Principal;
    assert.equal(servicePrincipal.Kind, PrincipalKind.Service);
    assert.ok(servicePrincipal.Groups.includes("read:models"));

    await pack.Tokens.Revoke(realm, Grant.TokenRef);
    const afterRevoke = await tokenAuth.Authenticate(new Credential(AuthMethod.ServiceToken, Grant.TokenRef), new PresentedSecret(Token), realm);
    assert.ok(afterRevoke instanceof RejectedResult);

    assert.ok(pack.Audit.Events.some(e => e.Detail.get("action") === "register" && e.Detail.get("email") === "a@x.io"));
    for (const e of pack.Audit.Events)
    {
        for (const v of e.Detail.values())
        {
            assert.ok(!v.includes(Password));
            assert.ok(!v.includes(Token));
        }
    }
});
