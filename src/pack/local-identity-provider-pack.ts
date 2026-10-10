import { randomBytes } from "node:crypto";
import { DelegationDepth, ResourceAuthorizationPolicy } from "@pragmatic-tech-ai/todl-identity";
import type { AuthMethod, IAccessPolicy, IAuthenticator, IIdentityProviderPack, IPrincipalDirectory, ISessionManager } from "@pragmatic-tech-ai/todl-identity";
import { Argon2PasswordHasher } from "../hashing/argon2-password-hasher.js";
import { EncryptedSecretStore } from "../secrets/encrypted-secret-store.js";
import { LocalAccountStore } from "../accounts/local-account-store.js";
import { LocalSessionManager } from "../sessions/local-session-manager.js";
import { ServiceTokenStore } from "../tokens/service-token-store.js";
import { ServiceTokenAuthenticator } from "../tokens/service-token-authenticator.js";
import { LocalPasswordAuthenticator } from "../authn/local-password-authenticator.js";
import { InMemoryAuditSink } from "./in-memory-audit-sink.js";
import { InMemoryRoleGrantStore } from "./in-memory-role-grant-store.js";
import { LocalAccountRegistrar } from "./local-account-registrar.js";

export class LocalIdentityProviderPack implements IIdentityProviderPack
{
    private static readonly MasterKeyBytes = 32;

    public readonly DelegationDepth = DelegationDepth.FullAuthz;
    public readonly Policy: IAccessPolicy = new ResourceAuthorizationPolicy();
    public readonly Authenticators: readonly IAuthenticator[];
    public readonly Directory: IPrincipalDirectory;
    public readonly Sessions: ISessionManager;
    public readonly Grants: InMemoryRoleGrantStore;
    public readonly Audit: InMemoryAuditSink;
    public readonly Registrar: LocalAccountRegistrar;
    public readonly Tokens: ServiceTokenStore;

    private constructor(masterKey: Buffer)
    {
        const secrets = new EncryptedSecretStore(masterKey);
        const hasher = new Argon2PasswordHasher();
        const accounts = new LocalAccountStore();
        this.Tokens = new ServiceTokenStore();
        this.Sessions = new LocalSessionManager();
        this.Audit = new InMemoryAuditSink();
        this.Grants = new InMemoryRoleGrantStore();
        this.Directory = accounts;
        this.Registrar = new LocalAccountRegistrar(accounts, secrets, hasher, this.Audit);
        this.Authenticators = [new LocalPasswordAuthenticator(accounts, secrets, hasher), new ServiceTokenAuthenticator(this.Tokens)];
    }

    public static Create(masterKey?: Buffer): LocalIdentityProviderPack
    {
        return new LocalIdentityProviderPack(masterKey ?? randomBytes(LocalIdentityProviderPack.MasterKeyBytes));
    }

    public AuthenticatorFor(method: AuthMethod): IAuthenticator | undefined
    {
        return this.Authenticators.find(authenticator => authenticator.Method === method);
    }
}
