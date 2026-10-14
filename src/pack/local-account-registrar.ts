import { AuditEvent, AuditEventKind } from "@pragmatic-tech-ai/todl-identity";
import type { IAuditSink, ILocalAccountStore, IPasswordHasher, ISecretStore, LocalAccount, PresentedSecret, Tenant } from "@pragmatic-tech-ai/todl-identity";

/** Registers a local account: hashes the password, stores the hash by reference, records a non-secret audit event. */
export class LocalAccountRegistrar
{
    private static readonly SecretRefSegment = "/pwhash/";
    private static readonly ActionKey = "action";
    private static readonly EmailKey = "email";
    private static readonly RegisterAction = "register";
    private static readonly RotateAction = "rotate";

    public constructor(
        private readonly accounts: ILocalAccountStore,
        private readonly secrets: ISecretStore,
        private readonly hasher: IPasswordHasher,
        private readonly audit: IAuditSink)
    {
    }

    public async Register(tenant: Tenant, email: string, principalId: string, password: PresentedSecret): Promise<LocalAccount>
    {
        const hash = await this.hasher.Hash(password.Reveal());
        const ref = tenant.Id + LocalAccountRegistrar.SecretRefSegment + principalId;
        // Reserve uniqueness first: a duplicate email/principal throws here, before any secret write,
        // so an existing account's stored hash is never overwritten or deleted.
        const account = await this.accounts.CreateAccount(tenant, email, principalId, ref);
        await this.secrets.Put(ref, hash);
        const detail = new Map<string, string>([
            [LocalAccountRegistrar.ActionKey, LocalAccountRegistrar.RegisterAction],
            [LocalAccountRegistrar.EmailKey, email]
        ]);
        await this.audit.Record(new AuditEvent(AuditEventKind.AdminAction, tenant.Id, principalId, new Date(), detail));
        return account;
    }

    /**
     * Re-hashes and overwrites an existing account's stored password hash iff the presented password no
     * longer verifies against it (i.e. it was rotated). Returns true when the hash was rewritten.
     * Fail-safe: a principal with no stored hash is left untouched (never mints a credential), and a
     * matching password writes nothing. Never logs or audits the password or the hash.
     */
    public async RotatePasswordIfChanged(tenant: Tenant, principalId: string, password: PresentedSecret): Promise<boolean>
    {
        const ref = tenant.Id + LocalAccountRegistrar.SecretRefSegment + principalId;
        const stored = await this.secrets.Get(ref);
        if (stored === null)
        {
            return false;
        }
        if (await this.hasher.Verify(password.Reveal(), stored))
        {
            return false;
        }
        const hash = await this.hasher.Hash(password.Reveal());
        await this.secrets.Put(ref, hash);
        const detail = new Map<string, string>([
            [LocalAccountRegistrar.ActionKey, LocalAccountRegistrar.RotateAction]
        ]);
        await this.audit.Record(new AuditEvent(AuditEventKind.AdminAction, tenant.Id, principalId, new Date(), detail));
        return true;
    }
}
