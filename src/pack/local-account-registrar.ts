import { AuditEvent, AuditEventKind } from "@pragmatic-tech-ai/todl-identity";
import type { IAuditSink, ILocalAccountStore, IPasswordHasher, ISecretStore, LocalAccount, PresentedSecret, Tenant } from "@pragmatic-tech-ai/todl-identity";

/** Registers a local account: hashes the password, stores the hash by reference, records a non-secret audit event. */
export class LocalAccountRegistrar
{
    private static readonly SecretRefSegment = "/pwhash/";
    private static readonly ActionKey = "action";
    private static readonly EmailKey = "email";
    private static readonly RegisterAction = "register";

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
        await this.secrets.Put(ref, hash);
        const account = await this.accounts.CreateAccount(tenant, email, principalId, ref);
        const detail = new Map<string, string>([
            [LocalAccountRegistrar.ActionKey, LocalAccountRegistrar.RegisterAction],
            [LocalAccountRegistrar.EmailKey, email]
        ]);
        await this.audit.Record(new AuditEvent(AuditEventKind.AdminAction, tenant.Id, principalId, new Date(), detail));
        return account;
    }
}
