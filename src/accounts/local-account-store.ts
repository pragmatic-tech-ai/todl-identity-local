import { LocalAccount, LocalAccountNotFoundError, Principal, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import type { ILocalAccountStore, IPrincipalDirectory, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class LocalAccountStore implements ILocalAccountStore, IPrincipalDirectory
{
    private static readonly DuplicateEmailMessage = "email already registered";
    private static readonly DuplicatePrincipalMessage = "principal already registered";
    private static readonly InvalidKeyComponentMessage = "tenant id and principal id must not contain the key separator";
    private static readonly KeySeparator = "/";

    private readonly byEmail = new Map<string, LocalAccount>();
    private readonly byPrincipal = new Map<string, LocalAccount>();
    private readonly groups = new Map<string, readonly string[]>();

    public async CreateAccount(tenant: Tenant, email: string, principalId: string, secretRef: string): Promise<LocalAccount>
    {
        if (tenant.Id.includes(LocalAccountStore.KeySeparator) || principalId.includes(LocalAccountStore.KeySeparator))
        {
            throw new Error(LocalAccountStore.InvalidKeyComponentMessage);
        }
        const emailKey = LocalAccountStore.Key(tenant.Id, email);
        const principalKey = LocalAccountStore.Key(tenant.Id, principalId);
        if (this.byEmail.has(emailKey))
        {
            throw new Error(LocalAccountStore.DuplicateEmailMessage);
        }
        if (this.byPrincipal.has(principalKey))
        {
            throw new Error(LocalAccountStore.DuplicatePrincipalMessage);
        }
        const account = new LocalAccount(principalId, tenant.Id, email, secretRef, false);
        this.byEmail.set(emailKey, account);
        this.byPrincipal.set(principalKey, account);
        return account;
    }

    public async FindByEmail(tenant: Tenant, email: string): Promise<LocalAccount | null>
    {
        return this.byEmail.get(LocalAccountStore.Key(tenant.Id, email)) ?? null;
    }

    public async FindByPrincipalId(tenant: Tenant, principalId: string): Promise<LocalAccount | null>
    {
        return this.byPrincipal.get(LocalAccountStore.Key(tenant.Id, principalId)) ?? null;
    }

    public async Lookup(principalId: string, tenant: Tenant): Promise<Principal | null>
    {
        const key = LocalAccountStore.Key(tenant.Id, principalId);
        const account = this.byPrincipal.get(key);
        if (account === undefined || account.Disabled)
        {
            return null;
        }
        return new Principal(principalId, tenant.Id, PrincipalKind.User, new Map(), this.groups.get(key) ?? []);
    }

    public async Disable(tenant: Tenant, principalId: string): Promise<void>
    {
        const principalKey = LocalAccountStore.Key(tenant.Id, principalId);
        const existing = this.byPrincipal.get(principalKey);
        if (existing === undefined)
        {
            throw new LocalAccountNotFoundError(principalId);
        }
        const disabled = new LocalAccount(existing.PrincipalId, existing.TenantId, existing.Email, existing.SecretRef, true);
        this.byPrincipal.set(principalKey, disabled);
        this.byEmail.set(LocalAccountStore.Key(tenant.Id, existing.Email), disabled);
    }

    public async ListAccounts(tenant: Tenant): Promise<readonly LocalAccount[]>
    {
        return [...this.byPrincipal.values()].filter(account => account.TenantId === tenant.Id);
    }

    public async GroupsOf(principal: Principal): Promise<readonly string[]>
    {
        if (principal.Groups.length > 0)
        {
            return principal.Groups;
        }
        return this.groups.get(LocalAccountStore.Key(principal.TenantId, principal.Id)) ?? [];
    }

    private static Key(tenantId: string, id: string): string
    {
        return tenantId + LocalAccountStore.KeySeparator + id;
    }
}
