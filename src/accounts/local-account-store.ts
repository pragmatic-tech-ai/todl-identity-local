import { LocalAccount, LocalAccountNotFoundError, LocalGroup, LocalGroupNotFoundError, Principal, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import type { ILocalAccountStore, ILocalGroupStore, IPrincipalDirectory, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class LocalAccountStore implements ILocalAccountStore, IPrincipalDirectory, ILocalGroupStore
{
    private static readonly DuplicateEmailMessage = "email already registered";
    private static readonly DuplicatePrincipalMessage = "principal already registered";
    private static readonly InvalidKeyComponentMessage = "tenant id and principal id must not contain the key separator";
    private static readonly DuplicateGroupMessage = "group already exists";
    private static readonly KeySeparator = "/";

    private readonly byEmail = new Map<string, LocalAccount>();
    private readonly byPrincipal = new Map<string, LocalAccount>();
    private readonly groups = new Map<string, Map<string, LocalGroup>>();

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
        return new Principal(principalId, tenant.Id, PrincipalKind.User, new Map(), this.GroupIdsOf(tenant.Id, principalId));
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

    public async Enable(tenant: Tenant, principalId: string): Promise<void>
    {
        const principalKey = LocalAccountStore.Key(tenant.Id, principalId);
        const existing = this.byPrincipal.get(principalKey);
        if (existing === undefined)
        {
            throw new LocalAccountNotFoundError(principalId);
        }
        const enabled = new LocalAccount(existing.PrincipalId, existing.TenantId, existing.Email, existing.SecretRef, false);
        this.byPrincipal.set(principalKey, enabled);
        this.byEmail.set(LocalAccountStore.Key(tenant.Id, existing.Email), enabled);
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
        return this.GroupIdsOf(principal.TenantId, principal.Id);
    }

    public async CreateGroup(tenant: Tenant, groupId: string, name: string): Promise<LocalGroup>
    {
        const tenantGroups = this.GroupsFor(tenant.Id, true) as Map<string, LocalGroup>;
        if (tenantGroups.has(groupId))
        {
            throw new Error(LocalAccountStore.DuplicateGroupMessage);
        }
        const group = new LocalGroup(groupId, tenant.Id, name, []);
        tenantGroups.set(groupId, group);
        return group;
    }

    public async DeleteGroup(tenant: Tenant, groupId: string): Promise<void>
    {
        this.RequireGroup(tenant, groupId);
        this.GroupsFor(tenant.Id, false)?.delete(groupId);
    }

    public async AddMember(tenant: Tenant, groupId: string, principalId: string): Promise<void>
    {
        const group = this.RequireGroup(tenant, groupId);
        if (group.MemberIds.includes(principalId))
        {
            return;
        }
        this.GroupsFor(tenant.Id, false)?.set(groupId, new LocalGroup(group.GroupId, group.TenantId, group.Name, [...group.MemberIds, principalId]));
    }

    public async RemoveMember(tenant: Tenant, groupId: string, principalId: string): Promise<void>
    {
        const group = this.RequireGroup(tenant, groupId);
        this.GroupsFor(tenant.Id, false)?.set(groupId, new LocalGroup(group.GroupId, group.TenantId, group.Name, group.MemberIds.filter(id => id !== principalId)));
    }

    public async ListGroups(tenant: Tenant): Promise<readonly LocalGroup[]>
    {
        return [...(this.GroupsFor(tenant.Id, false)?.values() ?? [])];
    }

    private RequireGroup(tenant: Tenant, groupId: string): LocalGroup
    {
        const group = this.GroupsFor(tenant.Id, false)?.get(groupId);
        if (group === undefined)
        {
            throw new LocalGroupNotFoundError(groupId);
        }
        return group;
    }

    private GroupsFor(tenantId: string, create: boolean): Map<string, LocalGroup> | undefined
    {
        let tenantGroups = this.groups.get(tenantId);
        if (tenantGroups === undefined && create)
        {
            tenantGroups = new Map<string, LocalGroup>();
            this.groups.set(tenantId, tenantGroups);
        }
        return tenantGroups;
    }

    private GroupIdsOf(tenantId: string, principalId: string): readonly string[]
    {
        return [...(this.groups.get(tenantId)?.values() ?? [])]
            .filter(group => group.MemberIds.includes(principalId))
            .map(group => group.GroupId);
    }

    private static Key(tenantId: string, id: string): string
    {
        return tenantId + LocalAccountStore.KeySeparator + id;
    }
}
