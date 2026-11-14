import { LocalAccount, LocalAccountNotFoundError, LocalGroup, LocalGroupNotFoundError, Principal, PrincipalKind, SystemPrincipal } from "@pragmatic-tech-ai/todl-identity";
import type { ILocalAccountStore, ILocalGroupStore, IPrincipalDirectory, Realm } from "@pragmatic-tech-ai/todl-identity";

export class LocalAccountStore implements ILocalAccountStore, IPrincipalDirectory, ILocalGroupStore
{
    private static readonly DuplicateEmailMessage = "email already registered";
    private static readonly DuplicatePrincipalMessage = "principal already registered";
    private static readonly InvalidKeyComponentMessage = "realm id and principal id must not contain the key separator";
    private static readonly DuplicateGroupMessage = "group already exists";
    private static readonly ReservedPrincipalMessage = "principal id uses the reserved system prefix";
    private static readonly KeySeparator = "/";

    private readonly byEmail = new Map<string, LocalAccount>();
    private readonly byPrincipal = new Map<string, LocalAccount>();
    private readonly groups = new Map<string, Map<string, LocalGroup>>();

    public async CreateAccount(realm: Realm, email: string, principalId: string, secretRef: string): Promise<LocalAccount>
    {
        if (realm.Id.includes(LocalAccountStore.KeySeparator) || principalId.includes(LocalAccountStore.KeySeparator))
        {
            throw new Error(LocalAccountStore.InvalidKeyComponentMessage);
        }
        if (SystemPrincipal.IsReserved(principalId))
        {
            throw new Error(LocalAccountStore.ReservedPrincipalMessage);
        }
        const emailKey = LocalAccountStore.Key(realm.Id, email);
        const principalKey = LocalAccountStore.Key(realm.Id, principalId);
        if (this.byEmail.has(emailKey))
        {
            throw new Error(LocalAccountStore.DuplicateEmailMessage);
        }
        if (this.byPrincipal.has(principalKey))
        {
            throw new Error(LocalAccountStore.DuplicatePrincipalMessage);
        }
        const account = new LocalAccount(principalId, realm.Id, email, secretRef, false);
        this.byEmail.set(emailKey, account);
        this.byPrincipal.set(principalKey, account);
        return account;
    }

    public async FindByEmail(realm: Realm, email: string): Promise<LocalAccount | null>
    {
        return this.byEmail.get(LocalAccountStore.Key(realm.Id, email)) ?? null;
    }

    public async FindByPrincipalId(realm: Realm, principalId: string): Promise<LocalAccount | null>
    {
        return this.byPrincipal.get(LocalAccountStore.Key(realm.Id, principalId)) ?? null;
    }

    public async Lookup(principalId: string, realm: Realm): Promise<Principal | null>
    {
        const key = LocalAccountStore.Key(realm.Id, principalId);
        const account = this.byPrincipal.get(key);
        if (account === undefined || account.Disabled)
        {
            return null;
        }
        return new Principal(principalId, realm.Id, PrincipalKind.User, new Map(), this.GroupIdsOf(realm.Id, principalId));
    }

    public async Disable(realm: Realm, principalId: string): Promise<void>
    {
        const principalKey = LocalAccountStore.Key(realm.Id, principalId);
        const existing = this.byPrincipal.get(principalKey);
        if (existing === undefined)
        {
            throw new LocalAccountNotFoundError(principalId);
        }
        const disabled = new LocalAccount(existing.PrincipalId, existing.RealmId, existing.Email, existing.SecretRef, true);
        this.byPrincipal.set(principalKey, disabled);
        this.byEmail.set(LocalAccountStore.Key(realm.Id, existing.Email), disabled);
    }

    public async Enable(realm: Realm, principalId: string): Promise<void>
    {
        const principalKey = LocalAccountStore.Key(realm.Id, principalId);
        const existing = this.byPrincipal.get(principalKey);
        if (existing === undefined)
        {
            throw new LocalAccountNotFoundError(principalId);
        }
        const enabled = new LocalAccount(existing.PrincipalId, existing.RealmId, existing.Email, existing.SecretRef, false);
        this.byPrincipal.set(principalKey, enabled);
        this.byEmail.set(LocalAccountStore.Key(realm.Id, existing.Email), enabled);
    }

    public async ListAccounts(realm: Realm): Promise<readonly LocalAccount[]>
    {
        return [...this.byPrincipal.values()].filter(account => account.RealmId === realm.Id);
    }

    public async GroupsOf(principal: Principal): Promise<readonly string[]>
    {
        if (principal.Groups.length > 0)
        {
            return principal.Groups;
        }
        return this.GroupIdsOf(principal.RealmId, principal.Id);
    }

    public async CreateGroup(realm: Realm, groupId: string, name: string): Promise<LocalGroup>
    {
        const realmGroups = this.GroupsFor(realm.Id, true) as Map<string, LocalGroup>;
        if (realmGroups.has(groupId))
        {
            throw new Error(LocalAccountStore.DuplicateGroupMessage);
        }
        const group = new LocalGroup(groupId, realm.Id, name, []);
        realmGroups.set(groupId, group);
        return group;
    }

    public async DeleteGroup(realm: Realm, groupId: string): Promise<void>
    {
        this.RequireGroup(realm, groupId);
        this.GroupsFor(realm.Id, false)?.delete(groupId);
    }

    public async AddMember(realm: Realm, groupId: string, principalId: string): Promise<void>
    {
        const group = this.RequireGroup(realm, groupId);
        if (group.MemberIds.includes(principalId))
        {
            return;
        }
        this.GroupsFor(realm.Id, false)?.set(groupId, new LocalGroup(group.GroupId, group.RealmId, group.Name, [...group.MemberIds, principalId]));
    }

    public async RemoveMember(realm: Realm, groupId: string, principalId: string): Promise<void>
    {
        const group = this.RequireGroup(realm, groupId);
        this.GroupsFor(realm.Id, false)?.set(groupId, new LocalGroup(group.GroupId, group.RealmId, group.Name, group.MemberIds.filter(id => id !== principalId)));
    }

    public async ListGroups(realm: Realm): Promise<readonly LocalGroup[]>
    {
        return [...(this.GroupsFor(realm.Id, false)?.values() ?? [])];
    }

    private RequireGroup(realm: Realm, groupId: string): LocalGroup
    {
        const group = this.GroupsFor(realm.Id, false)?.get(groupId);
        if (group === undefined)
        {
            throw new LocalGroupNotFoundError(groupId);
        }
        return group;
    }

    private GroupsFor(realmId: string, create: boolean): Map<string, LocalGroup> | undefined
    {
        let realmGroups = this.groups.get(realmId);
        if (realmGroups === undefined && create)
        {
            realmGroups = new Map<string, LocalGroup>();
            this.groups.set(realmId, realmGroups);
        }
        return realmGroups;
    }

    private GroupIdsOf(realmId: string, principalId: string): readonly string[]
    {
        return [...(this.groups.get(realmId)?.values() ?? [])]
            .filter(group => group.MemberIds.includes(principalId))
            .map(group => group.GroupId);
    }

    private static Key(realmId: string, id: string): string
    {
        return realmId + LocalAccountStore.KeySeparator + id;
    }
}
