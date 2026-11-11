import { IdpDirectorySnapshot, IdpUserState } from "@pragmatic-tech-ai/todl-identity";
import type { IdpDirectoryRequest, IIdpDirectorySource, ILocalAccountStore, ILocalGroupStore, Tenant } from "@pragmatic-tech-ai/todl-identity";

/** The local IdP is its own authority: account and group records answer every directory question. */
export class LocalDirectorySource implements IIdpDirectorySource
{
    public readonly Authoritative = true;

    public constructor(
        private readonly accounts: ILocalAccountStore,
        private readonly groups: ILocalGroupStore,
        private readonly now: () => Date = () => new Date())
    {
    }

    public async Snapshot(tenant: Tenant, request: IdpDirectoryRequest): Promise<IdpDirectorySnapshot>
    {
        const users = new Map<string, IdpUserState>();
        for (const principalId of request.PrincipalIds)
        {
            users.set(principalId, await this.StateOf(tenant, principalId));
        }
        const records = await this.groups.ListGroups(tenant);
        const members = new Map<string, readonly string[]>();
        for (const groupId of request.GroupIds)
        {
            const memberIds = records.find(group => group.GroupId === groupId)?.MemberIds ?? [];
            members.set(groupId, memberIds);
            // A member reached only through a linked group still needs a state, or it would read Unknown (active).
            for (const memberId of memberIds)
            {
                if (!users.has(memberId))
                {
                    users.set(memberId, await this.StateOf(tenant, memberId));
                }
            }
        }
        return new IdpDirectorySnapshot(this.now(), this.Authoritative, users, members);
    }

    private async StateOf(tenant: Tenant, principalId: string): Promise<IdpUserState>
    {
        const account = await this.accounts.FindByPrincipalId(tenant, principalId);
        if (account === null)
        {
            return IdpUserState.Deleted;
        }
        return account.Disabled ? IdpUserState.Disabled : IdpUserState.Enabled;
    }
}
