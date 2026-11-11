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
            const account = await this.accounts.FindByPrincipalId(tenant, principalId);
            if (account === null)
            {
                users.set(principalId, IdpUserState.Deleted);
            }
            else
            {
                users.set(principalId, account.Disabled ? IdpUserState.Disabled : IdpUserState.Enabled);
            }
        }
        const records = await this.groups.ListGroups(tenant);
        const members = new Map<string, readonly string[]>();
        for (const groupId of request.GroupIds)
        {
            members.set(groupId, records.find(group => group.GroupId === groupId)?.MemberIds ?? []);
        }
        return new IdpDirectorySnapshot(this.now(), this.Authoritative, users, members);
    }
}
