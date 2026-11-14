import { IdpDirectorySnapshot, IdpUserState } from "@pragmatic-tech-ai/todl-identity";
import type { IdpDirectoryRequest, IIdpDirectorySource, ILocalAccountStore, ILocalGroupStore, Realm } from "@pragmatic-tech-ai/todl-identity";

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

    public async Snapshot(realm: Realm, request: IdpDirectoryRequest): Promise<IdpDirectorySnapshot>
    {
        const users = new Map<string, IdpUserState>();
        for (const principalId of request.PrincipalIds)
        {
            users.set(principalId, await this.StateOf(realm, principalId));
        }
        const records = await this.groups.ListGroups(realm);
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
                    users.set(memberId, await this.StateOf(realm, memberId));
                }
            }
        }
        return new IdpDirectorySnapshot(this.now(), this.Authoritative, users, members);
    }

    private async StateOf(realm: Realm, principalId: string): Promise<IdpUserState>
    {
        const account = await this.accounts.FindByPrincipalId(realm, principalId);
        if (account === null)
        {
            return IdpUserState.Deleted;
        }
        return account.Disabled ? IdpUserState.Disabled : IdpUserState.Enabled;
    }
}
