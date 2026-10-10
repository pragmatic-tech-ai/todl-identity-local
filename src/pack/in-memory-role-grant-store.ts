import type { IRoleGrantStore, Grant, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class InMemoryRoleGrantStore implements IRoleGrantStore
{
    private readonly grants: Grant[] = [];

    public async GrantsFor(subject: string, _tenant: Tenant): Promise<readonly Grant[]>
    {
        return this.grants.filter(grant => grant.Subject === subject);
    }

    public async Save(grant: Grant): Promise<void>
    {
        this.grants.push(grant);
    }
}
