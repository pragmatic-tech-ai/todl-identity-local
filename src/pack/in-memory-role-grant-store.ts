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

    public async Revoke(grant: Grant): Promise<void>
    {
        const kept = this.grants.filter(existing => !InMemoryRoleGrantStore.Matches(existing, grant));
        this.grants.length = 0;
        this.grants.push(...kept);
    }

    private static Matches(a: Grant, b: Grant): boolean
    {
        return a.Subject === b.Subject && a.Role === b.Role && a.Resource.Kind === b.Resource.Kind && a.Resource.TenantId === b.Resource.TenantId && a.Resource.Path.length === b.Resource.Path.length && a.Resource.Path.every((p, i) => p === b.Resource.Path[i]);
    }
}
