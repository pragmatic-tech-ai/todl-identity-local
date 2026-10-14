import type { IRoleGrantStore, Grant, ResourceRef, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class InMemoryRoleGrantStore implements IRoleGrantStore
{
    private readonly grants: Grant[] = [];

    public async GrantsFor(subject: string, _tenant: Tenant): Promise<readonly Grant[]>
    {
        return this.grants.filter(grant => grant.Subject === subject);
    }

    public async GrantsOn(resource: ResourceRef): Promise<readonly Grant[]>
    {
        return this.grants.filter(grant => InMemoryRoleGrantStore.SameResource(grant.Resource, resource));
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
        return a.Subject === b.Subject && a.Role === b.Role && InMemoryRoleGrantStore.SameResource(a.Resource, b.Resource);
    }

    private static SameResource(a: ResourceRef, b: ResourceRef): boolean
    {
        return a.Kind === b.Kind && a.TenantId === b.TenantId && a.Path.length === b.Path.length && a.Path.every((p, i) => p === b.Path[i]);
    }
}
