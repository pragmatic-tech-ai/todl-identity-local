import { randomBytes, createHash } from "node:crypto";
import { ServiceTokenGrant, ServiceTokenSummary } from "@pragmatic-tech-ai/todl-identity";
import type { IServiceTokenStore, Tenant, PresentedSecret } from "@pragmatic-tech-ai/todl-identity";

interface ServiceTokenRecord
{
    grant: ServiceTokenGrant;
    revoked: boolean;
}

/**
 * In-memory scoped, revocable service token store. Tokens are opaque 256-bit values; the store
 * is keyed ONLY by sha256(token) and the raw token is returned once at issue. Absent, revoked,
 * expired and wrong-tenant tokens resolve to null (fail-closed).
 */
export class ServiceTokenStore implements IServiceTokenStore
{
    private static readonly TokenBytes = 32;
    private static readonly TokenEncoding = "base64url";
    private static readonly HashAlgorithm = "sha256";
    private static readonly HashEncoding = "base64url";
    private static readonly RefSegment = "/svctok/";
    private static readonly RefSeparator = "/";

    private readonly records = new Map<string, ServiceTokenRecord>();
    private readonly now: () => Date;

    public constructor(now: () => Date = () => new Date())
    {
        this.now = now;
    }

    public async Issue(tenant: Tenant, principalId: string, scopes: readonly string[], expiresAt: Date | null): Promise<{ Grant: ServiceTokenGrant; Token: string }>
    {
        const token = randomBytes(ServiceTokenStore.TokenBytes).toString(ServiceTokenStore.TokenEncoding);
        const hash = this.hash(token);
        const tokenRef = tenant.Id + ServiceTokenStore.RefSegment + hash;
        const grant = new ServiceTokenGrant(tokenRef, principalId, tenant.Id, [...scopes], expiresAt);
        this.records.set(hash, { grant, revoked: false });
        return { Grant: grant, Token: token };
    }

    public async Resolve(tenant: Tenant, presented: PresentedSecret): Promise<ServiceTokenGrant | null>
    {
        const record = this.records.get(this.hash(presented.Reveal()));
        if (record === undefined || record.revoked || record.grant.TenantId !== tenant.Id)
        {
            return null;
        }
        const expiresAt = record.grant.ExpiresAt;
        if (expiresAt !== null && expiresAt.getTime() <= this.now().getTime())
        {
            return null;
        }
        return record.grant;
    }

    public async Revoke(tenant: Tenant, tokenRef: string): Promise<void>
    {
        const record = this.records.get(tokenRef.slice(tokenRef.lastIndexOf(ServiceTokenStore.RefSeparator) + 1));
        if (record !== undefined && record.grant.TokenRef === tokenRef && record.grant.TenantId === tenant.Id)
        {
            record.revoked = true;
        }
    }

    public async List(tenant: Tenant): Promise<readonly ServiceTokenSummary[]>
    {
        return [...this.records.values()]
            .filter(record => record.grant.TenantId === tenant.Id)
            .map(record => new ServiceTokenSummary(record.grant.TokenRef, record.grant.PrincipalId, [...record.grant.Scopes], record.grant.ExpiresAt, record.revoked));
    }

    private hash(token: string): string
    {
        return createHash(ServiceTokenStore.HashAlgorithm).update(token).digest(ServiceTokenStore.HashEncoding);
    }
}
