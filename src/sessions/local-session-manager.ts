import { randomBytes, createHash } from "node:crypto";
import { Session, AuthMethod } from "@pragmatic-tech-ai/todl-identity";
import type { ISessionManager, Principal, Tenant } from "@pragmatic-tech-ai/todl-identity";

/**
 * In-memory session manager issuing opaque 256-bit bearer tokens. The store is keyed ONLY by
 * sha256(token); the raw token is never persisted. Expired, revoked and unknown tokens
 * validate to null (fail-closed).
 */
export class LocalSessionManager implements ISessionManager
{
    private static readonly DefaultTtlMs = 3_600_000;
    private static readonly TokenBytes = 32;
    private static readonly TokenEncoding = "base64url";
    private static readonly HashAlgorithm = "sha256";
    private static readonly HashEncoding = "base64url";

    private readonly sessions = new Map<string, Session>();
    private readonly ttlMs: number;
    private readonly now: () => Date;

    public constructor(ttlMs: number = LocalSessionManager.DefaultTtlMs, now: () => Date = () => new Date())
    {
        this.ttlMs = ttlMs;
        this.now = now;
    }

    public async Issue(principal: Principal): Promise<Session>
    {
        const token = randomBytes(LocalSessionManager.TokenBytes).toString(LocalSessionManager.TokenEncoding);
        const issuedAt = this.now();
        const expiresAt = new Date(issuedAt.getTime() + this.ttlMs);
        const session = new Session(token, principal.Id, principal.TenantId, issuedAt, expiresAt, AuthMethod.Local);
        this.sessions.set(this.hash(token), session);
        return session;
    }

    public async Validate(token: string): Promise<Session | null>
    {
        const key = this.hash(token);
        const record = this.sessions.get(key);
        if (record === undefined)
        {
            return null;
        }
        if (record.IsExpired(this.now()))
        {
            this.sessions.delete(key);
            return null;
        }
        return record;
    }

    public async Revoke(sessionId: string): Promise<void>
    {
        this.sessions.delete(this.hash(sessionId));
    }

    public async RevokeAllFor(tenant: Tenant, principalId: string): Promise<void>
    {
        for (const [key, session] of [...this.sessions])
        {
            if (session.PrincipalId === principalId && session.TenantId === tenant.Id)
            {
                this.sessions.delete(key);
            }
        }
    }

    private hash(token: string): string
    {
        return createHash(LocalSessionManager.HashAlgorithm).update(token).digest(LocalSessionManager.HashEncoding);
    }
}
