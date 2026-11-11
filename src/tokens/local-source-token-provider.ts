import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { PresentedSecret, SourceToken, SourceTokenError, SourceTokenFailure, SystemPrincipal } from "@pragmatic-tech-ai/todl-identity";
import type { ILocalAccountStore, ISecretStore, ISourceTokenProvider, SourceTokenRequest, Tenant } from "@pragmatic-tech-ai/todl-identity";

/** Issues short-lived per-user HS256 source tokens signed with a per-tenant key held in the secret store. */
export class LocalSourceTokenProvider implements ISourceTokenProvider
{
    private static readonly Issuer = "todl-identity-local";
    private static readonly KeyPrefix = "local-source-token-key/";
    private static readonly LifetimeSeconds = 300;
    private static readonly KeyBytes = 32;
    private static readonly Algorithm = "HS256";
    private static readonly TokenType = "JWT";
    private static readonly HmacAlgorithm = "sha256";
    private static readonly Encoding = "base64url";
    private static readonly KeyEncoding = "base64";
    private static readonly PartSeparator = ".";
    private static readonly AlgHeader = "alg";
    private static readonly TypHeader = "typ";
    private static readonly IssClaim = "iss";
    private static readonly SubClaim = "sub";
    private static readonly AudClaim = "aud";
    private static readonly IatClaim = "iat";
    private static readonly ExpClaim = "exp";
    private static readonly MillisPerSecond = 1000;
    private static readonly PartCount = 3;

    public constructor(
        private readonly accounts: ILocalAccountStore,
        private readonly secrets: ISecretStore,
        private readonly now: () => Date = () => new Date())
    {
    }

    public async Acquire(request: SourceTokenRequest): Promise<SourceToken>
    {
        if (request.PrincipalId === SystemPrincipal.IdFor(request.TenantId))
        {
            throw new SourceTokenError(SourceTokenFailure.UnsupportedPrincipal);
        }
        const tenant = { Id: request.TenantId } as Tenant;
        const account = await this.accounts.FindByPrincipalId(tenant, request.PrincipalId);
        if (account === null || account.Disabled)
        {
            throw new SourceTokenError(SourceTokenFailure.PrincipalInactive);
        }
        const issuedAt = Math.floor(this.now().getTime() / LocalSourceTokenProvider.MillisPerSecond);
        const expiresAt = issuedAt + LocalSourceTokenProvider.LifetimeSeconds;
        const header = { [LocalSourceTokenProvider.AlgHeader]: LocalSourceTokenProvider.Algorithm, [LocalSourceTokenProvider.TypHeader]: LocalSourceTokenProvider.TokenType };
        const claims = {
            [LocalSourceTokenProvider.IssClaim]: LocalSourceTokenProvider.Issuer,
            [LocalSourceTokenProvider.SubClaim]: request.PrincipalId,
            [LocalSourceTokenProvider.AudClaim]: request.Resource,
            [LocalSourceTokenProvider.IatClaim]: issuedAt,
            [LocalSourceTokenProvider.ExpClaim]: expiresAt,
        };
        const signingInput = LocalSourceTokenProvider.Encode(header) + LocalSourceTokenProvider.PartSeparator + LocalSourceTokenProvider.Encode(claims);
        const key = await this.CreateOrLoadKey(request.TenantId);
        const signature = LocalSourceTokenProvider.Sign(key, signingInput);
        return new SourceToken(
            request.Resource,
            new PresentedSecret(signingInput + LocalSourceTokenProvider.PartSeparator + signature),
            new Date(expiresAt * LocalSourceTokenProvider.MillisPerSecond));
    }

    /** Returns the subject when signature, audience, issuer and expiry all hold; otherwise null. */
    public async Verify(tenantId: string, token: string, resource: string): Promise<string | null>
    {
        const parts = token.split(LocalSourceTokenProvider.PartSeparator);
        if (parts.length !== LocalSourceTokenProvider.PartCount)
        {
            return null;
        }
        const stored = await this.secrets.Get(LocalSourceTokenProvider.KeyPrefix + tenantId);
        if (stored === null)
        {
            return null;
        }
        const key = Buffer.from(stored, LocalSourceTokenProvider.KeyEncoding);
        const expected = Buffer.from(LocalSourceTokenProvider.Sign(key, parts[0] + LocalSourceTokenProvider.PartSeparator + parts[1]));
        const presented = Buffer.from(parts[2]);
        if (expected.length !== presented.length || !timingSafeEqual(expected, presented))
        {
            return null;
        }
        let claims: Record<string, unknown>;
        try
        {
            claims = JSON.parse(Buffer.from(parts[1], LocalSourceTokenProvider.Encoding).toString()) as Record<string, unknown>;
        }
        catch
        {
            return null;
        }
        const exp = claims[LocalSourceTokenProvider.ExpClaim];
        const sub = claims[LocalSourceTokenProvider.SubClaim];
        if (claims[LocalSourceTokenProvider.IssClaim] !== LocalSourceTokenProvider.Issuer
            || claims[LocalSourceTokenProvider.AudClaim] !== resource
            || typeof exp !== "number"
            || typeof sub !== "string")
        {
            return null;
        }
        if (this.now().getTime() >= exp * LocalSourceTokenProvider.MillisPerSecond)
        {
            return null;
        }
        return sub;
    }

    private async CreateOrLoadKey(tenantId: string): Promise<Buffer>
    {
        const reference = LocalSourceTokenProvider.KeyPrefix + tenantId;
        const existing = await this.secrets.Get(reference);
        if (existing !== null)
        {
            return Buffer.from(existing, LocalSourceTokenProvider.KeyEncoding);
        }
        const key = randomBytes(LocalSourceTokenProvider.KeyBytes);
        await this.secrets.Put(reference, key.toString(LocalSourceTokenProvider.KeyEncoding));
        return key;
    }

    private static Sign(key: Buffer, signingInput: string): string
    {
        return createHmac(LocalSourceTokenProvider.HmacAlgorithm, key).update(signingInput).digest(LocalSourceTokenProvider.Encoding);
    }

    private static Encode(value: object): string
    {
        return Buffer.from(JSON.stringify(value)).toString(LocalSourceTokenProvider.Encoding);
    }
}
