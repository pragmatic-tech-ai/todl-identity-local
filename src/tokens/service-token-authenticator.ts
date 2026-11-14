import { Principal, PrincipalKind, AuthMethod, AuthenticatedResult, RejectedResult } from "@pragmatic-tech-ai/todl-identity";
import type { IServiceTokenStore, IAuthenticator, Credential, Realm, PresentedSecret, AuthenticationResult } from "@pragmatic-tech-ai/todl-identity";

/** Authenticates a presented service token; the grant's scopes surface as the principal's Groups. */
export class ServiceTokenAuthenticator implements IAuthenticator
{
    private static readonly RejectionReason = "Invalid service token";

    public readonly Method = AuthMethod.ServiceToken;
    private readonly store: IServiceTokenStore;

    public constructor(store: IServiceTokenStore)
    {
        this.store = store;
    }

    public async Authenticate(_credential: Credential, presented: PresentedSecret, realm: Realm): Promise<AuthenticationResult>
    {
        const grant = await this.store.Resolve(realm, presented);
        if (grant === null)
        {
            return new RejectedResult(ServiceTokenAuthenticator.RejectionReason);
        }
        const principal = new Principal(grant.PrincipalId, grant.RealmId, PrincipalKind.Service, new Map(), [...grant.Scopes]);
        return new AuthenticatedResult(principal);
    }
}
