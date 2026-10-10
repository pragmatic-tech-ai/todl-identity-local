import { AuthMethod, AuthenticatedResult, RejectedResult } from "@pragmatic-tech-ai/todl-identity";
import type { IAuthenticator, ILocalAccountStore, IPrincipalDirectory, ISecretStore, IPasswordHasher, Credential, PresentedSecret, Tenant, AuthenticationResult } from "@pragmatic-tech-ai/todl-identity";

/**
 * Email/password authenticator. Fail-closed: every failure path returns the same
 * RejectedResult reason (no account enumeration), and the no-account / no-hash path performs a
 * dummy argon2 verify so response timing does not reveal whether the account exists.
 */
export class LocalPasswordAuthenticator implements IAuthenticator
{
    private static readonly RejectionReason = "invalid email or password";
    // Real argon2id PHC hash of a throwaway password; used only to equalize verify timing.
    private static readonly DummyHash = "$argon2id$v=19$m=19456,t=2,p=1$ClgzIH9BUkj/jKZmnfHCVQ$XkYdC+mkghtLtcgM4VhsT00yypQx/vHT5ArtyBNu/0c";

    public readonly Method = AuthMethod.Local;

    public constructor(
        private readonly accounts: ILocalAccountStore & IPrincipalDirectory,
        private readonly secrets: ISecretStore,
        private readonly hasher: IPasswordHasher)
    {
    }

    public async Authenticate(credential: Credential, presented: PresentedSecret, tenant: Tenant): Promise<AuthenticationResult>
    {
        const account = await this.accounts.FindByEmail(tenant, credential.Reference);
        if (account === null)
        {
            return this.RejectAfterDummyVerify(presented);
        }
        const storedHash = await this.secrets.Get(account.SecretRef);
        if (storedHash === null)
        {
            return this.RejectAfterDummyVerify(presented);
        }
        const ok = await this.hasher.Verify(presented.Reveal(), storedHash);
        if (!ok)
        {
            return this.Reject();
        }
        const principal = await this.accounts.Lookup(account.PrincipalId, tenant);
        if (principal === null)
        {
            return this.Reject();
        }
        return new AuthenticatedResult(principal);
    }

    private async RejectAfterDummyVerify(presented: PresentedSecret): Promise<AuthenticationResult>
    {
        await this.hasher.Verify(presented.Reveal(), LocalPasswordAuthenticator.DummyHash);
        return this.Reject();
    }

    private Reject(): AuthenticationResult
    {
        return new RejectedResult(LocalPasswordAuthenticator.RejectionReason);
    }
}
