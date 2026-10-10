import { randomBytes } from "node:crypto";
import { argon2id, argon2Verify } from "hash-wasm";
import type { IPasswordHasher } from "@pragmatic-tech-ai/todl-identity";

/** Argon2id password hasher producing self-describing PHC strings. */
export class Argon2PasswordHasher implements IPasswordHasher
{
    private static readonly MemorySize = 19456;
    private static readonly Iterations = 2;
    private static readonly Parallelism = 1;
    private static readonly HashLength = 32;
    private static readonly SaltBytes = 16;
    private static readonly OutputType = "encoded";

    public async Hash(password: string): Promise<string>
    {
        const salt = randomBytes(Argon2PasswordHasher.SaltBytes);
        return argon2id({
            password,
            salt,
            parallelism: Argon2PasswordHasher.Parallelism,
            iterations: Argon2PasswordHasher.Iterations,
            memorySize: Argon2PasswordHasher.MemorySize,
            hashLength: Argon2PasswordHasher.HashLength,
            outputType: Argon2PasswordHasher.OutputType,
        });
    }

    public async Verify(password: string, stored: string): Promise<boolean>
    {
        try
        {
            return await argon2Verify({ password, hash: stored });
        }
        catch
        {
            return false;
        }
    }
}
